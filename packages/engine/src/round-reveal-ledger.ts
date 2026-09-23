import { bytesEqual, bytesToHex, randomBytes, RistrettoPoint, type RandomSource, type RistrettoScalar } from "@p2pcards/crypto";
import {
  CardPointTable, createProvenDecryptionShare, decodeActionBody, decodeSharesBody, decryptionShare, removeDecryptionShares, verifyProvenDecryptionShare,
  type ActionBody, type DeckSpec, type MaskedCard, type PositionShare, type SharesBody,
} from "@p2pcards/deck";
import { decodeAndVerifyEnvelope, type EnvelopeArtifact, type GameId, type IdentityPublicKey } from "@p2pcards/protocol";

import { ActionEnvelopeError, decodeActionEnvelope, MAX_ACTION_ENVELOPE_BYTES, type ActionEnvelopeErrorCode } from "./action-envelope";
import { SetupEnvelopeCoordinator } from "./setup-envelope-coordinator";

export const MAX_ROUND_REVEAL_ENVELOPE_BYTES = MAX_ACTION_ENVELOPE_BYTES;

export interface PrivateDealStep {
  readonly to: number;
  readonly count: number;
}

export interface RoundRevealOptions {
  readonly setup: SetupEnvelopeCoordinator;
  readonly round: number;
  readonly deckSpec: DeckSpec;
  readonly deck: readonly MaskedCard[];
  readonly schedule: readonly PrivateDealStep[];
  readonly maxActions: number;
}

export interface RoundRevealSnapshot {
  readonly phase: string;
  readonly dealIndex: number;
  readonly actionIndex: number;
  readonly deal: {
    readonly to: number;
    readonly positions: readonly number[];
    readonly pendingSenders: readonly number[];
  } | null;
  readonly revealed: Readonly<Record<number, string>>;
}

export interface RoundPrivateHand {
  readonly dealt: Readonly<Record<number, string>>;
  readonly remaining: Readonly<Record<number, string>>;
}

export type RoundRevealTransition = {
  readonly status: "accepted" | "duplicate";
  readonly received: EnvelopeArtifact;
  readonly seat: number;
} & (
  | { readonly type: "SHARES"; readonly body: SharesBody }
  | { readonly type: "ACTION"; readonly body: ActionBody; readonly revealed: Readonly<Record<number, string>> }
);

export type RoundRevealErrorCode = ActionEnvelopeErrorCode
  | "deal_incomplete" | "wrong_recipient" | "wrong_positions" | "conflicting_contribution"
  | "unscheduled_position" | "wrong_owner" | "already_revealed" | "invalid_share_proof"
  | "action_limit" | "inconsistent_deck" | "invalid_local_key";

export class RoundRevealError extends Error {
  readonly code: RoundRevealErrorCode;
  constructor(code: RoundRevealErrorCode, options?: ErrorOptions) {
    super(`Round reveal rejected: ${code}`, options);
    this.name = "RoundRevealError";
    this.code = code;
  }
}

interface ScheduledDeal {
  readonly to: number;
  readonly positions: readonly number[];
}

/** Proof/ownership ledger relative to a supplied deck and schedule, not a shuffle verifier or durable game receiver. */
export class RoundRevealLedger {
  readonly #gameId: GameId;
  readonly #round: number;
  readonly #roster: readonly IdentityPublicKey[];
  readonly #seats: ReadonlyMap<string, number>;
  readonly #publicKeys: readonly RistrettoPoint[];
  readonly #table: CardPointTable;
  readonly #deck: readonly MaskedCard[];
  readonly #schedule: readonly ScheduledDeal[];
  readonly #owners: readonly (number | null)[];
  readonly #maxActions: number;
  readonly #shares: readonly Map<number, RistrettoPoint>[];
  readonly #contributors = new Set<number>();
  readonly #revealed = new Map<number, string>();
  readonly #accepted = new Map<string, Readonly<Record<number, string>>>();
  #dealIndex = 0;
  #actionIndex = 0;

  constructor(options: RoundRevealOptions) {
    if (typeof options !== "object" || options === null ||
        !(options.setup instanceof SetupEnvelopeCoordinator) || options.setup.state !== "complete") {
      throw new TypeError("Round reveals require completed key and beacon setup");
    }
    if (!Number.isSafeInteger(options.round) || options.round < options.setup.round || Object.is(options.round, -0)) {
      throw new RangeError("Round must be a safe integer no earlier than setup");
    }
    if (!Number.isSafeInteger(options.maxActions) || options.maxActions < 1) {
      throw new RangeError("Round action budget must be a positive safe integer");
    }
    this.#gameId = options.setup.gameId;
    this.#round = options.round;
    this.#roster = options.setup.roster;
    this.#seats = new Map(this.#roster.map((identity, seat) => [bytesToHex(identity), seat]));
    this.#publicKeys = this.#roster.map((_, seat) => {
      const key = options.setup.publicKeyAt(seat);
      if (key === null) { throw new TypeError("Completed setup is missing a public game key"); }
      return RistrettoPoint.fromBytes(key.toBytes());
    });
    if (typeof options.deckSpec !== "object" || options.deckSpec === null || !Array.isArray(options.deckSpec.cards)) {
      throw new TypeError("A round deck specification is required");
    }
    this.#table = new CardPointTable(options.deckSpec);
    if (!Array.isArray(options.deck) || options.deck.length !== this.#table.size) {
      throw new RangeError("Ciphertext deck must match the deck specification size");
    }
    this.#deck = Object.freeze(Array.from(options.deck, (card) => Object.freeze({
      A: RistrettoPoint.fromBytes(card.A.toBytes()), B: RistrettoPoint.fromBytes(card.B.toBytes()),
    })));
    if (!Array.isArray(options.schedule) || options.schedule.length > this.#deck.length) {
      throw new RangeError("Private-deal schedule cannot exceed the deck size");
    }
    const owners: (number | null)[] = new Array(this.#deck.length).fill(null);
    let cursor = 0;
    this.#schedule = Object.freeze(Array.from(options.schedule, (step) => {
      if (typeof step !== "object" || step === null ||
          !Number.isSafeInteger(step.to) || step.to < 0 || step.to >= this.#roster.length || Object.is(step.to, -0) ||
          !Number.isSafeInteger(step.count) || step.count < 1 || step.count > this.#deck.length - cursor) {
        throw new RangeError("Each private-deal step must name a roster seat and an available positive card count");
      }
      const positions = Object.freeze(Array.from({ length: step.count }, () => {
        const position = cursor++;
        owners[position] = step.to;
        return position;
      }));
      return Object.freeze({ to: step.to, positions });
    }));
    this.#owners = Object.freeze(owners);
    this.#shares = Array.from({ length: this.#deck.length }, () => new Map<number, RistrettoPoint>());
    this.#maxActions = options.maxActions;
  }

  get dealCount(): number { return this.#schedule.length; }

  get snapshot(): RoundRevealSnapshot {
    const deal = this.#schedule[this.#dealIndex];
    return Object.freeze({
      phase: this.#phase(), dealIndex: this.#dealIndex, actionIndex: this.#actionIndex,
      deal: deal === undefined ? null : Object.freeze({
        to: deal.to, positions: deal.positions,
        pendingSenders: Object.freeze(this.#roster.flatMap((_, seat) =>
          seat !== deal.to && !this.#contributors.has(seat) ? [seat] : [])),
      }),
      revealed: Object.freeze(Object.fromEntries(this.#revealed)),
    });
  }

  ownerAt(position: number): number | null {
    if (!Number.isSafeInteger(position) || position < 0 || position >= this.#deck.length || Object.is(position, -0)) {
      throw new RangeError("Position is outside the round deck");
    }
    return this.#owners[position]!;
  }

  /** Local secret-bearing read, never part of a public snapshot. Null until the entire initial deal is committed. */
  readPrivateHand(seat: number, secretKey: RistrettoScalar): RoundPrivateHand | null {
    this.#requireLocalKey(seat, secretKey);
    if (this.#dealIndex < this.#schedule.length) { return null; }
    const dealt: Record<number, string> = {};
    const remaining: Record<number, string> = {};
    const cardPositions = new Map([...this.#revealed].map(([pos, card]) => [card, pos]));
    for (let pos = 0; pos < this.#deck.length; pos += 1) {
      if (this.#owners[pos] !== seat) continue;
      const ciphertext = this.#deck[pos]!;
      const shares = this.#roster.map((_, donor) => {
        const share = donor === seat ? decryptionShare(secretKey, ciphertext.A) : this.#shares[pos]!.get(donor);
        if (share === undefined) { throw new RoundRevealError("deal_incomplete"); }
        return share;
      });
      const card = this.#table.identify(removeDecryptionShares(ciphertext, shares));
      const known = this.#revealed.get(pos);
      if (card === null || (cardPositions.has(card) && cardPositions.get(card) !== pos) || (known !== undefined && known !== card)) {
        throw new RoundRevealError("inconsistent_deck");
      }
      cardPositions.set(card, pos);
      dealt[pos] = card;
      if (known === undefined) remaining[pos] = card;
    }
    return Object.freeze({ dealt: Object.freeze(dealt), remaining: Object.freeze(remaining) });
  }

  /** Prepares only this pending nonrecipient's exact current batch, never caller-selected positions. */
  createDealShares(seat: number, secretKey: RistrettoScalar, source?: RandomSource): SharesBody {
    this.#requireLocalKey(seat, secretKey);
    const step = this.#schedule[this.#dealIndex];
    if (step === undefined) { throw new RoundRevealError("wrong_phase"); }
    if (seat === step.to) { throw new RoundRevealError("unexpected_sender"); }
    const requirePending = (): void => {
      if (this.#schedule[this.#dealIndex] !== step) { throw new RoundRevealError("wrong_phase"); }
      if (this.#contributors.has(seat)) { throw new RoundRevealError("conflicting_contribution"); }
    };
    requirePending();
    const context = { gameId: this.#gameId, round: this.#round, phase: this.#phase() };
    const guardedSource: RandomSource = { fill: (bytes) => {
      requirePending();
      bytes.set(randomBytes(bytes.length, source));
      // Check every draw, including nonces rejected by the scalar sampler.
      requirePending();
    } };
    const items: PositionShare[] = [];
    for (const pos of step.positions) {
      const share = createProvenDecryptionShare(context, pos, secretKey, this.#deck[pos]!.A, guardedSource);
      requirePending();
      items.push(Object.freeze({ pos, ...share }));
    }
    return Object.freeze({ to: step.to, items: Object.freeze(items) });
  }

  /** Prepares deliberate disclosure for the current action phase; does not sign, persist, or consume the position. */
  createActionShare(seat: number, secretKey: RistrettoScalar, position: number, source?: RandomSource): PositionShare {
    const hand = this.readPrivateHand(seat, secretKey);
    if (hand === null) { throw new RoundRevealError("deal_incomplete"); }
    const owner = this.ownerAt(position);
    if (owner === null) { throw new RoundRevealError("unscheduled_position"); }
    if (owner !== seat) { throw new RoundRevealError("wrong_owner"); }
    if (!Object.hasOwn(hand.remaining, position)) { throw new RoundRevealError("already_revealed"); }
    if (this.#actionIndex >= this.#maxActions) { throw new RoundRevealError("action_limit"); }
    const phase = this.#phase();
    const guardedSource: RandomSource = { fill: (bytes) => {
      if (phase !== this.#phase()) { throw new RoundRevealError("wrong_phase"); }
      bytes.set(randomBytes(bytes.length, source));
      if (phase !== this.#phase()) { throw new RoundRevealError("wrong_phase"); }
    } };
    const share = createProvenDecryptionShare({ gameId: this.#gameId, round: this.#round, phase }, position, secretKey, this.#deck[position]!.A, guardedSource);
    if (phase !== this.#phase()) { throw new RoundRevealError("wrong_phase"); }
    return Object.freeze({ pos: position, ...share });
  }

  classify(candidate: EnvelopeArtifact, expectedSeat?: number): RoundRevealTransition {
    return this.#process(candidate, expectedSeat, false);
  }

  /** The caller must validate rules and durably accept the envelope before this mutation. */
  commit(candidate: EnvelopeArtifact, expectedSeat?: number): RoundRevealTransition {
    return this.#process(candidate, expectedSeat, true);
  }

  #requireLocalKey(seat: number, secretKey: RistrettoScalar): void {
    if (!Number.isSafeInteger(seat) || seat < 0 || seat >= this.#roster.length || Object.is(seat, -0)) {
      throw new RangeError("Local seat must belong to the round roster");
    }
    let matches = false;
    try { matches = RistrettoPoint.base().multiply(secretKey).equals(this.#publicKeys[seat]!); }
    catch { /* Invalid scalar values must not be included in the error or its cause. */ }
    if (!matches) { throw new RoundRevealError("invalid_local_key"); }
  }

  #phase(): string {
    return this.#schedule[this.#dealIndex] === undefined
      ? `round.${this.#round}.play.${this.#actionIndex}`
      : `round.${this.#round}.deal.${this.#dealIndex}`;
  }

  #process(candidate: EnvelopeArtifact, expectedSeat: number | undefined, commit: boolean): RoundRevealTransition {
    let received: EnvelopeArtifact;
    try {
      const bytes = candidate.canonicalBytes;
      if (!(bytes instanceof Uint8Array) || bytes.constructor !== Uint8Array || bytes.length > MAX_ROUND_REVEAL_ENVELOPE_BYTES) {
        throw new TypeError("Round reveal envelope exceeds its byte boundary");
      }
      received = decodeAndVerifyEnvelope(bytes);
    } catch (cause) { throw new RoundRevealError("invalid_envelope", { cause }); }
    const envelope = received.envelope;
    if (!bytesEqual(envelope.game, this.#gameId)) { throw new RoundRevealError("wrong_game"); }
    const seat = this.#seats.get(bytesToHex(envelope.from));
    if (seat === undefined) { throw new RoundRevealError("unknown_sender"); }
    if (envelope.round !== this.#round) { throw new RoundRevealError("wrong_round"); }
    const hash = bytesToHex(received.hash);
    const duplicate = this.#accepted.get(hash);
    const context = { gameId: this.#gameId, round: this.#round, phase: envelope.phase };
    if (envelope.type === "SHARES") {
      let body: SharesBody;
      try { body = decodeSharesBody(envelope.body); }
      catch (cause) { throw new RoundRevealError("malformed_body", { cause }); }
      if (duplicate !== undefined) {
        return Object.freeze({ status: "duplicate", type: "SHARES", received, seat, body });
      }
      const step = this.#schedule[this.#dealIndex];
      if (step === undefined || envelope.phase !== this.#phase()) { throw new RoundRevealError("wrong_phase"); }
      if (seat === step.to) { throw new RoundRevealError("unexpected_sender"); }
      if (this.#contributors.has(seat)) { throw new RoundRevealError("conflicting_contribution"); }
      if (body.to !== step.to) { throw new RoundRevealError("wrong_recipient"); }
      if (body.items.length !== step.positions.length || body.items.some(({ pos }) => !step.positions.includes(pos))) {
        throw new RoundRevealError("wrong_positions");
      }
      for (const item of body.items) {
        if (!verifyProvenDecryptionShare(context, item.pos, this.#publicKeys[seat]!, this.#deck[item.pos]!.A, item)) {
          throw new RoundRevealError("invalid_share_proof");
        }
      }
      if (commit) {
        for (const item of body.items) this.#shares[item.pos]!.set(seat, item.S);
        this.#contributors.add(seat);
        this.#accepted.set(hash, Object.freeze({}));
        if (this.#contributors.size === this.#roster.length - 1) {
          this.#dealIndex += 1;
          this.#contributors.clear();
        }
      }
      return Object.freeze({ status: "accepted", type: "SHARES", received, seat, body });
    }
    if (envelope.type !== "ACTION") { throw new RoundRevealError("wrong_type"); }
    if (duplicate !== undefined) {
      return Object.freeze({ status: "duplicate", type: "ACTION", received, seat, body: decodeActionBody(envelope.body), revealed: duplicate });
    }
    if (this.#schedule[this.#dealIndex] !== undefined) { throw new RoundRevealError("deal_incomplete"); }
    if (this.#actionIndex >= this.#maxActions) { throw new RoundRevealError("action_limit"); }
    let body: ActionBody;
    try {
      body = decodeActionEnvelope(received.canonicalBytes, {
        gameId: this.#gameId, round: this.#round, actionIndex: this.#actionIndex, roster: this.#roster,
        expectedSeats: expectedSeat === undefined ? [] : [expectedSeat],
      }).action;
    } catch (cause) {
      if (cause instanceof ActionEnvelopeError) { throw new RoundRevealError(cause.code, { cause }); }
      throw cause;
    }
    // Check all ownership/freshness constraints before attempting any card opening.
    for (const position of body.reveal) {
      const owner = this.#owners[position];
      if (owner === null || owner === undefined) { throw new RoundRevealError("unscheduled_position"); }
      if (owner !== seat) { throw new RoundRevealError("wrong_owner"); }
      if (this.#revealed.has(position)) { throw new RoundRevealError("already_revealed"); }
    }
    const revealed: Record<number, string> = {};
    const cardIds = new Set(this.#revealed.values());
    for (const item of body.shares) {
      const ciphertext = this.#deck[item.pos]!;
      if (!verifyProvenDecryptionShare(context, item.pos, this.#publicKeys[seat]!, ciphertext.A, item)) {
        throw new RoundRevealError("invalid_share_proof");
      }
      const shares = this.#roster.map((_, donor) => {
        const share = donor === seat ? item.S : this.#shares[item.pos]!.get(donor);
        if (share === undefined) { throw new RoundRevealError("deal_incomplete"); }
        return share;
      });
      const card = this.#table.identify(removeDecryptionShares(ciphertext, shares));
      // Valid proofs against an invalid supplied deck are not evidence against the revealer.
      if (card === null || cardIds.has(card)) { throw new RoundRevealError("inconsistent_deck"); }
      cardIds.add(card);
      revealed[item.pos] = card;
    }
    Object.freeze(revealed);
    if (commit) {
      for (const position of body.reveal) this.#revealed.set(position, revealed[position]!);
      this.#accepted.set(hash, revealed);
      this.#actionIndex += 1;
    }
    return Object.freeze({ status: "accepted", type: "ACTION", received, seat, body, revealed });
  }
}
