import { bytesEqual, bytesToHex, randomBytes, scalarFromBigInt, type RandomSource, type RistrettoScalar } from "@p2pcards/crypto";
import { decodeActionBody, decodeAuditDiscloseBody, encodeActionBody, encodeAuditDiscloseBody, encodeSharesBody, type ActionBody, type MaskedCard } from "@p2pcards/deck";
import {
  MAX_ROUND_REVEAL_ENVELOPE_BYTES, RoundRevealError, RoundRevealLedger, SetupEnvelopeCoordinator,
  type PrivateDealStep, type RoundRevealSnapshot, type RoundRevealTransition,
} from "@p2pcards/engine";
import { decodeAndVerifyEnvelope, encodeUnsignedEnvelope, parseHash256, parseIdentityPublicKey, type EnvelopeArtifact, type IdentityPublicKey } from "@p2pcards/protocol";
import {
  MAX_SASKU_HAND_ACTIONS, SASKU_DECK_SPEC, SASKU_SUITS, SaskuHandError, SaskuPublicHandController,
  auditSaskuHand, decodeSaskuAction, legalSaskuCards, parseSaskuCard, saskuBidStrength,
  type SaskuCardId, type SaskuHandAction, type SaskuHandAuditResult, type SaskuHandScore, type SaskuPublicHandSnapshot, type SaskuSeat, type SaskuSuit,
} from "@p2pcards/rules-sasku";
import { AuthoredEnvelopeStoreError, PersistentEnvelopeAuthor, PersistentSessionReceiver, PersistentSessionReceiverError, SessionChainRegistry, type EnvelopeContent } from "@p2pcards/session";

import { captureSaskuRoundHistory, SaskuRoundRecoveryError, type SaskuRoundRecoveryLimits } from "./round-recovery";

export const DEFAULT_MAX_PENDING_SASKU_ENVELOPES = 32;
export const DEFAULT_MAX_PENDING_SASKU_BYTES = 1024 * 1024;

export interface PersistentSaskuRoundOptions {
  readonly setup: SetupEnvelopeCoordinator;
  readonly round: number;
  readonly deck: readonly MaskedCard[];
  readonly schedule: readonly PrivateDealStep[];
  readonly dealer: SaskuSeat;
  readonly session: SessionChainRegistry;
  readonly sessionReceiver: PersistentSessionReceiver;
  readonly maxPendingEnvelopes?: number;
  readonly maxPendingBytes?: number;
}

export interface SaskuRoundSnapshot {
  readonly ledger: RoundRevealSnapshot;
  readonly hand: SaskuPublicHandSnapshot;
  readonly history: readonly SaskuHandAction[];
  readonly audit: SaskuRoundAuditSnapshot | null;
}

export interface SaskuPrivateHand {
  readonly dealt: Readonly<Record<number, SaskuCardId>>;
  readonly remaining: Readonly<Record<number, SaskuCardId>>;
}

export type SaskuActionIntent =
  | { readonly type: "pass" | "diamonds" }
  | { readonly type: "bid"; readonly value: number }
  | { readonly type: "choose_trump"; readonly suit: SaskuSuit }
  | { readonly type: "play"; readonly position: number };

export interface SaskuRoundAuditSnapshot {
  readonly phase: string;
  readonly pendingSenders: readonly SaskuSeat[];
  readonly result:
    | { readonly status: "valid"; readonly score: SaskuHandScore }
    | Extract<SaskuHandAuditResult, { readonly status: "violation" }>
    | null;
}

export type SaskuRoundReceiveResult = {
  readonly received: EnvelopeArtifact;
} & (
  | {
      readonly status: "accepted" | "duplicate";
      readonly chainStatus: "accepted" | "duplicate";
      readonly persistenceStatus: "stored" | "duplicate";
      readonly snapshot: SaskuRoundSnapshot;
    }
  | { readonly status: "rejected"; readonly reason: "gap" | "broken_prev" | "equivocation" | "durable_conflict" }
);

export type SaskuRoundReceiverErrorCode =
  | "invalid_envelope" | "queue_limit" | "closed" | "hand_complete" | "stale_action" | "stale_contribution"
  | "invalid_receipt" | "commit_failed" | "recovery_required";

export class SaskuRoundReceiverError extends Error {
  readonly code: SaskuRoundReceiverErrorCode;
  constructor(code: SaskuRoundReceiverErrorCode, options?: ErrorOptions) {
    super(`Sasku round receiver: ${code}`, options);
    this.name = "SaskuRoundReceiverError";
    this.code = code;
  }
}

interface PendingOperation {
  readonly size: number;
  readonly run: () => Promise<SaskuRoundReceiveResult>;
  readonly resolve: (result: SaskuRoundReceiveResult) => void;
  readonly reject: (cause: unknown) => void;
}

interface RoundTransition {
  readonly received: EnvelopeArtifact;
  readonly expectedSeat: SaskuSeat | undefined;
  readonly type: "SHARES" | "ACTION" | "AUDIT_DISCLOSE";
  readonly seat: SaskuSeat;
  readonly status: "accepted" | "duplicate";
  readonly action: SaskuHandAction | null;
}

/** Owns deal, public play, and local hand audit. Setup, shuffle provenance, and the agreed schedule/dealer remain caller prerequisites. */
export class PersistentSaskuRoundReceiver {
  readonly #ledger: RoundRevealLedger;
  readonly #hand: SaskuPublicHandController;
  readonly #session: SessionChainRegistry;
  readonly #durable: PersistentSessionReceiver;
  readonly #maxPendingEnvelopes: number;
  readonly #maxPendingBytes: number;
  readonly #round: number;
  readonly #auditHashes = new Map<SaskuSeat, string>();
  readonly #queue: PendingOperation[] = [];
  #active = false;
  #closed = false;
  #failure: SaskuRoundReceiverError | null = null;
  #pendingEnvelopes = 0;
  #pendingBytes = 0;
  #idle: Promise<void> = Promise.resolve();
  #resolveIdle: (() => void) | null = null;
  #snapshot: SaskuRoundSnapshot;

  constructor(options: PersistentSaskuRoundOptions) {
    if (typeof options !== "object" || options === null || !(options.setup instanceof SetupEnvelopeCoordinator) ||
        options.setup.state !== "complete" || options.setup.roster.length !== 4) {
      throw new TypeError("A Sasku receiver requires completed four-seat setup");
    }
    if (!(options.session instanceof SessionChainRegistry) || !(options.sessionReceiver instanceof PersistentSessionReceiver) ||
        !options.sessionReceiver.isBoundTo(options.session) || !bytesEqual(options.setup.gameId, options.session.gameId)) {
      throw new TypeError("Sasku receipt requires the matching game's bound durable session receiver");
    }
    const roster = options.setup.roster;
    const sessionRoster = options.session.roster;
    if (sessionRoster.length !== 4 || roster.some((key, seat) => !bytesEqual(key, sessionRoster[seat]!))) {
      throw new TypeError("Sasku setup and durable session must use the same seat order");
    }
    this.#maxPendingEnvelopes = positiveInteger(options.maxPendingEnvelopes ?? DEFAULT_MAX_PENDING_SASKU_ENVELOPES);
    this.#maxPendingBytes = positiveInteger(options.maxPendingBytes ?? DEFAULT_MAX_PENDING_SASKU_BYTES);
    this.#session = options.session;
    this.#durable = options.sessionReceiver;
    this.#hand = new SaskuPublicHandController({ dealer: options.dealer });
    this.#ledger = new RoundRevealLedger({
      setup: options.setup, round: options.round, deck: options.deck, schedule: options.schedule,
      deckSpec: SASKU_DECK_SPEC, maxActions: MAX_SASKU_HAND_ACTIONS,
    });
    this.#round = options.round;
    const counts = [0, 0, 0, 0];
    for (let pos = 0; pos < 36; pos += 1) {
      const owner = this.#ledger.ownerAt(pos);
      if (owner === null) { throw new RangeError("Sasku must privately deal all 36 positions"); }
      counts[owner]! += 1;
    }
    if (counts.some((count) => count !== 9)) { throw new RangeError("Sasku must deal exactly nine cards per seat"); }
    this.#snapshot = Object.freeze({ ledger: this.#ledger.snapshot, hand: this.#hand.snapshot, history: this.#hand.history, audit: null });
  }

  /** Read-only reconstruction from a quiescent, already restored session and the same trusted round context. */
  static recover(options: PersistentSaskuRoundOptions, limits?: SaskuRoundRecoveryLimits): PersistentSaskuRoundReceiver {
    const captured = Object.freeze({ ...options });
    const receiver = new PersistentSaskuRoundReceiver(captured);
    try {
      const history = captureSaskuRoundHistory(captured.setup, receiver.#session, receiver.#round, limits);
      const next = [0, 0, 0, 0];
      let remaining = history.bySeat.reduce((sum, messages) => sum + messages.length, 0);
      while (remaining > 0) {
        const snapshot = receiver.#snapshot;
        const type = snapshot.audit !== null ? "AUDIT_DISCLOSE" : snapshot.ledger.deal !== null ? "SHARES" : "ACTION";
        const phase = snapshot.audit?.phase ?? snapshot.ledger.phase;
        let progressed = false;
        // Never skip a sender's earlier round message to reach a later, conveniently named phase.
        for (let seat = 0; seat < 4; seat += 1) {
          const artifact = history.bySeat[seat]![next[seat]!];
          if (artifact === undefined || artifact.envelope.type !== type || artifact.envelope.phase !== phase) continue;
          const transition = receiver.#classify(artifact);
          if (transition.status !== "accepted") { throw new SaskuRoundRecoveryError("Round history repeats a semantic contribution"); }
          receiver.#commit(transition);
          next[seat]! += 1;
          remaining -= 1;
          progressed = true;
          break;
        }
        if (!progressed) { throw new SaskuRoundRecoveryError("Round history has missing or out-of-order prerequisites"); }
      }
      history.assertUnchanged();
      return receiver;
    } catch (cause) {
      receiver.close();
      if (cause instanceof SaskuRoundRecoveryError || cause instanceof RangeError || cause instanceof TypeError) throw cause;
      throw new SaskuRoundRecoveryError("Could not reconstruct Sasku round semantics", { cause });
    }
  }

  get snapshot(): SaskuRoundSnapshot { return this.#snapshot; }
  get failure(): SaskuRoundReceiverError | null { return this.#failure; }
  get closed(): boolean { return this.#closed; }
  get pendingEnvelopes(): number { return this.#pendingEnvelopes; }
  get pendingBytes(): number { return this.#pendingBytes; }
  get round(): number { return this.#round; }
  get dealCount(): number { return this.#ledger.dealCount; }
  isBoundTo(session: SessionChainRegistry): boolean { return this.#session === session; }
  /** Observes the next empty admitted queue; not a lock or a shared control/network barrier. */
  whenIdle(): Promise<void> { return this.#idle; }
  ownerAt(position: number): SaskuSeat { return this.#ledger.ownerAt(position) as SaskuSeat; }

  /** Explicit local-only access; the caller must keep returned cards out of public state and diagnostics. */
  readPrivateHand(identity: IdentityPublicKey, secretKey: RistrettoScalar): SaskuPrivateHand | null {
    if (this.#failure !== null) { throw this.#failure; }
    if (this.#closed) { throw new SaskuRoundReceiverError("closed"); }
    const seat = this.#session.seatOf(identity);
    if (seat === null) { throw new RoundRevealError("unknown_sender"); }
    try {
      const hand = this.#ledger.readPrivateHand(seat, secretKey);
      if (hand === null) return null;
      const cards = (map: Readonly<Record<number, string>>) => Object.freeze(Object.fromEntries(
        Object.entries(map).map(([pos, card]) => [pos, parseSaskuCard(card).id]),
      ));
      return Object.freeze({ dealt: cards(hand.dealt), remaining: cards(hand.remaining) });
    } catch (cause) {
      if (cause instanceof RoundRevealError && (cause.code === "inconsistent_deck" || cause.code === "deal_incomplete")) {
        throw this.#fail("recovery_required", cause);
      }
      throw cause;
    }
  }

  /** Local authoring and receipt share one queue. No artifact is returned for broadcast before both succeed. */
  authorAction(
    author: PersistentEnvelopeAuthor,
    secretKey: RistrettoScalar,
    expected: SaskuRoundSnapshot,
    intent: SaskuActionIntent,
    source?: RandomSource,
  ): Promise<SaskuRoundReceiveResult> {
    return this.#enqueueAuthoring(author, expected, "stale_action", (identity) => {
      try { scalarFromBigInt(secretKey); }
      catch { throw new RoundRevealError("invalid_local_key"); }
      const captured = snapshotIntent(intent);
      return () => this.#authorActionOne(author, identity, secretKey, expected, captured, source);
    });
  }

  /** Authors only the current scheduled nonrecipient batch; peers may contribute first in the same phase. */
  authorDealShares(
    author: PersistentEnvelopeAuthor, secretKey: RistrettoScalar, expected: SaskuRoundSnapshot, source?: RandomSource,
  ): Promise<SaskuRoundReceiveResult> {
    return this.#enqueueAuthoring(author, expected, "stale_contribution", (identity) => {
      try { scalarFromBigInt(secretKey); }
      catch { throw new RoundRevealError("invalid_local_key"); }
      const seat = this.#session.seatOf(identity)! as SaskuSeat;
      return () => {
        const requireCurrent = (): void => this.#requireContribution(expected, seat, "SHARES");
        requireCurrent();
        const guardedSource: RandomSource = { fill: (bytes) => {
          requireCurrent();
          bytes.set(randomBytes(bytes.length, source));
          requireCurrent();
        } };
        const body = this.#ledger.createDealShares(seat, secretKey, guardedSource);
        return this.#authorAndReceive(author, identity, () => ({
          round: this.#round, phase: expected.ledger.phase, type: "SHARES", body: encodeSharesBody(body),
        }), requireCurrent);
      };
    });
  }

  /** Completed Sasku hands have no outstanding cards; this contribution needs only the signing identity. */
  authorAuditDisclose(author: PersistentEnvelopeAuthor, expected: SaskuRoundSnapshot): Promise<SaskuRoundReceiveResult> {
    return this.#enqueueAuthoring(author, expected, "stale_contribution", (identity) => {
      const seat = this.#session.seatOf(identity)! as SaskuSeat;
      return () => {
        const requireCurrent = (): void => this.#requireContribution(expected, seat, "AUDIT_DISCLOSE");
        requireCurrent();
        return this.#authorAndReceive(author, identity, () => ({
          round: this.#round, phase: expected.audit!.phase, type: "AUDIT_DISCLOSE", body: encodeAuditDiscloseBody({ items: [] }),
        }), requireCurrent);
      };
    });
  }

  #enqueueAuthoring(
    author: PersistentEnvelopeAuthor, expected: SaskuRoundSnapshot, staleCode: "stale_action" | "stale_contribution",
    capture: (identity: IdentityPublicKey) => PendingOperation["run"],
  ): Promise<SaskuRoundReceiveResult> {
    let reserved = false;
    try {
      if (this.#failure !== null) { throw this.#failure; }
      if (this.#closed) { throw new SaskuRoundReceiverError("closed"); }
      // Charge the full envelope ceiling before copying an intent or doing key/proof work.
      const size = MAX_ROUND_REVEAL_ENVELOPE_BYTES;
      this.#reserve(size);
      reserved = true;
      if (!(author instanceof PersistentEnvelopeAuthor)) { throw new TypeError("Local authoring requires a persistent envelope author"); }
      if (!bytesEqual(author.gameId, this.#session.gameId)) { throw new RoundRevealError("wrong_game"); }
      const identity = parseIdentityPublicKey(author.sender);
      if (this.#session.seatOf(identity) === null) { throw new RoundRevealError("unknown_sender"); }
      if (expected !== this.#snapshot) { throw new SaskuRoundReceiverError(staleCode); }
      const run = capture(identity);
      if (this.#failure !== null) { throw this.#failure; }
      if (this.#closed) { throw new SaskuRoundReceiverError("closed"); }
      const pending = new Promise<SaskuRoundReceiveResult>((resolve, reject) => this.#queue.push({
        size, resolve, reject, run,
      }));
      reserved = false;
      void this.#drain();
      return pending;
    } catch (cause) {
      if (reserved) this.#release(MAX_ROUND_REVEAL_ENVELOPE_BYTES);
      return Promise.reject(cause);
    }
  }

  #requireContribution(expected: SaskuRoundSnapshot, seat: SaskuSeat, type: "SHARES" | "AUDIT_DISCLOSE"): void {
    if (this.#failure !== null) { throw this.#failure; }
    if (this.#closed) { throw new SaskuRoundReceiverError("closed"); }
    if (type === "SHARES") {
      if (expected.ledger.deal === null) { throw new RoundRevealError("wrong_phase"); }
      const current = this.#snapshot.ledger;
      if (current.deal === null || current.phase !== expected.ledger.phase) { throw new SaskuRoundReceiverError("stale_contribution"); }
      if (current.deal.to === seat) { throw new RoundRevealError("unexpected_sender"); }
      if (!current.deal.pendingSenders.includes(seat)) { throw new RoundRevealError("conflicting_contribution"); }
    } else {
      if (expected.audit === null) { throw new RoundRevealError("wrong_phase"); }
      const current = this.#snapshot.audit;
      if (current === null || current.phase !== expected.audit.phase) { throw new SaskuRoundReceiverError("stale_contribution"); }
      if (!current.pendingSenders.includes(seat)) { throw new RoundRevealError("conflicting_contribution"); }
    }
  }

  receive(candidate: EnvelopeArtifact): Promise<SaskuRoundReceiveResult> {
    let reservedBytes: number | null = null;
    try {
      if (this.#failure !== null) { throw this.#failure; }
      if (this.#closed) { throw new SaskuRoundReceiverError("closed"); }
      const input = candidate?.canonicalBytes;
      if (!(input instanceof Uint8Array) || input.constructor !== Uint8Array || input.length === 0 || input.length > MAX_ROUND_REVEAL_ENVELOPE_BYTES) {
        throw new SaskuRoundReceiverError("invalid_envelope");
      }
      const size = input.length;
      this.#reserve(size);
      reservedBytes = size;
      const bytes = new Uint8Array(size);
      try {
        bytes.set(input);
        decodeAndVerifyEnvelope(bytes);
      } catch (cause) { throw new SaskuRoundReceiverError("invalid_envelope", { cause }); }
      if (this.#failure !== null) { throw this.#failure; }
      if (this.#closed) { throw new SaskuRoundReceiverError("closed"); }
      const pending = new Promise<SaskuRoundReceiveResult>((resolve, reject) => this.#queue.push({
        size, resolve, reject, run: () => this.#receiveOne(bytes),
      }));
      reservedBytes = null;
      void this.#drain();
      return pending;
    } catch (cause) {
      if (reservedBytes !== null) this.#release(reservedBytes);
      return Promise.reject(cause);
    }
  }

  /** Cancels queued work. An already submitted durable receipt is allowed to finish consistently. */
  close(): void {
    this.#closed = true;
    this.#rejectQueued(this.#failure ?? new SaskuRoundReceiverError("closed"));
  }

  async #drain(): Promise<void> {
    if (this.#active) { return; }
    this.#active = true;
    try {
      for (let job = this.#queue.shift(); job !== undefined; job = this.#queue.shift()) {
        try { job.resolve(await job.run()); }
        catch (cause) { job.reject(cause); }
        finally { this.#release(job.size); }
      }
    } finally { this.#active = false; }
  }

  async #authorActionOne(
    author: PersistentEnvelopeAuthor, identity: IdentityPublicKey, secretKey: RistrettoScalar,
    expected: SaskuRoundSnapshot, intent: SaskuActionIntent, source: RandomSource | undefined,
  ): Promise<SaskuRoundReceiveResult> {
    const requireCurrent = (): void => {
      if (this.#failure !== null) { throw this.#failure; }
      if (this.#closed) { throw new SaskuRoundReceiverError("closed"); }
      if (expected !== this.#snapshot) { throw new SaskuRoundReceiverError("stale_action"); }
    };
    requireCurrent();
    const seat = this.#session.seatOf(identity)! as SaskuSeat;
    const privateHand = this.readPrivateHand(identity, secretKey);
    if (privateHand === null) { throw new RoundRevealError("deal_incomplete"); }
    if (expected.hand.phase === "complete") { throw new SaskuRoundReceiverError("hand_complete"); }
    let action: SaskuHandAction;
    if (intent.type === "play") {
      if (this.ownerAt(intent.position) !== seat) { throw new RoundRevealError("wrong_owner"); }
      const card = privateHand.remaining[intent.position];
      if (card === undefined) { throw new RoundRevealError("already_revealed"); }
      action = { type: "play", seat, card };
    } else { action = { ...intent, seat }; }
    this.#hand.preview(action);
    if (action.type === "bid" && action.value !== saskuBidStrength(Object.values(privateHand.dealt))) {
      throw new SaskuHandError("A bid must equal the player's exact calculated hand strength", "bid_strength");
    }
    if (action.type === "play") {
      const contract = expected.hand.contract!;
      const trump = contract.kind === "pass_round" ? "diamonds" : contract.suit;
      if (!legalSaskuCards(Object.values(privateHand.remaining), expected.hand.trick, trump).includes(action.card)) {
        throw new SaskuHandError("The player must follow the effective led suit", "follow_suit");
      }
    }
    const guardedSource: RandomSource = { fill: (bytes) => {
      requireCurrent();
      bytes.set(randomBytes(bytes.length, source));
      requireCurrent();
    } };
    const body: ActionBody = {
      kind: intent.type,
      data: intent.type === "bid" ? { value: intent.value } : intent.type === "choose_trump" ? { suit: intent.suit } : {},
      reveal: intent.type === "play" ? [intent.position] : [],
      shares: intent.type === "play" ? [this.#ledger.createActionShare(seat, secretKey, intent.position, guardedSource)] : [],
    };
    return this.#authorAndReceive(author, identity, () => ({
      round: this.#round, phase: expected.ledger.phase, type: "ACTION", body: encodeActionBody(body),
    }), requireCurrent);
  }

  async #authorAndReceive(
    author: PersistentEnvelopeAuthor, identity: IdentityPublicKey,
    makeContent: () => EnvelopeContent, requireCurrent: () => void,
  ): Promise<SaskuRoundReceiveResult> {
    requireCurrent();
    const content = makeContent();
    const argument = makeContent();
    requireCurrent();
    let intended: Uint8Array | null = null;
    let authored: EnvelopeArtifact;
    try {
      // Keep the intended wire body separate from buffers passed to the author dependency.
      authored = await author.author(argument, (head) => {
        requireCurrent();
        const accepted = this.#session.heads().find((entry) => bytesEqual(entry.from, identity));
        const matches = head === null ? accepted === undefined
          : accepted !== undefined && accepted.seq === head.envelope.seq && bytesEqual(accepted.hash, head.hash) &&
            this.#session.classify(head).status === "duplicate";
        if (!matches) { throw this.#fail("recovery_required", new Error("Local authored and accepted heads must agree before signing")); }
        requireCurrent();
        intended = encodeUnsignedEnvelope({
          v: 1, game: this.#session.gameId, from: identity,
          seq: head === null ? 0 : head.envelope.seq + 1,
          prev: head === null ? parseHash256(new Uint8Array(32)) : head.hash,
          ...content,
        });
        return undefined;
      });
    } catch (cause) {
      // Once signing was permitted, an uncertain append outcome must be reconciled from durable history.
      if (intended !== null || cause instanceof AuthoredEnvelopeStoreError) { throw this.#fail("recovery_required", cause); }
      throw this.#failure ?? cause;
    }
    let received: EnvelopeArtifact;
    try {
      const bytes = authored.canonicalBytes;
      if (!(bytes instanceof Uint8Array) || bytes.constructor !== Uint8Array || bytes.length > MAX_ROUND_REVEAL_ENVELOPE_BYTES) {
        throw new Error("Invalid authored round envelope bytes");
      }
      received = decodeAndVerifyEnvelope(bytes);
      if (intended === null || !bytesEqual(encodeUnsignedEnvelope(received.envelope), intended)) {
        throw new Error("Authored round envelope does not match the guarded content");
      }
    } catch (cause) { throw this.#fail("invalid_receipt", cause); }
    try {
      // Avoid re-enqueueing behind ourselves. Closing after signing cannot erase this durable artifact.
      const result = await this.#receiveOne(received.canonicalBytes, true);
      if (result.status === "rejected") { throw new Error("Durably authored round envelope was rejected by local receipt"); }
      return result;
    } catch (cause) { throw this.#fail("recovery_required", cause); }
  }

  #classify(received: EnvelopeArtifact): RoundTransition {
    const expectedSeat = this.#hand.snapshot.turn ?? undefined;
    let classification: RoundRevealTransition | { readonly type: "AUDIT_DISCLOSE"; readonly seat: SaskuSeat; readonly status: "accepted" | "duplicate" };
    try {
      if (received.envelope.type === "AUDIT_DISCLOSE") {
        const envelope = received.envelope;
        if (!bytesEqual(envelope.game, this.#session.gameId)) { throw new RoundRevealError("wrong_game"); }
        const seat = this.#session.seatOf(parseIdentityPublicKey(envelope.from)) as SaskuSeat | null;
        if (seat === null) { throw new RoundRevealError("unknown_sender"); }
        if (envelope.round !== this.#round) { throw new RoundRevealError("wrong_round"); }
        const audit = this.#snapshot.audit;
        if (audit === null || envelope.phase !== audit.phase) { throw new RoundRevealError("wrong_phase"); }
        let body: ReturnType<typeof decodeAuditDiscloseBody>;
        try { body = decodeAuditDiscloseBody(envelope.body); }
        catch (cause) { throw new RoundRevealError("malformed_body", { cause }); }
        // A complete Sasku hand has opened every scheduled position; no shares remain to disclose.
        if (body.items.length !== 0) { throw new RoundRevealError("wrong_positions"); }
        const prior = this.#auditHashes.get(seat);
        if (prior !== undefined && prior !== bytesToHex(received.hash)) { throw new RoundRevealError("conflicting_contribution"); }
        classification = { type: "AUDIT_DISCLOSE", seat, status: prior === undefined ? "accepted" : "duplicate" };
      } else {
        classification = Object.freeze({ ...this.#ledger.classify(decodeAndVerifyEnvelope(received.canonicalBytes), expectedSeat) });
        if (classification.type !== received.envelope.type || classification.seat !== this.#session.seatOf(parseIdentityPublicKey(received.envelope.from)) ||
            !bytesEqual(classification.received.canonicalBytes, received.canonicalBytes)) {
          throw this.#fail("recovery_required", new Error("Reveal classification does not match the original envelope"));
        }
      }
    }
    catch (cause) {
      if (cause instanceof RoundRevealError && cause.code === "inconsistent_deck") {
        throw this.#fail("recovery_required", cause);
      }
      // Exact duplicates are classified before the ledger requires an active expected seat.
      if (expectedSeat === undefined && received.envelope.type === "ACTION" && cause instanceof RangeError) {
        throw new SaskuRoundReceiverError("hand_complete", { cause });
      }
      throw cause;
    }
    let action: SaskuHandAction | null = null;
    if (classification.type === "ACTION" && classification.status === "accepted") {
      if (expectedSeat === undefined) { throw new SaskuRoundReceiverError("hand_complete"); }
      const revealed = Object.fromEntries(Object.entries(classification.revealed).map(([pos, card]) => [pos, parseSaskuCard(card).id]));
      const body = decodeActionBody(received.envelope.body);
      action = decodeSaskuAction(classification.seat, {
        kind: body.kind, data: body.data, reveal: body.reveal,
      }, revealed);
      this.#hand.preview(action);
    }
    return { received, expectedSeat, type: classification.type, seat: classification.seat as SaskuSeat, status: classification.status, action };
  }

  async #receiveOne(bytes: Uint8Array, finishAuthored = false): Promise<SaskuRoundReceiveResult> {
    if (this.#failure !== null) { throw this.#failure; }
    if (this.#closed && !finishAuthored) { throw new SaskuRoundReceiverError("closed"); }
    const received = decodeAndVerifyEnvelope(bytes);
    const transition = this.#classify(received);
    let receipt: Awaited<ReturnType<PersistentSessionReceiver["receive"]>>;
    let chainStatus: "accepted" | "duplicate";
    let persistenceStatus: "stored" | "duplicate";
    try {
      // The durable dependency never receives the private admission/commit buffers.
      receipt = await this.#durable.receive(decodeAndVerifyEnvelope(bytes));
    } catch (cause) {
      if (this.#failure !== null) { throw this.#failure; }
      if (cause instanceof PersistentSessionReceiverError) { throw this.#fail("recovery_required", cause); }
      throw cause;
    }
    try {
      const returnedBytes = receipt.received.canonicalBytes;
      if (!(returnedBytes instanceof Uint8Array) || returnedBytes.constructor !== Uint8Array || !bytesEqual(returnedBytes, bytes)) {
        throw new Error("Durable receipt does not match the submitted artifact");
      }
      const status = receipt.status;
      if (status === "rejected") {
        const reason = receipt.reason;
        if (reason !== "gap" && reason !== "broken_prev" && reason !== "equivocation" && reason !== "durable_conflict") {
          throw new Error("Durable receipt contradicts the bound round scope");
        }
        if (this.#failure !== null) { throw this.#failure; }
        return Object.freeze({ status: "rejected", reason, received });
      }
      if (status !== "accepted" && status !== "duplicate") {
        throw new Error("Invalid durable receipt status");
      }
      const persisted = receipt.persistenceStatus;
      if (persisted !== "stored" && persisted !== "duplicate") { throw new Error("Invalid persistence status"); }
      chainStatus = status;
      persistenceStatus = persisted;
      const envelope = received.envelope;
      const recorded = this.#session.readRange(envelope.from, envelope.seq, envelope.seq);
      if (this.#session.classify(decodeAndVerifyEnvelope(bytes)).status !== "duplicate" || recorded.status !== "complete" ||
          recorded.envelopes.length !== 1 || !bytesEqual(recorded.envelopes[0]!.canonicalBytes, bytes)) {
        throw new Error("Durable receipt is not reflected in its bound session registry");
      }
    } catch (cause) { throw this.#fail("invalid_receipt", cause); }

    // A local private read can discover a bad supplied deck while persistence is pending.
    if (this.#failure !== null) { throw this.#failure; }
    this.#commit(transition);
    return Object.freeze({
      status: transition.status, received, chainStatus, persistenceStatus, snapshot: this.#snapshot,
    });
  }

  #commit({ received, expectedSeat, type, seat, status, action }: RoundTransition): void {
    try {
      if (type === "AUDIT_DISCLOSE") {
        if (status === "accepted") {
          const audit = this.#snapshot.audit!;
          const pendingSenders = Object.freeze(audit.pendingSenders.filter((pending) => pending !== seat));
          let result: SaskuRoundAuditSnapshot["result"] = null;
          if (pendingSenders.length === 0) {
            const hands: [SaskuCardId[], SaskuCardId[], SaskuCardId[], SaskuCardId[]] = [[], [], [], []];
            for (let pos = 0; pos < 36; pos += 1) {
              hands[this.ownerAt(pos)].push(parseSaskuCard(this.#snapshot.ledger.revealed[pos]).id);
            }
            const checked = auditSaskuHand({ dealer: this.#snapshot.hand.dealer, hands }, this.#snapshot.history);
            if (checked.status === "violation") { result = checked; }
            else {
              if (checked.status !== "valid" || checked.snapshot.score === null) { throw new Error("Completed Sasku audit returned an incomplete result"); }
              result = Object.freeze({ status: "valid", score: checked.snapshot.score });
            }
          }
          this.#auditHashes.set(seat, bytesToHex(received.hash));
          this.#snapshot = Object.freeze({ ...this.#snapshot, audit: Object.freeze({ phase: audit.phase, pendingSenders, result }) });
        }
      } else {
        const committed = this.#ledger.commit(decodeAndVerifyEnvelope(received.canonicalBytes), expectedSeat);
        if (committed.status !== status || committed.type !== type || committed.seat !== seat ||
            !bytesEqual(committed.received.canonicalBytes, received.canonicalBytes)) {
          throw new Error("Reveal commit does not match the original transition");
        }
        if (action?.type === "play" && (committed.type !== "ACTION" || Object.values(committed.revealed).length !== 1 ||
            Object.values(committed.revealed)[0] !== action.card)) { throw new Error("Committed reveal does not match the previewed card"); }
        if (action !== null) this.#hand.apply(action);
        if (committed.status === "accepted") {
          const ledger = this.#ledger.snapshot;
          const hand = this.#hand.snapshot;
          let audit = this.#snapshot.audit;
          if (hand.phase === "complete" && audit === null) {
            if (Object.keys(ledger.revealed).length !== 36) { throw new Error("Completed Sasku hand has unopened positions"); }
            audit = Object.freeze({ phase: `round.${this.#round}.audit`, pendingSenders: Object.freeze([0, 1, 2, 3] as const), result: null });
          }
          this.#snapshot = Object.freeze({ ledger, hand, history: this.#hand.history, audit });
        }
      }
    } catch (cause) { throw this.#fail("commit_failed", cause); }
  }

  #reserve(bytes: number): void {
    if (this.#pendingEnvelopes >= this.#maxPendingEnvelopes || bytes > this.#maxPendingBytes - this.#pendingBytes) {
      throw new SaskuRoundReceiverError("queue_limit");
    }
    if (this.#pendingEnvelopes === 0) {
      this.#idle = new Promise<void>((resolve) => { this.#resolveIdle = resolve; });
    }
    this.#pendingEnvelopes += 1;
    this.#pendingBytes += bytes;
  }

  #release(bytes: number): void {
    this.#pendingEnvelopes -= 1;
    this.#pendingBytes -= bytes;
    if (this.#pendingEnvelopes === 0) {
      const resolve = this.#resolveIdle;
      this.#resolveIdle = null;
      resolve?.();
    }
  }

  #rejectQueued(cause: SaskuRoundReceiverError): void {
    for (const job of this.#queue.splice(0)) {
      this.#release(job.size);
      job.reject(cause);
    }
  }

  #fail(code: SaskuRoundReceiverErrorCode, cause: unknown): SaskuRoundReceiverError {
    this.#failure ??= new SaskuRoundReceiverError(code, { cause });
    this.#rejectQueued(this.#failure);
    return this.#failure;
  }
}

function positiveInteger(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) { throw new RangeError("Sasku queue limits must be positive safe integers"); }
  return value;
}

function snapshotIntent(candidate: SaskuActionIntent): SaskuActionIntent {
  if (typeof candidate !== "object" || candidate === null ||
      (Object.getPrototypeOf(candidate) !== Object.prototype && Object.getPrototypeOf(candidate) !== null)) {
    throw new SaskuHandError("A plain local action intent is required");
  }
  const keys = Reflect.ownKeys(candidate);
  if (keys.length < 1 || keys.length > 2) { throw new SaskuHandError("Invalid local action fields"); }
  const fields: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of keys) {
    const property = Object.getOwnPropertyDescriptor(candidate, key);
    if (typeof key !== "string" || property === undefined || !property.enumerable || !("value" in property)) {
      throw new SaskuHandError("Local action fields must be enumerable data properties");
    }
    fields[key] = property.value;
  }
  const names = Object.keys(fields).sort().join(",");
  if ((fields["type"] === "pass" || fields["type"] === "diamonds") && names === "type") {
    return Object.freeze({ type: fields["type"] });
  }
  if (fields["type"] === "bid" && names === "type,value" && typeof fields["value"] === "number" &&
      Number.isSafeInteger(fields["value"]) && fields["value"] >= 3 && fields["value"] <= 9) {
    return Object.freeze({ type: "bid", value: fields["value"] });
  }
  if (fields["type"] === "choose_trump" && names === "suit,type" && SASKU_SUITS.includes(fields["suit"] as SaskuSuit)) {
    return Object.freeze({ type: "choose_trump", suit: fields["suit"] as SaskuSuit });
  }
  if (fields["type"] === "play" && names === "position,type" && typeof fields["position"] === "number" &&
      Number.isSafeInteger(fields["position"]) && fields["position"] >= 0 && fields["position"] < 36 && !Object.is(fields["position"], -0)) {
    return Object.freeze({ type: "play", position: fields["position"] });
  }
  throw new SaskuHandError("Invalid local action intent");
}
