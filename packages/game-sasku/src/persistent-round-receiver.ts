import { bytesEqual, bytesToHex, type RandomSource, type RistrettoScalar } from "@p2pcards/crypto";
import { decodeAuditDiscloseBody, encodeActionBody, encodeAuditDiscloseBody, encodeSharesBody, type ActionBody, type DecryptionShareBatchBackend, type MaskedCard } from "@p2pcards/deck";
import {
  MAX_ROUND_REVEAL_ENVELOPE_BYTES, RoundRevealError, RoundRevealLedger, SetupEnvelopeCoordinator,
  type PrivateDealStep, type RoundRevealCheckpoint, type RoundRevealSnapshot, type RoundRevealTransition,
} from "@p2pcards/engine";
import { encodeUnsignedEnvelope, parseHash256, parseIdentityPublicKey, type EnvelopeArtifact, type IdentityPublicKey } from "@p2pcards/protocol";
import {
  MAX_SASKU_HAND_ACTIONS, SASKU_DECK_SPEC, SaskuHandError, SaskuPublicHandController,
  auditSaskuHand, decodeSaskuAction, legalSaskuCards, parseSaskuCard, saskuBidStrength,
  type SaskuCardId, type SaskuHandAction, type SaskuHandAuditResult, type SaskuHandScore, type SaskuPublicHandSnapshot, type SaskuSeat, type SaskuSuit,
} from "@p2pcards/rules-sasku";
import { AuthoredEnvelopeStoreError, PersistentEnvelopeAuthor, PersistentSessionReceiver, PersistentSessionReceiverError, SessionChainRegistry, type EnvelopeContent } from "@p2pcards/session";

import { captureSaskuRoundHistory, SaskuRoundRecoveryError, type SaskuRoundRecoveryLimits } from "./round-recovery";

const AUDIT_SEATS = Object.freeze([0, 1, 2, 3] as const);

export const DEFAULT_MAX_PENDING_SASKU_ENVELOPES = 32;
export const DEFAULT_MAX_PENDING_SASKU_BYTES = 1024 * 1024;

export interface PersistentSaskuRoundOptions {
  readonly setup: SetupEnvelopeCoordinator;
  readonly round: number;
  readonly deck: readonly MaskedCard[];
  readonly schedule: readonly PrivateDealStep[];
  readonly batchDeal?: boolean;
  readonly dealBackend?: DecryptionShareBatchBackend;
  readonly dealer: SaskuSeat;
  readonly session: SessionChainRegistry;
  readonly sessionReceiver: PersistentSessionReceiver;
  /** Use direct transitions under an existing round owner. */
  readonly serializedByCaller?: boolean;
  readonly maxPendingEnvelopes?: number;
  readonly maxPendingBytes?: number;
}

export interface SaskuRoundSnapshot {
  readonly ledger: RoundRevealSnapshot;
  readonly hand: SaskuPublicHandSnapshot;
  readonly history: readonly SaskuHandAction[];
  readonly audit: SaskuRoundAuditSnapshot | null;
}

export interface SaskuRoundCheckpoint {
  readonly reveal: RoundRevealCheckpoint;
  readonly history: readonly SaskuHandAction[];
  readonly auditHashes: readonly (readonly [SaskuSeat, string])[];
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
  readonly reveal: RoundRevealTransition | null;
  readonly type: "SHARES" | "ACTION" | "AUDIT_DISCLOSE";
  readonly seat: SaskuSeat;
  readonly status: "accepted" | "duplicate";
  readonly action: SaskuHandAction | null;
}

/** Owns deal, public play, and local hand audit. Setup, shuffle provenance, and the agreed schedule/dealer remain caller prerequisites. */
export class PersistentSaskuRoundReceiver {
  readonly #ledger: RoundRevealLedger;
  readonly #setup: SetupEnvelopeCoordinator;
  readonly #dealBackend: DecryptionShareBatchBackend | undefined;
  readonly #hand: SaskuPublicHandController;
  readonly #session: SessionChainRegistry;
  readonly #durable: PersistentSessionReceiver;
  readonly #maxPendingEnvelopes: number;
  readonly #maxPendingBytes: number;
  readonly #round: number;
  readonly #serializedByCaller: boolean;
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
    this.#setup = options.setup;
    this.#durable = options.sessionReceiver;
    this.#hand = new SaskuPublicHandController({ dealer: options.dealer });
    this.#ledger = new RoundRevealLedger({
      setup: options.setup, round: options.round, deck: options.deck, schedule: options.schedule,
      deckSpec: SASKU_DECK_SPEC, maxActions: MAX_SASKU_HAND_ACTIONS,
      ...(options.batchDeal === undefined ? {} : { batchDeal: options.batchDeal }),
    });
    this.#round = options.round;
    this.#dealBackend = options.dealBackend;
    this.#serializedByCaller = options.serializedByCaller ?? false;
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
    const receiver = new PersistentSaskuRoundReceiver(options);
    try {
      for (const artifact of receiver.#replay(limits)) {
        receiver.#commitRecovered(receiver.#classify(artifact));
      }
      return receiver;
    } catch (cause) { throw receiver.#recoveryError(cause); }
  }

  static async recoverWithBackend(options: PersistentSaskuRoundOptions, limits?: SaskuRoundRecoveryLimits): Promise<PersistentSaskuRoundReceiver> {
    const backend = options.dealBackend;
    if (!backend) return this.recover(options, limits);
    const receiver = new PersistentSaskuRoundReceiver(options);
    try {
      for (const artifact of receiver.#replay(limits)) {
        const prepared = artifact.envelope.type === "SHARES"
          ? await receiver.#ledger.prepareDealReceipt(artifact, backend) : undefined;
        receiver.#commitRecovered(receiver.#classify(artifact, prepared?.transition), prepared?.commit);
      }
      return receiver;
    } catch (cause) { throw receiver.#recoveryError(cause); }
  }

  *#replay(limits?: SaskuRoundRecoveryLimits): Generator<EnvelopeArtifact> {
    const history = captureSaskuRoundHistory(this.#setup, this.#session, this.#round, limits);
    const next = [0, 0, 0, 0];
    let remaining = history.bySeat.reduce((sum, messages) => sum + messages.length, 0);
    while (remaining > 0) {
      const snapshot = this.#snapshot;
      const type = snapshot.audit !== null ? "AUDIT_DISCLOSE" : snapshot.ledger.deal !== null ? "SHARES" : "ACTION";
      const phase = snapshot.audit?.phase ?? snapshot.ledger.phase;
      // Only the first unprocessed message from each sender is eligible.
      const seat = history.bySeat.findIndex((chain, index) => {
        const envelope = chain[next[index]!]?.envelope;
        return envelope?.type === type && envelope.phase === phase;
      });
      if (seat === -1) throw new SaskuRoundRecoveryError("Round history has missing or out-of-order prerequisites");
      yield history.bySeat[seat]![next[seat]!]!;
      next[seat]! += 1;
      remaining -= 1;
    }
    history.assertUnchanged();
  }

  #commitRecovered(transition: RoundTransition, commitPreparedDeal?: () => RoundRevealTransition): void {
    if (transition.status !== "accepted") throw new SaskuRoundRecoveryError("Round history repeats a semantic contribution");
    this.#commit(transition, commitPreparedDeal);
  }

  #recoveryError(cause: unknown): unknown {
    this.close();
    if (cause instanceof SaskuRoundRecoveryError || cause instanceof RangeError || cause instanceof TypeError) return cause;
    return new SaskuRoundRecoveryError("Could not reconstruct Sasku round semantics", { cause });
  }

  /** Restore only local derived state whose four sender heads have been matched. */
  static restoreTrustedCheckpoint(options: PersistentSaskuRoundOptions, state: SaskuRoundCheckpoint): PersistentSaskuRoundReceiver {
    const receiver = new PersistentSaskuRoundReceiver(options);
    if (state.history.length !== state.reveal.actionIndex ||
        (state.history.length > 0 && state.reveal.dealIndex !== options.schedule.length)) {
      throw new Error("Invalid Sasku round checkpoint");
    }
    receiver.#ledger.restoreTrustedCheckpoint(state.reveal);
    for (const action of state.history) receiver.#hand.apply(action);
    const hand = receiver.#hand.snapshot;
    if (hand.phase !== "complete" && state.auditHashes.length > 0) throw new Error("Invalid checkpoint audit phase");
    for (const [seat, hash] of state.auditHashes) receiver.#auditHashes.set(seat, hash);
    const ledger = receiver.#ledger.snapshot;
    const history = receiver.#hand.history;
    const pendingSenders = AUDIT_SEATS.filter(seat => !receiver.#auditHashes.has(seat));
    const audit = hand.phase === "complete" ? receiver.#auditSnapshot(pendingSenders, ledger, hand, history) : null;
    receiver.#snapshot = Object.freeze({ ledger, hand, history, audit });
    return receiver;
  }

  exportCheckpoint(): SaskuRoundCheckpoint {
    return {
      reveal: this.#ledger.exportCheckpoint(), history: this.#snapshot.history,
      auditHashes: [...this.#auditHashes],
    };
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
      const captured = { ...intent };
      return () => this.#authorActionOne(author, identity, secretKey, expected, captured, source);
    });
  }

  /** Authors only the current scheduled nonrecipient batch; peers may contribute first in the same phase. */
  authorDealShares(
    author: PersistentEnvelopeAuthor, secretKey: RistrettoScalar, expected: SaskuRoundSnapshot, source?: RandomSource,
  ): Promise<SaskuRoundReceiveResult> {
    return this.#enqueueAuthoring(author, expected, "stale_contribution", (identity) => {
      const seat = this.#session.seatOf(identity)! as SaskuSeat;
      return async () => {
        const requireCurrent = (): void => this.#requireContribution(expected, seat, "SHARES");
        requireCurrent();
        const body = this.#dealBackend && source === undefined
          ? await this.#ledger.createDealSharesWithBackend(seat, secretKey, this.#dealBackend)
          : this.#ledger.createDealShares(seat, secretKey, source);
        return this.#authorAndReceive(author, identity, {
          round: this.#round, phase: expected.ledger.phase, type: "SHARES", body: encodeSharesBody(body),
        }, requireCurrent);
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
        return this.#authorAndReceive(author, identity, {
          round: this.#round, phase: expected.audit!.phase, type: "AUDIT_DISCLOSE", body: encodeAuditDiscloseBody({ items: [] }),
        }, requireCurrent);
      };
    });
  }

  #enqueueAuthoring(
    author: PersistentEnvelopeAuthor, expected: SaskuRoundSnapshot, staleCode: "stale_action" | "stale_contribution",
    capture: (identity: IdentityPublicKey) => PendingOperation["run"],
  ): Promise<SaskuRoundReceiveResult> {
    try {
      this.#guard();
      if (!(author instanceof PersistentEnvelopeAuthor)) { throw new TypeError("Local authoring requires a persistent envelope author"); }
      if (!bytesEqual(author.gameId, this.#session.gameId)) { throw new RoundRevealError("wrong_game"); }
      const identity = author.sender;
      if (this.#session.seatOf(identity) === null) { throw new RoundRevealError("unknown_sender"); }
      if (expected !== this.#snapshot) { throw new SaskuRoundReceiverError(staleCode); }
      return this.#schedule(MAX_ROUND_REVEAL_ENVELOPE_BYTES, capture(identity));
    } catch (cause) { return Promise.reject(cause); }
  }

  #guard(): void {
    if (this.#failure !== null) throw this.#failure;
    if (this.#closed) throw new SaskuRoundReceiverError("closed");
  }

  #schedule(size: number, run: PendingOperation["run"]): Promise<SaskuRoundReceiveResult> {
    if (this.#serializedByCaller) return run();
    this.#reserve(size);
    const pending = new Promise<SaskuRoundReceiveResult>((resolve, reject) => this.#queue.push({ size, resolve, reject, run }));
    void this.#drain();
    return pending;
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

  /** Receives a signed artifact produced by the protocol codec or local author. */
  async receive(received: EnvelopeArtifact): Promise<SaskuRoundReceiveResult> {
    this.#guard();
    const size = received.canonicalBytes.length;
    if (size === 0 || size > MAX_ROUND_REVEAL_ENVELOPE_BYTES) throw new SaskuRoundReceiverError("invalid_envelope");
    return this.#schedule(size, () => this.#receiveOne(received));
  }

  /** Cancels queued work. An already submitted durable receipt is allowed to finish consistently. */
  close(): void {
    this.#ledger.clearPrivateHands();
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
    if (action.type === "bid" && action.value > saskuBidStrength(Object.values(privateHand.dealt))) {
      throw new SaskuHandError("A bid cannot exceed the player's calculated hand strength", "bid_strength");
    }
    if (action.type === "play") {
      const contract = expected.hand.contract!;
      const trump = contract.kind === "pass_round" ? "diamonds" : contract.suit;
      if (!legalSaskuCards(Object.values(privateHand.remaining), expected.hand.trick, trump).includes(action.card)) {
        throw new SaskuHandError("The player must follow the effective led suit", "follow_suit");
      }
    }
    const body: ActionBody = {
      kind: intent.type,
      data: intent.type === "bid" ? { value: intent.value } : intent.type === "choose_trump" ? { suit: intent.suit } : {},
      reveal: intent.type === "play" ? [intent.position] : [],
      shares: intent.type === "play" ? [this.#ledger.createActionShare(seat, secretKey, intent.position, source)] : [],
    };
    return this.#authorAndReceive(author, identity, {
      round: this.#round, phase: expected.ledger.phase, type: "ACTION", body: encodeActionBody(body),
    }, requireCurrent);
  }

  async #authorAndReceive(
    author: PersistentEnvelopeAuthor, identity: IdentityPublicKey,
    content: EnvelopeContent, requireCurrent: () => void,
  ): Promise<SaskuRoundReceiveResult> {
    requireCurrent();
    let intended: Uint8Array | null = null;
    let authored: EnvelopeArtifact;
    try {
      authored = await author.author(content, (head) => {
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
    if (authored.canonicalBytes.length > MAX_ROUND_REVEAL_ENVELOPE_BYTES ||
        intended === null || !bytesEqual(encodeUnsignedEnvelope(authored.envelope), intended)) {
      throw this.#fail("invalid_receipt", new Error("Authored round envelope does not match the guarded content"));
    }
    try {
      // Avoid re-enqueueing behind ourselves. Closing after signing cannot erase this durable artifact.
      const result = await this.#receiveOne(authored, true);
      if (result.status === "rejected") { throw new Error("Durably authored round envelope was rejected by local receipt"); }
      return result;
    } catch (cause) { throw this.#fail("recovery_required", cause); }
  }

  #classify(received: EnvelopeArtifact, prepared?: RoundRevealTransition): RoundTransition {
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
        classification = prepared ?? this.#ledger.classify(received, expectedSeat);
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
      const body = classification.body;
      action = decodeSaskuAction(classification.seat, {
        kind: body.kind, data: body.data, reveal: body.reveal,
      }, revealed);
      this.#hand.preview(action);
    }
    return { received, reveal: "received" in classification ? classification : null, type: classification.type, seat: classification.seat as SaskuSeat, status: classification.status, action };
  }

  async #receiveOne(received: EnvelopeArtifact, finishAuthored = false): Promise<SaskuRoundReceiveResult> {
    if (this.#failure !== null) { throw this.#failure; }
    if (this.#closed && !finishAuthored) { throw new SaskuRoundReceiverError("closed"); }
    const prepared = this.#dealBackend && received.envelope.type === "SHARES"
      ? await this.#ledger.prepareDealReceipt(received, this.#dealBackend) : undefined;
    if (this.#closed && !finishAuthored) { throw new SaskuRoundReceiverError("closed"); }
    if (this.#failure !== null) { throw this.#failure; }
    const transition = this.#classify(received, prepared?.transition);
    let receipt: Awaited<ReturnType<PersistentSessionReceiver["receive"]>>;
    let chainStatus: "accepted" | "duplicate";
    let persistenceStatus: "stored" | "duplicate";
    try {
      receipt = await this.#durable.receiveVerified(received);
    } catch (cause) {
      if (this.#failure !== null) { throw this.#failure; }
      if (cause instanceof PersistentSessionReceiverError) { throw this.#fail("recovery_required", cause); }
      throw cause;
    }
    try {
      const returnedBytes = receipt.received.canonicalBytes;
      if (!(returnedBytes instanceof Uint8Array) || returnedBytes.constructor !== Uint8Array || !bytesEqual(returnedBytes, received.canonicalBytes)) {
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
      if (this.#session.classify(received).status !== "duplicate" || recorded.status !== "complete" ||
          recorded.envelopes.length !== 1 || !bytesEqual(recorded.envelopes[0]!.canonicalBytes, received.canonicalBytes)) {
        throw new Error("Durable receipt is not reflected in its bound session registry");
      }
    } catch (cause) { throw this.#fail("invalid_receipt", cause); }

    // A local private read can discover a bad supplied deck while persistence is pending.
    if (this.#failure !== null) { throw this.#failure; }
    this.#commit(transition, prepared?.commit);
    return Object.freeze({
      status: transition.status, received, chainStatus, persistenceStatus, snapshot: this.#snapshot,
    });
  }

  #commit(
    { received, reveal, type, seat, status, action }: RoundTransition,
    commitPreparedDeal?: () => RoundRevealTransition,
  ): void {
    try {
      if (type === "AUDIT_DISCLOSE") {
        if (status === "accepted") {
          const { audit, ledger, hand, history } = this.#snapshot;
          const pendingSenders = audit!.pendingSenders.filter(pending => pending !== seat);
          const nextAudit = this.#auditSnapshot(pendingSenders, ledger, hand, history);
          this.#auditHashes.set(seat, bytesToHex(received.hash));
          this.#snapshot = Object.freeze({ ...this.#snapshot, audit: nextAudit });
        }
      } else {
        const committed = commitPreparedDeal ? commitPreparedDeal() : this.#ledger.commit(reveal!);
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
            audit = this.#auditSnapshot(AUDIT_SEATS, ledger, hand, this.#hand.history);
          }
          this.#snapshot = Object.freeze({ ledger, hand, history: this.#hand.history, audit });
        }
      }
    } catch (cause) { throw this.#fail("commit_failed", cause); }
  }

  #auditSnapshot(
    pendingSenders: readonly SaskuSeat[],
    ledger: RoundRevealSnapshot,
    hand: SaskuPublicHandSnapshot,
    history: readonly SaskuHandAction[],
  ): SaskuRoundAuditSnapshot {
    let result: SaskuRoundAuditSnapshot["result"] = null;
    if (pendingSenders.length === 0) {
      const hands: [SaskuCardId[], SaskuCardId[], SaskuCardId[], SaskuCardId[]] = [[], [], [], []];
      for (let pos = 0; pos < 36; pos++) hands[this.ownerAt(pos)].push(parseSaskuCard(ledger.revealed[pos]).id);
      const checked = auditSaskuHand({ dealer: hand.dealer, hands }, history);
      if (checked.status === "violation") result = checked;
      else {
        if (checked.status !== "valid" || checked.snapshot.score === null) throw new Error("Completed Sasku audit returned an incomplete result");
        result = Object.freeze({ status: "valid", score: checked.snapshot.score });
      }
    }
    return Object.freeze({ phase: `round.${this.#round}.audit`, pendingSenders: Object.freeze(pendingSenders), result });
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
    this.#ledger.clearPrivateHands();
    this.#rejectQueued(this.#failure);
    return this.#failure;
  }
}

function positiveInteger(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) { throw new RangeError("Sasku queue limits must be positive safe integers"); }
  return value;
}
