import { bytesEqual, type RistrettoScalar } from "@p2pcards/crypto";
import { PersistentCandidateShuffleReceiver, recoverSetup, type CandidateShuffleSnapshot } from "@p2pcards/engine";
import { decodeAndVerifyEnvelope, decodeRosterBody, encodeRosterBody, parseIdentityPublicKey,
  type EnvelopeArtifact, type IdentityPublicKey } from "@p2pcards/protocol";
import { SASKU_DECK_SPEC, MAX_SASKU_HAND_ACTIONS } from "@p2pcards/rules-sasku";
import { PersistentEnvelopeAuthor, captureSessionHistory } from "@p2pcards/session";
import { captureCandidateSaskuPolicy, type CandidateShuffledSaskuRoundOptions } from "./candidate-shuffled-round";
import { PersistentSaskuRoundReceiver, type SaskuActionIntent, type SaskuRoundSnapshot } from "./persistent-round-receiver";

export interface CandidateRoundOwnerOptions extends CandidateShuffledSaskuRoundOptions {
  readonly maxPendingEnvelopes?: number;
  readonly maxPendingBytes?: number;
}
export type CandidateRoundOwnerSnapshot =
  | { readonly phase: "shuffle"; readonly state: CandidateShuffleSnapshot }
  | { readonly phase: "round"; readonly state: SaskuRoundSnapshot };
export type CandidateRoundReceipt = { readonly received: EnvelopeArtifact } &
  ({ readonly status: "accepted" | "duplicate" } | { readonly status: "rejected"; readonly reason: string });
interface Job {
  readonly size: number;
  readonly bytes?: Uint8Array;
  readonly stage: number;
  readonly index: number;
  readonly run: () => Promise<CandidateRoundReceipt>;
  readonly resolve: (value: CandidateRoundReceipt) => void;
  readonly reject: (error: unknown) => void;
}

/** Exclusive semantic owner after completed setup. Transport authentication and application readiness remain caller prerequisites. */
export class CandidateSaskuRoundOwner {
  readonly #options: CandidateRoundOwnerOptions;
  #shuffle: PersistentCandidateShuffleReceiver;
  #round: PersistentSaskuRoundReceiver | null = null;
  readonly #queue: Job[] = [];
  #active: Job | null = null;
  #pendingBytes = 0;
  #closed = false;
  #failure: Error | null = null;
  #idle: Promise<void> = Promise.resolve();
  #resolveIdle: (() => void) | null = null;
  readonly #maxCount: number;
  readonly #maxBytes: number;

  private constructor(options: CandidateRoundOwnerOptions, shuffle: PersistentCandidateShuffleReceiver) {
    this.#options = options; this.#shuffle = shuffle;
    this.#maxCount = options.maxPendingEnvelopes ?? 32;
    this.#maxBytes = options.maxPendingBytes ?? 1024 * 1024;
  }
  static async open(input: CandidateRoundOwnerOptions): Promise<CandidateSaskuRoundOwner> {
    for (const value of [input.maxPendingEnvelopes ?? 32, input.maxPendingBytes ?? 1024 * 1024]) {
      if (!Number.isSafeInteger(value) || value < 1) throw new Error("Invalid owner queue limit");
    }
    const options = Object.freeze({ ...input, ...captureCandidateSaskuPolicy(input),
      roster: decodeRosterBody(encodeRosterBody(input.roster)), self: parseIdentityPublicKey(input.self),
      ...(input.historyLimits === undefined ? {} : { historyLimits: Object.freeze({ ...input.historyLimits }) }),
      ...(input.roundHistoryLimits === undefined ? {} : { roundHistoryLimits: Object.freeze({ ...input.roundHistoryLimits }) }) });
    const shuffle = await PersistentCandidateShuffleReceiver.open({ ...options, deckSpec: SASKU_DECK_SPEC });
    const owner = new CandidateSaskuRoundOwner(options, shuffle);
    try { await owner.#promote(); return owner; } catch (error) { owner.close(); throw error; }
  }
  get snapshot(): CandidateRoundOwnerSnapshot {
    return this.#round === null ? Object.freeze({ phase: "shuffle", state: this.#shuffle.snapshot })
      : Object.freeze({ phase: "round", state: this.#round.snapshot });
  }
  get pendingEnvelopes(): number { return this.#queue.length + (this.#active === null ? 0 : 1); }
  get pendingBytes(): number { return this.#pendingBytes; }
  get failure(): Error | null { return this.#failure; }
  get closed(): boolean { return this.#closed; }
  /** Quiescent processing only; future-phase and missing-predecessor jobs may remain queued. */
  whenIdle(): Promise<void> { return this.#idle; }
  nextShuffleStatement(): Uint8Array {
    this.#guard(); if (this.#active || this.#round) throw new Error("Shuffle preparation is unavailable");
    return this.#shuffle.nextStatement();
  }
  readPrivateHand(secret: RistrettoScalar) {
    this.#guard(); if (this.#active || !this.#round) throw new Error("Private hand is unavailable");
    return this.#round.readPrivateHand(this.#options.self, secret);
  }
  /** Direct peer identity must come from an authenticated, ready transport; never from payload claims. */
  receive(remote: IdentityPublicKey, payload: Uint8Array): Promise<CandidateRoundReceipt> {
    try {
      const peer = parseIdentityPublicKey(remote);
      if (bytesEqual(peer, this.#options.self) || !this.#options.roster.seats.some(id => bytesEqual(id, peer))) throw new Error("Wrong direct peer");
      return this.#admit(payload, peer);
    } catch (error) { return Promise.reject(error); }
  }
  /** For originals from separately preflighted sync history. Does not admit a SYNC_RESP wrapper or execute controls. */
  receiveHistory(candidate: EnvelopeArtifact): Promise<CandidateRoundReceipt> {
    try { return this.#admit(candidate.canonicalBytes); } catch (error) { return Promise.reject(error); }
  }
  authorShuffle(author: PersistentEnvelopeAuthor, prepared: { readonly statement: Uint8Array; readonly proof: Uint8Array }, expected: CandidateShuffleSnapshot): Promise<CandidateRoundReceipt> {
    try {
      this.#checkAuthor(author);
      const size = prepared.statement.length + prepared.proof.length;
      this.#capacity(size);
      if (size > 16 * 1024) throw new Error("Invalid shuffle preparation size");
      const captured = { statement: prepared.statement.slice(), proof: prepared.proof.slice() };
      return this.#enqueue(size, -1, 0, () => {
        if (this.#round) throw new Error("Shuffle phase is complete");
        return this.#shuffle.author(author, captured, expected);
      });
    } catch (error) { return Promise.reject(error); }
  }
  authorDealShares(author: PersistentEnvelopeAuthor, secret: RistrettoScalar, expected: SaskuRoundSnapshot): Promise<CandidateRoundReceipt> {
    return this.#local(author, () => this.#requireRound().authorDealShares(author, secret, expected));
  }
  authorAction(author: PersistentEnvelopeAuthor, secret: RistrettoScalar, expected: SaskuRoundSnapshot, intent: SaskuActionIntent): Promise<CandidateRoundReceipt> {
    const captured = Object.freeze({ ...intent });
    return this.#local(author, () => this.#requireRound().authorAction(author, secret, expected, captured));
  }
  authorAuditDisclose(author: PersistentEnvelopeAuthor, expected: SaskuRoundSnapshot): Promise<CandidateRoundReceipt> {
    return this.#local(author, () => this.#requireRound().authorAuditDisclose(author, expected));
  }
  close(): void {
    this.#closed = true;
    // Active durable receipt finishes under its receiver; close does not pretend to roll back writes.
    this.#rejectQueued(new Error("Round owner is closed"));
    if (!this.#active) { this.#shuffle.close(); this.#round?.close(); }
  }
  #checkAuthor(author: PersistentEnvelopeAuthor): void {
    this.#guard();
    if (!(author instanceof PersistentEnvelopeAuthor) || !bytesEqual(author.sender, this.#options.self) ||
      !bytesEqual(author.gameId, this.#options.roster.gameId)) throw new Error("Wrong local author");
  }
  #local(author: PersistentEnvelopeAuthor, run: () => Promise<CandidateRoundReceipt>): Promise<CandidateRoundReceipt> {
    try { this.#checkAuthor(author); return this.#enqueue(64 * 1024, -1, 0, run); }
    catch (error) { return Promise.reject(error); }
  }
  #requireRound(): PersistentSaskuRoundReceiver {
    if (!this.#round) throw new Error("Round phase has not started"); return this.#round;
  }
  #admit(payload: Uint8Array, peer?: IdentityPublicKey): Promise<CandidateRoundReceipt> {
    const job = this.#prepare(payload, peer);
    return this.#enqueue(job.size, job.stage, job.index, job.run, job.bytes);
  }
  #prepare(payload: Uint8Array, peer?: IdentityPublicKey): Omit<Job, "resolve" | "reject"> {
    this.#guard();
    if (!(payload instanceof Uint8Array) || payload.constructor !== Uint8Array || payload.length < 1 || payload.length > 64 * 1024) throw new Error("Invalid semantic envelope size");
    this.#capacity(payload.length);
    const bytes = payload.slice(), { envelope: e } = decodeAndVerifyEnvelope(bytes);
    if (peer && !bytesEqual(peer, e.from)) throw new Error("Direct sender differs from authenticated peer");
    if (!bytesEqual(e.game, this.#options.roster.gameId) || e.round !== this.#options.round ||
      !this.#options.roster.seats.some(id => bytesEqual(id, e.from))) throw new Error("Wrong round scope");
    for (const job of [...this.#queue, ...(this.#active ? [this.#active] : [])]) {
      if (!job.bytes) continue;
      const prior = decodeAndVerifyEnvelope(job.bytes).envelope;
      if (prior.seq === e.seq && bytesEqual(prior.from, e.from) && !bytesEqual(job.bytes, bytes)) throw new Error("Conflicting queued sender sequence");
    }
    const stage = ["SHUFFLE", "SHARES", "ACTION", "AUDIT_DISCLOSE"].indexOf(e.type);
    if (stage < 0) throw new Error("Unsupported semantic traffic");
    const prefix = `round.${e.round}.${["shuffle", "deal", "play", "audit"][stage]}`;
    const index = stage === 3 ? 0 : Number(e.phase.slice(prefix.length + 1));
    const limit = [4, this.#options.schedule.length, MAX_SASKU_HAND_ACTIONS, 1][stage]!;
    if (!Number.isSafeInteger(index) || index < 0 || index >= limit || e.phase !== (stage === 3 ? prefix : `${prefix}.${index}`)) throw new Error("Invalid semantic phase");
    return { size: bytes.length, stage, index, bytes, run: async () => {
      const artifact = decodeAndVerifyEnvelope(bytes);
      if (stage === 0) {
        if (!this.#round) return this.#shuffle.receive(artifact);
        // Round opening already verified every stored shuffle; only exact recorded replays are admissible here.
        if (this.#options.session.classify(artifact).status !== "duplicate") throw new Error("Shuffle phase is complete");
        return this.#options.sessionReceiver.receive(artifact);
      }
      return this.#requireRound().receive(artifact);
    } };
  }
  #capacity(size: number): void {
    this.#guard();
    if (!Number.isSafeInteger(size) || size < 1 || this.pendingEnvelopes >= this.#maxCount || size > this.#maxBytes - this.#pendingBytes) throw new Error("Round owner queue limit");
  }
  #enqueue(size: number, stage: number, index: number, run: Job["run"], bytes?: Uint8Array): Promise<CandidateRoundReceipt> {
    this.#capacity(size);
    this.#pendingBytes += size;
    const result = new Promise<CandidateRoundReceipt>((resolve, reject) => {
      this.#queue.push({ size, stage, index, run, resolve, reject, ...(bytes === undefined ? {} : { bytes }) });
    });
    this.#start();
    return result;
  }
  #eligible(job: Pick<Job, "bytes" | "stage" | "index">): boolean {
    if (!job.bytes || job.stage === -1) return true;
    const chain = this.#options.session.classify(decodeAndVerifyEnvelope(job.bytes));
    if (chain.status === "rejected") return chain.reason !== "gap";
    const stage = this.#round === null ? 0 : this.#round.snapshot.audit !== null ? 3 : this.#round.snapshot.ledger.deal !== null ? 1 : 2;
    const index = this.#round === null ? this.#shuffle.snapshot.nextSeat ?? 4 : stage === 1 ? this.#round.snapshot.ledger.dealIndex : stage === 2 ? this.#round.snapshot.ledger.actionIndex : 0;
    return job.stage < stage || (job.stage === stage && job.index <= index);
  }
  #start(): void {
    if (this.#resolveIdle || this.#closed || this.#failure) return;
    this.#idle = new Promise(resolve => { this.#resolveIdle = resolve; });
    void this.#drain();
  }
  async #drain(): Promise<void> {
    try {
      while (!this.#closed && !this.#failure) {
        const index = this.#queue.findIndex(job => this.#eligible(job));
        if (index < 0) break;
        const job = this.#queue.splice(index, 1)[0]!; this.#active = job;
        try {
          const result = await job.run();
          if (!this.#closed) await this.#promote();
          job.resolve(result);
        } catch (error) {
          const fatal = this.#failure ?? this.#shuffle.failure ?? this.#round?.failure;
          if (fatal) { this.#failure = fatal; this.#rejectQueued(fatal); }
          job.reject(error);
        } finally { this.#pendingBytes -= job.size; this.#active = null; }
      }
    } catch (error) {
      this.#failure = new Error("Round owner recovery required", { cause: error }); this.#rejectQueued(this.#failure);
    } finally {
      if (this.#closed || this.#failure) { this.#shuffle.close(); this.#round?.close(); }
      const resolve = this.#resolveIdle; this.#resolveIdle = null; resolve?.();
    }
  }
  async #promote(): Promise<void> {
    if (this.#closed || this.#round || !this.#shuffle.snapshot.complete) return;
    let round: PersistentSaskuRoundReceiver | undefined;
    try {
      // The live shuffle owner has already verified each original before its
      // durable receipt and is checkpoint-bound to the same session. Reuse its
      // verified final deck; reopening after a restart still re-verifies all
      // stored proofs in PersistentCandidateShuffleReceiver.open.
      const history = captureSessionHistory(this.#options.session, this.#options.historyLimits);
      const setup = recoverSetup(this.#options.roster.gameId, this.#options.setupRound,
        this.#options.roster.seats, history.envelopes, this.#options.beaconRequired).coordinator;
      const deck = this.#shuffle.finalDeck;
      history.assertUnchanged();
      round = PersistentSaskuRoundReceiver.recover({ setup, round: this.#options.round, deck,
        dealer: this.#options.dealer, schedule: this.#options.schedule,
        ...(this.#options.batchDeal === undefined ? {} : { batchDeal: this.#options.batchDeal }), session: this.#options.session,
        sessionReceiver: this.#options.sessionReceiver }, this.#options.roundHistoryLimits);
      history.assertUnchanged();
      if (this.#closed) { round.close(); return; }
      this.#round = round; this.#shuffle.close();
    } catch (error) {
      round?.close();
      this.#failure = new Error("Round handoff requires recovery", { cause: error }); throw this.#failure;
    }
  }
  #rejectQueued(error: Error): void { for (const job of this.#queue.splice(0)) { this.#pendingBytes -= job.size; job.reject(error); } }
  #guard(): void { if (this.#failure) throw this.#failure; if (this.#closed) throw new Error("Round owner is closed"); }
}
