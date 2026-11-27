import { bytesEqual, type RistrettoScalar } from "@p2pcards/crypto";
import { PersistentCandidateShuffleReceiver, type CandidateShuffleBody, type CandidateShuffleCheckpoint, type CandidateShuffleSnapshot } from "@p2pcards/engine";
import { decodeAndVerifyEnvelope, decodeRosterBody, encodeRosterBody, parseIdentityPublicKey,
  type EnvelopeArtifact, type IdentityPublicKey } from "@p2pcards/protocol";
import { SASKU_DECK_SPEC, MAX_SASKU_HAND_ACTIONS } from "@p2pcards/rules-sasku";
import { PersistentEnvelopeAuthor, type ChainHead } from "@p2pcards/session";
import { captureCandidateSaskuPolicy, type CandidateShuffledSaskuRoundOptions } from "./candidate-shuffled-round";
import { PersistentSaskuRoundReceiver, type SaskuActionIntent, type SaskuRoundCheckpoint, type SaskuRoundSnapshot } from "./persistent-round-receiver";

export interface CandidateRoundOwnerOptions extends CandidateShuffledSaskuRoundOptions {
  /** The caller serializes operations and defers future-phase traffic. */
  readonly serializedByCaller?: boolean;
  readonly maxPendingEnvelopes?: number;
  readonly maxPendingBytes?: number;
}
export interface CandidateRoundCheckpoint {
  readonly round: number;
  readonly heads: readonly ChainHead[];
  readonly shuffle: CandidateShuffleCheckpoint;
  readonly reveal: SaskuRoundCheckpoint | null;
}

export type CandidateRoundOwnerSnapshot =
  | { readonly phase: "shuffle"; readonly state: CandidateShuffleSnapshot }
  | { readonly phase: "round"; readonly state: SaskuRoundSnapshot };
export type CandidateRoundReceipt = { readonly received: EnvelopeArtifact } &
  ({ readonly status: "accepted" | "duplicate" } | { readonly status: "rejected"; readonly reason: string });
interface Job {
  readonly size: number;
  readonly artifact?: EnvelopeArtifact;
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
  /** Replays signed history by default. A local checkpoint must match all four sender heads. */
  static async open(input: CandidateRoundOwnerOptions, trustedCheckpoint?: CandidateRoundCheckpoint): Promise<CandidateSaskuRoundOwner> {
    for (const value of [input.maxPendingEnvelopes ?? 32, input.maxPendingBytes ?? 1024 * 1024]) {
      if (!Number.isSafeInteger(value) || value < 1) throw new Error("Invalid owner queue limit");
    }
    const options = Object.freeze({ ...input, ...captureCandidateSaskuPolicy(input),
      roster: decodeRosterBody(encodeRosterBody(input.roster)), self: parseIdentityPublicKey(input.self),
      ...(input.historyLimits === undefined ? {} : { historyLimits: Object.freeze({ ...input.historyLimits }) }),
      ...(input.roundHistoryLimits === undefined ? {} : { roundHistoryLimits: Object.freeze({ ...input.roundHistoryLimits }) }) });
    if (trustedCheckpoint !== undefined) {
      const heads = options.session.heads();
      if (trustedCheckpoint.round !== options.round || heads.length !== 4 || trustedCheckpoint.heads.length !== 4 ||
          heads.some(({ from, seq, hash }, seat) => {
            const expected = trustedCheckpoint.heads[seat]!;
            return seq !== expected.seq || !bytesEqual(from, expected.from) || !bytesEqual(hash, expected.hash);
          })) throw new Error("Round checkpoint does not match the session heads");
    }
    const shuffle = await PersistentCandidateShuffleReceiver.open({ ...options, deckSpec: SASKU_DECK_SPEC, serializedByCaller: true }, trustedCheckpoint?.shuffle);
    const owner = new CandidateSaskuRoundOwner(options, shuffle);
    try {
      if (trustedCheckpoint !== undefined && shuffle.snapshot.complete !== (trustedCheckpoint.reveal !== null)) {
        throw new Error("Inconsistent checkpoint phase");
      }
      await owner.#promote(trustedCheckpoint?.reveal ?? undefined);
      return owner;
    } catch (error) { owner.close(); throw error; }
  }
  exportCheckpoint(): CandidateRoundCheckpoint {
    this.#guard();
    if (this.pendingEnvelopes !== 0) throw new Error("Cannot checkpoint a busy round");
    return { round: this.#options.round, heads: this.#options.session.heads(), shuffle: this.#shuffle.exportCheckpoint(), reveal: this.#round?.exportCheckpoint() ?? null };
  }
  get snapshot(): CandidateRoundOwnerSnapshot {
    return this.#round === null ? Object.freeze({ phase: "shuffle", state: this.#shuffle.snapshot })
      : Object.freeze({ phase: "round", state: this.#round.snapshot });
  }
  get pendingEnvelopes(): number { return this.#queue.length + (this.#active === null ? 0 : 1); }
  get pendingBytes(): number { return this.#pendingBytes; }
  get failure(): Error | null { return this.#failure ?? this.#round?.failure ?? this.#shuffle.failure; }
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
      return this.#admit(this.#decode(payload), peer);
    } catch (error) { return Promise.reject(error); }
  }
  /** For originals from separately preflighted sync history. */
  receiveHistory(candidate: EnvelopeArtifact): Promise<CandidateRoundReceipt> {
    try { return this.#admit(candidate); } catch (error) { return Promise.reject(error); }
  }
  authorShuffle(author: PersistentEnvelopeAuthor, prepared: CandidateShuffleBody, expected: CandidateShuffleSnapshot): Promise<CandidateRoundReceipt> {
    try {
      this.#checkAuthor(author);
      const size = prepared.outputDeck.length + prepared.proof.length;
      this.#capacity(size);
      if (size > 16 * 1024) throw new Error("Invalid shuffle preparation size");
      const captured = { outputDeck: prepared.outputDeck.slice(), proof: prepared.proof.slice() };
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
  #decode(payload: Uint8Array): EnvelopeArtifact {
    if (payload.length < 1 || payload.length > 64 * 1024) throw new Error("Invalid semantic envelope size");
    this.#capacity(payload.length);
    return decodeAndVerifyEnvelope(payload);
  }
  #admit(artifact: EnvelopeArtifact, peer?: IdentityPublicKey): Promise<CandidateRoundReceipt> {
    const job = this.#prepare(artifact, peer);
    return this.#enqueue(job.size, job.stage, job.index, job.run, artifact);
  }
  #prepare(artifact: EnvelopeArtifact, peer?: IdentityPublicKey): Omit<Job, "resolve" | "reject"> {
    this.#guard();
    const { canonicalBytes: bytes, envelope: e } = artifact;
    if (bytes.length < 1 || bytes.length > 64 * 1024) throw new Error("Invalid semantic envelope size");
    this.#capacity(bytes.length);
    if (peer && !bytesEqual(peer, e.from)) throw new Error("Direct sender differs from authenticated peer");
    if (!bytesEqual(e.game, this.#options.roster.gameId) || e.round !== this.#options.round ||
      !this.#options.roster.seats.some(id => bytesEqual(id, e.from))) throw new Error("Wrong round scope");
    for (const job of [...this.#queue, ...(this.#active ? [this.#active] : [])]) {
      if (!job.artifact) continue;
      const prior = job.artifact.envelope;
      if (prior.seq === e.seq && bytesEqual(prior.from, e.from) && !bytesEqual(job.artifact.canonicalBytes, bytes)) throw new Error("Conflicting queued sender sequence");
    }
    const stage = ["SHUFFLE", "SHARES", "ACTION", "AUDIT_DISCLOSE"].indexOf(e.type);
    if (stage < 0) throw new Error("Unsupported semantic traffic");
    const prefix = `round.${e.round}.${["shuffle", "deal", "play", "audit"][stage]}`;
    const index = stage === 3 ? 0 : Number(e.phase.slice(prefix.length + 1));
    const limit = [4, this.#options.schedule.length, MAX_SASKU_HAND_ACTIONS, 1][stage]!;
    if (!Number.isSafeInteger(index) || index < 0 || index >= limit || e.phase !== (stage === 3 ? prefix : `${prefix}.${index}`)) throw new Error("Invalid semantic phase");
    return { size: bytes.length, stage, index, artifact, run: async () => {
      if (stage === 0) {
        if (!this.#round) return this.#shuffle.receive(artifact);
        // Round opening already verified every stored shuffle; only exact recorded replays are admissible here.
        if (this.#options.session.classify(artifact).status !== "duplicate") throw new Error("Shuffle phase is complete");
        return this.#options.sessionReceiver.receiveVerified(artifact);
      }
      return this.#requireRound().receive(artifact);
    } };
  }
  #capacity(size: number): void {
    this.#guard();
    if (!Number.isSafeInteger(size) || size < 1 || this.pendingEnvelopes >= this.#maxCount || size > this.#maxBytes - this.#pendingBytes) throw new Error("Round owner queue limit");
  }
  #enqueue(size: number, stage: number, index: number, run: Job["run"], artifact?: EnvelopeArtifact): Promise<CandidateRoundReceipt> {
    this.#capacity(size);
    if (this.#options.serializedByCaller) return this.#execute(run);
    this.#pendingBytes += size;
    const result = new Promise<CandidateRoundReceipt>((resolve, reject) => {
      this.#queue.push({ size, stage, index, run, resolve, reject, ...(artifact === undefined ? {} : { artifact }) });
    });
    this.#start();
    return result;
  }
  #eligible(job: Pick<Job, "artifact" | "stage" | "index">): boolean {
    if (!job.artifact || job.stage === -1) return true;
    const chain = this.#options.session.classify(job.artifact);
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
          job.resolve(await this.#execute(job.run));
        } catch (error) {
          if (this.#failure) this.#rejectQueued(this.#failure);
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
  async #execute(run: Job["run"]): Promise<CandidateRoundReceipt> {
    try {
      const result = await run();
      if (!this.#closed) await this.#promote();
      return result;
    } catch (error) {
      this.#failure ??= this.#shuffle.failure ?? this.#round?.failure ?? null;
      throw error;
    }
  }
  async #promote(checkpoint?: SaskuRoundCheckpoint): Promise<void> {
    if (this.#closed || this.#round || !this.#shuffle.snapshot.complete) return;
    let round: PersistentSaskuRoundReceiver | undefined;
    try {
      // The shuffle owner derived setup and the final deck from this session's signed history.
      const setup = this.#shuffle.completedSetup;
      const deck = this.#shuffle.finalDeck;
      const options = { setup, round: this.#options.round, deck,
        dealer: this.#options.dealer, schedule: this.#options.schedule,
        ...(this.#options.batchDeal === undefined ? {} : { batchDeal: this.#options.batchDeal }),
        ...(this.#options.dealBackend === undefined ? {} : { dealBackend: this.#options.dealBackend }),
        session: this.#options.session, sessionReceiver: this.#options.sessionReceiver, serializedByCaller: true };
      round = checkpoint === undefined
        ? await PersistentSaskuRoundReceiver.recoverWithBackend(options, this.#options.roundHistoryLimits)
        : PersistentSaskuRoundReceiver.restoreTrustedCheckpoint(options, checkpoint);
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
