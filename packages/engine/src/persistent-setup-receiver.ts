import { bytesEqual, bytesToHex, type RandomSource } from "@p2pcards/crypto";
import { encodeGameKeyShareBody } from "@p2pcards/deck";
import {
  decodeAndVerifyEnvelope, encodeRandCommitBody, encodeRandRevealBody, encodeUnsignedEnvelope,
  parseGameId, parseHash256, parseIdentityPublicKey,
  type EnvelopeArtifact, type GameId, type IdentityPublicKey,
} from "@p2pcards/protocol";
import {
  AuthoredEnvelopeStoreError, captureSessionHistory, MAX_AUTHORED_HISTORY_PAGE_BYTES, PersistentEnvelopeAuthor,
  PersistentSessionReceiver, PersistentSessionReceiverError, SessionChainRegistry,
  type EnvelopeContent, type SessionHistoryCaptureLimits,
} from "@p2pcards/session";

import { prepareLocalBeaconContribution, restoreLocalBeaconContribution, type DurableSetupBeaconSecretStore, type SetupBeaconSecretReader } from "./local-beacon-contribution";
import { prepareLocalGameKeyShare, type DurableGameSecretStore } from "./local-key-share";
import { SetupEnvelopeCoordinator, type SetupEnvelopeResult } from "./setup-envelope-coordinator";
import { recoverSetup } from "./setup-recovery";
import type { SetupState } from "./setup-coordinator";

export const MAX_SETUP_ENVELOPE_BYTES = 64 * 1024;
export const DEFAULT_MAX_PENDING_SETUP_ENVELOPES = 32;
export const DEFAULT_MAX_PENDING_SETUP_BYTES = 1024 * 1024;

export interface PersistentSetupReceiverOptions {
  readonly round: number;
  readonly self: IdentityPublicKey;
  readonly session: SessionChainRegistry;
  readonly sessionReceiver: PersistentSessionReceiver;
  readonly maxPendingEnvelopes?: number;
  readonly maxPendingBytes?: number;
  readonly historyLimits?: SessionHistoryCaptureLimits;
}

/** Public, immutable progress only: no key scalar, beacon preimage, or mutable byte views. */
export interface PersistentSetupSnapshot {
  readonly state: SetupState;
  readonly pendingSenders: readonly number[];
  readonly publicKeys: readonly (string | null)[];
  readonly commitments: readonly (string | null)[];
  readonly aggregateKey: string | null;
  readonly seed: string | null;
}

export type DurableSessionReceiveResult =
  | { readonly status: "accepted" | "duplicate"; readonly persistenceStatus: "stored" | "duplicate"; readonly received: EnvelopeArtifact }
  | { readonly status: "rejected"; readonly reason: string; readonly received: EnvelopeArtifact };

type CommittedSetupTransition = Exclude<SetupEnvelopeResult, { readonly status: "rejected" }>;
export type PersistentSetupReceiveResult =
  | Extract<SetupEnvelopeResult, { readonly status: "rejected" }>
  | { readonly status: "rejected"; readonly reason: "chain_rejected"; readonly classification: CommittedSetupTransition;
      readonly chainResult: Extract<DurableSessionReceiveResult, { readonly status: "rejected" }>; readonly received: EnvelopeArtifact }
  | { readonly status: "accepted" | "duplicate" | "failed"; readonly transition: CommittedSetupTransition;
      readonly chainResult: Extract<DurableSessionReceiveResult, { readonly status: "accepted" | "duplicate" }>;
      readonly received: EnvelopeArtifact; readonly snapshot: PersistentSetupSnapshot };

export type PersistentSetupReceiverErrorCode =
  | "invalid_envelope" | "queue_limit" | "closed" | "stale_setup" | "wrong_phase" | "unexpected_author"
  | "already_contributed" | "setup_incomplete" | "setup_failed" | "invalid_receipt" | "commit_failed" | "recovery_required";

export class PersistentSetupReceiverError extends Error {
  readonly code: PersistentSetupReceiverErrorCode;
  constructor(code: PersistentSetupReceiverErrorCode, options?: ErrorOptions) {
    super(`Persistent setup receiver: ${code}`, options);
    this.name = "PersistentSetupReceiverError";
    this.code = code;
  }
}

type SetupMessageType = "KEY_SHARE" | "RAND_COMMIT" | "RAND_REVEAL";
interface PendingOperation {
  readonly size: number;
  readonly run: () => Promise<PersistentSetupReceiveResult>;
  readonly resolve: (result: PersistentSetupReceiveResult) => void;
  readonly reject: (cause: unknown) => void;
}

const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype) as object;
const typedArrayLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, "length")!.get!;
const typedArrayByteLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, "byteLength")!.get!;

/** Single owner of setup receipt and local authoring. Construction reads a quiescent, restored registry, never storage. */
export class PersistentSetupReceiver {
  readonly #coordinator: SetupEnvelopeCoordinator;
  readonly #session: SessionChainRegistry;
  readonly #durable: PersistentSessionReceiver;
  readonly #gameId: GameId;
  readonly #round: number;
  readonly #roster: readonly IdentityPublicKey[];
  readonly #self: IdentityPublicKey;
  readonly #seat: number;
  readonly #maxPendingEnvelopes: number;
  readonly #maxPendingBytes: number;
  readonly #queue: PendingOperation[] = [];
  #active = false;
  #closed = false;
  #failure: PersistentSetupReceiverError | null = null;
  #pendingEnvelopes = 0;
  #pendingBytes = 0;
  #idle: Promise<void> = Promise.resolve();
  #resolveIdle: (() => void) | null = null;
  #snapshot: PersistentSetupSnapshot;

  constructor(options: PersistentSetupReceiverOptions) {
    const captured = Object.freeze({ ...options });
    if (!(captured.session instanceof SessionChainRegistry) || !(captured.sessionReceiver instanceof PersistentSessionReceiver) ||
        !captured.sessionReceiver.isBoundTo(captured.session)) {
      throw new TypeError("Setup requires the concrete durable receiver bound to its session registry");
    }
    if (!Number.isSafeInteger(captured.round) || captured.round < 0 || Object.is(captured.round, -0)) {
      throw new RangeError("Setup round must be a non-negative safe integer");
    }
    this.#session = captured.session;
    this.#durable = captured.sessionReceiver;
    this.#gameId = this.#session.gameId;
    this.#round = captured.round;
    this.#roster = this.#session.roster;
    this.#self = parseIdentityPublicKey(captured.self);
    this.#seat = this.#roster.findIndex((sender) => bytesEqual(sender, this.#self));
    if (this.#seat === -1) { throw new TypeError("The local setup identity must belong to the finalized roster"); }
    this.#maxPendingEnvelopes = positiveInteger(captured.maxPendingEnvelopes ?? DEFAULT_MAX_PENDING_SETUP_ENVELOPES);
    this.#maxPendingBytes = positiveInteger(captured.maxPendingBytes ?? DEFAULT_MAX_PENDING_SETUP_BYTES);
    const history = captureSessionHistory(this.#session, captured.historyLimits);
    for (const artifact of history.envelopes) {
      if ((artifact.envelope.type === "KEY_SHARE" || artifact.envelope.type === "RAND_COMMIT" || artifact.envelope.type === "RAND_REVEAL") &&
          artifact.canonicalBytes.length > MAX_SETUP_ENVELOPE_BYTES) {
        throw new PersistentSetupReceiverError("invalid_envelope");
      }
    }
    this.#coordinator = recoverSetup(this.#gameId, this.#round, this.#roster, history.envelopes).coordinator;
    this.#snapshot = this.#view();
    history.assertUnchanged();
  }

  get gameId(): GameId { return parseGameId(this.#gameId); }
  get round(): number { return this.#round; }
  get roster(): readonly IdentityPublicKey[] { return Object.freeze(this.#roster.map(parseIdentityPublicKey)); }
  get self(): IdentityPublicKey { return parseIdentityPublicKey(this.#self); }
  get snapshot(): PersistentSetupSnapshot { return this.#snapshot; }
  get failure(): PersistentSetupReceiverError | null { return this.#failure; }
  get closed(): boolean { return this.#closed; }
  get pendingEnvelopes(): number { return this.#pendingEnvelopes; }
  get pendingBytes(): number { return this.#pendingBytes; }
  isBoundTo(session: SessionChainRegistry): boolean { return this.#session === session; }
  whenIdle(): Promise<void> { return this.#idle; }

  /** Completed core setup cannot accept a new contribution. No mutable coordinator escapes before completion. */
  getCompletedSetup(): SetupEnvelopeCoordinator {
    if (this.#failure !== null) throw this.#failure;
    if (this.#snapshot.state === "failed") throw new PersistentSetupReceiverError("setup_failed");
    if (this.#snapshot.state !== "complete" || this.#pendingEnvelopes !== 0) throw new PersistentSetupReceiverError("setup_incomplete");
    return this.#coordinator;
  }

  receive(candidate: EnvelopeArtifact): Promise<PersistentSetupReceiveResult> {
    let reserved: number | null = null;
    try {
      this.#requireOpen();
      const input = candidate?.canonicalBytes;
      const size = byteSize(input);
      this.#reserve(size);
      reserved = size;
      const bytes = new Uint8Array(size);
      bytes.set(input);
      try { decodeAndVerifyEnvelope(bytes); }
      catch (cause) { throw new PersistentSetupReceiverError("invalid_envelope", { cause }); }
      this.#requireOpen();
      const promise = this.#enqueue(size, () => this.#receiveOne(bytes));
      reserved = null;
      return promise;
    } catch (cause) {
      if (reserved !== null) this.#release(reserved);
      return Promise.reject(cause);
    }
  }

  authorKeyShare(author: PersistentEnvelopeAuthor, store: DurableGameSecretStore, expected: PersistentSetupSnapshot, source?: RandomSource): Promise<PersistentSetupReceiveResult> {
    return this.#author(author, expected, "KEY_SHARE", async (guard) => {
      const local = await prepareLocalGameKeyShare({ gameId: this.gameId, round: this.#round, phase: "setup.keys" }, store, source, guard);
      return () => ({ type: "KEY_SHARE", round: this.#round, phase: "setup.keys", body: encodeGameKeyShareBody(local.share) });
    });
  }

  authorRandCommit(author: PersistentEnvelopeAuthor, store: DurableSetupBeaconSecretStore, expected: PersistentSetupSnapshot, source?: RandomSource): Promise<PersistentSetupReceiveResult> {
    return this.#author(author, expected, "RAND_COMMIT", async (guard) => {
      const local = await prepareLocalBeaconContribution({ gameId: this.gameId, round: this.#round, roster: this.roster, sender: this.self }, store, source, guard);
      return () => ({ type: "RAND_COMMIT", round: this.#round, phase: "setup.rand", body: encodeRandCommitBody({ cm: local.commitment }) });
    });
  }

  authorRandReveal(author: PersistentEnvelopeAuthor, store: SetupBeaconSecretReader, expected: PersistentSetupSnapshot): Promise<PersistentSetupReceiveResult> {
    return this.#author(author, expected, "RAND_REVEAL", async (guard) => {
      const cm = this.#coordinator.commitmentAt(this.#seat);
      if (cm === null) throw this.#fail("recovery_required", new Error("Reveal phase is missing the local commitment"));
      const local = await restoreLocalBeaconContribution({ gameId: this.gameId, round: this.#round, roster: this.roster, sender: this.self }, store, cm, guard);
      return () => ({ type: "RAND_REVEAL", round: this.#round, phase: "setup.rand", body: encodeRandRevealBody({ s: local.secret }) });
    });
  }

  close(): void {
    this.#closed = true;
    this.#rejectQueued(this.#failure ?? new PersistentSetupReceiverError("closed"));
  }

  #author(
    author: PersistentEnvelopeAuthor, expected: PersistentSetupSnapshot, type: SetupMessageType,
    prepare: (guard: () => undefined) => Promise<() => EnvelopeContent>,
  ): Promise<PersistentSetupReceiveResult> {
    let reserved = false;
    try {
      this.#requireOpen();
      this.#reserve(MAX_SETUP_ENVELOPE_BYTES);
      reserved = true;
      if (!(author instanceof PersistentEnvelopeAuthor) || !bytesEqual(author.gameId, this.#gameId) || !bytesEqual(author.sender, this.#self)) {
        throw new PersistentSetupReceiverError("unexpected_author");
      }
      if (expected !== this.#snapshot) throw new PersistentSetupReceiverError("stale_setup");
      const result = this.#enqueue(MAX_SETUP_ENVELOPE_BYTES, () => this.#authorOne(author, expected, type, prepare));
      reserved = false;
      return result;
    } catch (cause) {
      if (reserved) this.#release(MAX_SETUP_ENVELOPE_BYTES);
      return Promise.reject(cause);
    }
  }

  async #authorOne(
    author: PersistentEnvelopeAuthor, expected: PersistentSetupSnapshot, type: SetupMessageType,
    prepare: (guard: () => undefined) => Promise<() => EnvelopeContent>,
  ): Promise<PersistentSetupReceiveResult> {
    const guard = (): undefined => {
      this.#requireOpen();
      if (this.#snapshot.state === "failed") throw new PersistentSetupReceiverError("setup_failed");
      const phase = type === "KEY_SHARE" ? "keys" : type === "RAND_COMMIT" ? "rand_commit" : "rand_reveal";
      if (expected.state !== phase) throw new PersistentSetupReceiverError("wrong_phase");
      if (this.#snapshot.state !== phase) throw new PersistentSetupReceiverError("stale_setup");
      if (!this.#snapshot.pendingSenders.includes(this.#seat)) throw new PersistentSetupReceiverError("already_contributed");
      return undefined;
    };
    guard();
    try {
      const head = await author.readHead();
      guard();
      this.#requireHead(head);
    } catch (cause) {
      if (cause instanceof AuthoredEnvelopeStoreError) throw this.#fail("recovery_required", cause);
      throw this.#failure ?? cause;
    }
    const makeContent = await prepare(guard);
    guard();
    const content = makeContent();
    const argument = makeContent();
    guard();
    let intended: Uint8Array | null = null;
    let authored: EnvelopeArtifact;
    try {
      authored = await author.author(argument, (head) => {
        guard();
        this.#requireHead(head);
        guard();
        intended = encodeUnsignedEnvelope({
          v: 1, game: this.#gameId, from: this.#self, seq: head === null ? 0 : head.envelope.seq + 1,
          prev: head === null ? parseHash256(new Uint8Array(32)) : head.hash, ...content,
        });
        return undefined;
      });
    } catch (cause) {
      if (intended !== null || cause instanceof AuthoredEnvelopeStoreError) throw this.#fail("recovery_required", cause);
      throw this.#failure ?? cause;
    }
    let received: EnvelopeArtifact;
    try {
      received = snapshotArtifact(authored);
      if (intended === null || !bytesEqual(encodeUnsignedEnvelope(received.envelope), intended)) {
        throw new Error("Authored setup envelope does not match the guarded content");
      }
    } catch (cause) { throw this.#fail("invalid_receipt", cause); }
    try {
      const result = await this.#receiveOne(received.canonicalBytes, true);
      if (result.status === "rejected") throw new Error("Authored setup envelope was not locally accepted");
      return result;
    } catch (cause) { throw this.#fail("recovery_required", cause); }
  }

  #requireHead(candidate: EnvelopeArtifact | null): void {
    try {
      const head = candidate === null ? null : snapshotArtifact(candidate, MAX_AUTHORED_HISTORY_PAGE_BYTES);
      const accepted = this.#session.heads().find(({ from }) => bytesEqual(from, this.#self));
      if (head === null ? accepted !== undefined
        : accepted === undefined || !bytesEqual(head.envelope.game, this.#gameId) || !bytesEqual(head.envelope.from, this.#self) ||
          head.envelope.seq !== accepted.seq || !bytesEqual(head.hash, accepted.hash) ||
          this.#session.classify(decodeAndVerifyEnvelope(head.canonicalBytes)).status !== "duplicate") {
        throw new Error("Authored and accepted setup heads must agree before private preparation or signing");
      }
      if (head !== null) {
        const recorded = this.#session.readRange(this.self, head.envelope.seq, head.envelope.seq);
        if (recorded.status !== "complete" || recorded.envelopes.length !== 1 ||
            !bytesEqual(snapshotArtifact(recorded.envelopes[0]!, MAX_AUTHORED_HISTORY_PAGE_BYTES).canonicalBytes, head.canonicalBytes)) {
          throw new Error("Accepted setup predecessor bytes disagree with the authored head");
        }
      }
    } catch (cause) { throw this.#fail("recovery_required", cause); }
  }

  async #receiveOne(bytes: Uint8Array, finishAuthored = false): Promise<PersistentSetupReceiveResult> {
    if (this.#failure !== null) throw this.#failure;
    if (this.#closed && !finishAuthored) throw new PersistentSetupReceiverError("closed");
    const received = decodeAndVerifyEnvelope(bytes);
    let classification: SetupEnvelopeResult;
    try { classification = this.#normalize(this.#coordinator.classify(decodeAndVerifyEnvelope(bytes)), bytes); }
    catch (cause) { throw this.#fail("recovery_required", cause); }
    if (classification.status === "rejected") return classification;
    let receipt: Awaited<ReturnType<PersistentSessionReceiver["receive"]>>;
    try { receipt = await this.#durable.receive(decodeAndVerifyEnvelope(bytes)); }
    catch (cause) {
      if (cause instanceof PersistentSessionReceiverError) throw this.#fail("recovery_required", cause);
      throw this.#failure ?? cause;
    }
    let chainResult: DurableSessionReceiveResult;
    try {
      if (!bytesEqual(snapshotArtifact(receipt.received).canonicalBytes, bytes)) throw new Error("Setup receipt belongs to a different artifact");
      const status = receipt.status;
      if (status === "rejected") {
        const reason = receipt.reason;
        if (!["gap", "broken_prev", "equivocation", "durable_conflict"].includes(reason)) throw new Error("Setup receipt contradicts its bound scope");
        if (this.#failure !== null) throw this.#failure;
        return Object.freeze({ status, reason: "chain_rejected", classification,
          chainResult: Object.freeze({ status, reason, received: decodeAndVerifyEnvelope(bytes) }), received });
      }
      if (status !== "accepted" && status !== "duplicate") throw new Error("Invalid setup receipt status");
      const persistenceStatus = receipt.persistenceStatus;
      if (persistenceStatus !== "stored" && persistenceStatus !== "duplicate") throw new Error("Invalid setup persistence status");
      const recorded = this.#session.readRange(parseIdentityPublicKey(received.envelope.from), received.envelope.seq, received.envelope.seq);
      if (this.#session.classify(decodeAndVerifyEnvelope(bytes)).status !== "duplicate" || recorded.status !== "complete" ||
          recorded.envelopes.length !== 1 || !bytesEqual(snapshotArtifact(recorded.envelopes[0]!).canonicalBytes, bytes)) {
        throw new Error("Setup receipt is not reflected in its bound registry");
      }
      chainResult = Object.freeze({ status, persistenceStatus, received: decodeAndVerifyEnvelope(bytes) });
    } catch (cause) { throw this.#fail("invalid_receipt", cause); }
    if (this.#failure !== null) throw this.#failure;
    try {
      const transition = this.#normalize(this.#coordinator.ingest(decodeAndVerifyEnvelope(bytes)), bytes);
      if (transition.status === "rejected" || transition.status !== classification.status || transition.state !== classification.state ||
          transition.seat !== classification.seat || this.#coordinator.state !== transition.state) {
        throw new Error("Setup transition changed during durable receipt");
      }
      if (transition.status !== "duplicate") this.#snapshot = this.#view();
      return Object.freeze({ status: transition.status, transition, chainResult, received, snapshot: this.#snapshot });
    } catch (cause) { throw this.#fail("commit_failed", cause); }
  }

  #normalize(candidate: SetupEnvelopeResult, bytes: Uint8Array): SetupEnvelopeResult {
    try {
      const received = snapshotArtifact(candidate.received);
      if (!bytesEqual(received.canonicalBytes, bytes)) throw new Error("Setup transition does not match the original bytes");
      const status = candidate.status;
      const state = candidate.state;
      const seat = candidate.seat;
      if (!["keys", "rand_commit", "rand_reveal", "complete", "failed"].includes(state)) throw new Error("Invalid setup transition state");
      if (status === "rejected") return Object.freeze({ status, state, reason: candidate.reason, received,
        ...(seat === undefined ? {} : { seat }) });
      if (seat === undefined || seat !== this.#session.seatOf(parseIdentityPublicKey(received.envelope.from))) throw new Error("Invalid setup transition seat");
      if (status === "failed") {
        if (state !== "failed" || candidate.reason !== "aggregate_key_is_identity") throw new Error("Invalid collective setup failure");
        return Object.freeze({ status, state, reason: "aggregate_key_is_identity", seat, received,
          setupResult: Object.freeze({ status, state, reason: "aggregate_key_is_identity" }) });
      }
      if (status !== "accepted" && status !== "duplicate") throw new Error("Invalid setup transition status");
      return Object.freeze({ status, state, seat, received, setupResult: Object.freeze({ status, state, seat }) });
    } catch (cause) { throw this.#fail("invalid_receipt", cause); }
  }

  #view(): PersistentSetupSnapshot {
    return Object.freeze({
      state: this.#coordinator.state,
      pendingSenders: Object.freeze([...this.#coordinator.pendingSenders]),
      publicKeys: Object.freeze(this.#roster.map((_, seat) => {
        const key = this.#coordinator.publicKeyAt(seat);
        return key === null ? null : bytesToHex(key.toBytes());
      })),
      commitments: Object.freeze(this.#roster.map((_, seat) => {
        const cm = this.#coordinator.commitmentAt(seat);
        return cm === null ? null : bytesToHex(cm);
      })),
      aggregateKey: this.#coordinator.aggregateKey === null ? null : bytesToHex(this.#coordinator.aggregateKey.toBytes()),
      seed: this.#coordinator.seed === null ? null : bytesToHex(this.#coordinator.seed),
    });
  }

  #requireOpen(): void {
    if (this.#failure !== null) throw this.#failure;
    if (this.#closed) throw new PersistentSetupReceiverError("closed");
  }

  #enqueue(size: number, run: PendingOperation["run"]): Promise<PersistentSetupReceiveResult> {
    this.#requireOpen();
    const result = new Promise<PersistentSetupReceiveResult>((resolve, reject) => this.#queue.push({ size, run, resolve, reject }));
    void this.#drain();
    return result;
  }

  async #drain(): Promise<void> {
    if (this.#active) return;
    this.#active = true;
    try {
      for (let job = this.#queue.shift(); job !== undefined; job = this.#queue.shift()) {
        try { job.resolve(await job.run()); }
        catch (cause) { job.reject(cause); }
        finally { this.#release(job.size); }
      }
    } finally { this.#active = false; }
  }

  #reserve(size: number): void {
    if (this.#pendingEnvelopes >= this.#maxPendingEnvelopes || size > this.#maxPendingBytes - this.#pendingBytes) throw new PersistentSetupReceiverError("queue_limit");
    if (this.#pendingEnvelopes === 0) this.#idle = new Promise<void>((resolve) => { this.#resolveIdle = resolve; });
    this.#pendingEnvelopes += 1;
    this.#pendingBytes += size;
  }

  #release(size: number): void {
    this.#pendingEnvelopes -= 1;
    this.#pendingBytes -= size;
    if (this.#pendingEnvelopes === 0) {
      const resolve = this.#resolveIdle;
      this.#resolveIdle = null;
      resolve?.();
    }
  }

  #rejectQueued(cause: Error): void {
    for (const job of this.#queue.splice(0)) { this.#release(job.size); job.reject(cause); }
  }

  #fail(code: PersistentSetupReceiverErrorCode, cause: unknown): PersistentSetupReceiverError {
    this.#failure ??= new PersistentSetupReceiverError(code, { cause });
    this.#rejectQueued(this.#failure);
    return this.#failure;
  }
}

function positiveInteger(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new RangeError("Setup queue limits must be positive safe integers");
  return value;
}

function byteSize(value: Uint8Array, limit = MAX_SETUP_ENVELOPE_BYTES): number {
  try {
    if (!(value instanceof Uint8Array) || value.constructor !== Uint8Array) throw new Error("Expected bytes");
    const size = typedArrayLength.call(value) as number;
    if (size < 1 || size > limit || typedArrayByteLength.call(value) !== size) throw new Error("Invalid setup envelope size");
    return size;
  } catch (cause) { throw new PersistentSetupReceiverError("invalid_envelope", { cause }); }
}

function snapshotArtifact(candidate: EnvelopeArtifact, limit = MAX_SETUP_ENVELOPE_BYTES): EnvelopeArtifact {
  const value = candidate?.canonicalBytes;
  const bytes = new Uint8Array(byteSize(value, limit));
  bytes.set(value);
  return decodeAndVerifyEnvelope(bytes);
}
