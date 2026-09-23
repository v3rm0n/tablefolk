import { bytesEqual, bytesToHex } from "@p2pcards/crypto";
import { decodeActionBody, decodeAuditDiscloseBody, decodeSharesBody } from "@p2pcards/deck";
import { MAX_ROUND_REVEAL_ENVELOPE_BYTES } from "@p2pcards/engine";
import { decodeAndVerifyEnvelope, parseGameId, parseIdentityPublicKey, type GameId, type IdentityPublicKey } from "@p2pcards/protocol";
import { MAX_SASKU_HAND_ACTIONS } from "@p2pcards/rules-sasku";
import { SessionChainRegistry } from "@p2pcards/session";

import { PersistentSaskuRoundReceiver, type SaskuRoundReceiveResult } from "./persistent-round-receiver";

export const DEFAULT_MAX_PENDING_SASKU_INBOX_ENVELOPES = 32;
export const DEFAULT_MAX_PENDING_SASKU_INBOX_BYTES = 1024 * 1024;

const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype) as object;
const typedArrayLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, "length")!.get!;
const typedArrayByteLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, "byteLength")!.get!;

export interface SaskuRoundInboxOptions {
  readonly receiver: PersistentSaskuRoundReceiver;
  readonly session: SessionChainRegistry;
  readonly self: IdentityPublicKey;
  readonly maxPendingEnvelopes?: number;
  readonly maxPendingBytes?: number;
}

export type SaskuRoundInboxErrorCode =
  | "invalid_envelope" | "wrong_game" | "wrong_round" | "wrong_peer" | "wrong_type" | "wrong_phase"
  | "queue_limit" | "conflicting_pending" | "closed" | "invalid_receipt";

export class SaskuRoundInboxError extends Error {
  readonly code: SaskuRoundInboxErrorCode;
  constructor(code: SaskuRoundInboxErrorCode, options?: ErrorOptions) {
    super(`Sasku round inbox: ${code}`, options);
    this.name = "SaskuRoundInboxError";
    this.code = code;
  }
}

interface PendingEnvelope {
  readonly bytes: Uint8Array;
  readonly seat: number;
  readonly seq: number;
  readonly stage: number;
  readonly index: number;
  readonly resolve: (result: SaskuRoundReceiveResult) => void;
  readonly reject: (cause: unknown) => void;
}

/**
 * Headless prerequisite scheduling, not a transport, synchronization, or readiness boundary.
 * The caller must supply already-authenticated, session-ready direct peers from a trusted
 * transport, use one exclusive inbox for these direct inbound streams, and restore matching
 * session and round semantics before admission. Local authoring, controls, and broadcast stay
 * outside this inbox; their completed progress must explicitly wake it with processPending().
 */
export class SaskuRoundInbox {
  readonly #receiver: PersistentSaskuRoundReceiver;
  readonly #session: SessionChainRegistry;
  readonly #game: GameId;
  readonly #round: number;
  readonly #dealCount: number;
  readonly #roster: readonly IdentityPublicKey[];
  readonly #selfSeat: number;
  readonly #maxPendingEnvelopes: number;
  readonly #maxPendingBytes: number;
  readonly #queues: PendingEnvelope[][] = [[], [], [], []];
  #active: PendingEnvelope | null = null;
  #nextSeat = 0;
  #pendingEnvelopes = 0;
  #pendingBytes = 0;
  #closed = false;
  #failure: Error | null = null;
  #draining = false;
  #progressVersion = 0;
  #idle: Promise<void> = Promise.resolve();
  #resolveIdle: (() => void) | null = null;
  #cancelIdleWait: (() => void) | null = null;

  constructor(options: SaskuRoundInboxOptions) {
    options = Object.freeze({ ...options });
    if (typeof options !== "object" || options === null ||
        !(options.receiver instanceof PersistentSaskuRoundReceiver) || !(options.session instanceof SessionChainRegistry) ||
        !options.receiver.isBoundTo(options.session)) {
      throw new TypeError("A Sasku inbox requires the concrete round receiver bound to its session registry");
    }
    this.#roster = Array.from(options.session.roster, parseIdentityPublicKey);
    const self = parseIdentityPublicKey(options.self);
    this.#selfSeat = this.#roster.findIndex((identity) => bytesEqual(identity, self));
    if (this.#roster.length !== 4 || this.#selfSeat === -1) {
      throw new TypeError("A Sasku inbox requires four seats including the local identity");
    }
    this.#maxPendingEnvelopes = positiveInteger(options.maxPendingEnvelopes ?? DEFAULT_MAX_PENDING_SASKU_INBOX_ENVELOPES);
    this.#maxPendingBytes = positiveInteger(options.maxPendingBytes ?? DEFAULT_MAX_PENDING_SASKU_INBOX_BYTES);
    this.#receiver = options.receiver;
    this.#session = options.session;
    this.#game = parseGameId(options.session.gameId);
    this.#round = options.receiver.round;
    this.#dealCount = options.receiver.dealCount;
  }

  get pendingEnvelopes(): number { return this.#pendingEnvelopes; }
  get pendingBytes(): number { return this.#pendingBytes; }
  get closed(): boolean { return this.#closed; }
  get failure(): Error | null { return this.#failure; }

  /** remote must come from trusted transport authentication/readiness, never from this payload. No relays. */
  receive(remote: IdentityPublicKey, payload: Uint8Array): Promise<SaskuRoundReceiveResult> {
    let reservedBytes: number | null = null;
    try {
      if (this.#stopped()) { throw this.#failure ?? new SaskuRoundInboxError("closed"); }
      if (!(payload instanceof Uint8Array) || payload.constructor !== Uint8Array) {
        throw new SaskuRoundInboxError("invalid_envelope");
      }
      const size = typedArrayByteLength.call(payload) as number;
      if (!Number.isSafeInteger(size) || size < 1 || size > MAX_ROUND_REVEAL_ENVELOPE_BYTES) {
        throw new SaskuRoundInboxError("invalid_envelope");
      }
      this.#reserve(size);
      reservedBytes = size;
      // Charge both active and future work before any copying, signature checks, or body codecs.
      let peer: IdentityPublicKey;
      try { peer = parseIdentityPublicKey(remote); }
      catch (cause) { throw new SaskuRoundInboxError("wrong_peer", { cause }); }
      const seat = this.#roster.findIndex((identity) => bytesEqual(identity, peer));
      if (seat === -1 || seat === this.#selfSeat) { throw new SaskuRoundInboxError("wrong_peer"); }
      const bytes = new Uint8Array(size);
      let received: ReturnType<typeof decodeAndVerifyEnvelope>;
      try {
        bytes.set(payload);
        received = decodeAndVerifyEnvelope(bytes);
      } catch (cause) { throw new SaskuRoundInboxError("invalid_envelope", { cause }); }
      const envelope = received.envelope;
      if (!bytesEqual(envelope.from, peer)) { throw new SaskuRoundInboxError("wrong_peer"); }
      if (!bytesEqual(envelope.game, this.#game)) { throw new SaskuRoundInboxError("wrong_game"); }
      if (envelope.round !== this.#round) { throw new SaskuRoundInboxError("wrong_round"); }
      const type = envelope.type;
      if (type !== "SHARES" && type !== "ACTION" && type !== "AUDIT_DISCLOSE") {
        throw new SaskuRoundInboxError("wrong_type");
      }
      const stage = type === "SHARES" ? 0 : type === "ACTION" ? 1 : 2;
      let index = 0;
      if (type === "AUDIT_DISCLOSE") {
        if (envelope.phase !== `round.${this.#round}.audit`) { throw new SaskuRoundInboxError("wrong_phase"); }
      } else {
        const prefix = `round.${this.#round}.${type === "SHARES" ? "deal" : "play"}.`;
        index = Number(envelope.phase.slice(prefix.length));
        const limit = type === "SHARES" ? this.#dealCount : MAX_SASKU_HAND_ACTIONS;
        if (!Number.isSafeInteger(index) || index < 0 || index >= limit || envelope.phase !== `${prefix}${index}`) {
          throw new SaskuRoundInboxError("wrong_phase");
        }
      }
      try {
        // Syntax only: do not verify share equations or open any card before eligibility.
        if (type === "SHARES") decodeSharesBody(envelope.body);
        else if (type === "ACTION") decodeActionBody(envelope.body);
        else if (decodeAuditDiscloseBody(envelope.body).items.length !== 0) {
          throw new Error("Completed Sasku audit contributions must have no items");
        }
      } catch (cause) { throw new SaskuRoundInboxError("invalid_envelope", { cause }); }
      if (this.#stopped()) { throw this.#failure ?? new SaskuRoundInboxError("closed"); }
      const seq = envelope.seq;
      const queue = this.#queues[seat]!;
      const existing = this.#active?.seat === seat && this.#active.seq === seq
        ? this.#active : queue.find((job) => job.seq === seq);
      if (existing !== undefined && existing !== null && !bytesEqual(existing.bytes, bytes)) {
        throw new SaskuRoundInboxError("conflicting_pending");
      }
      const pending = new Promise<SaskuRoundReceiveResult>((resolve, reject) => {
        const job: PendingEnvelope = { bytes, seat, seq, stage, index, resolve, reject };
        const before = queue.findIndex((queued) => queued.seq > seq);
        // Equal-sequence duplicates each retain their own budget and promise, in admission order.
        queue.splice(before === -1 ? queue.length : before, 0, job);
      });
      reservedBytes = null;
      this.#startDrain();
      return pending;
    } catch (cause) {
      if (reservedBytes !== null) this.#release(reservedBytes);
      return Promise.reject(cause);
    }
  }

  /** Explicit wake after external local authoring or durable housekeeping changes prerequisites. */
  processPending(): Promise<void> {
    this.#progressVersion += 1;
    this.#startDrain();
    return this.#idle;
  }

  /** Drain quiescence only: may resolve with deferred envelopes still pending. Not readiness or future completion. */
  whenIdle(): Promise<void> { return this.#idle; }

  /** Cancels unsubmitted work, not an active receipt or the receiver, session, or transport. */
  close(): void {
    this.#closed = true;
    this.#rejectQueued(this.#failure ?? new SaskuRoundInboxError("closed"));
    this.#cancelIdleWait?.();
  }

  #startDrain(): void {
    if (this.#draining) return;
    this.#draining = true;
    this.#idle = new Promise<void>((resolve) => { this.#resolveIdle = resolve; });
    void this.#drain();
  }

  async #drain(): Promise<void> {
    try {
      while (!this.#stopped() && this.#pendingEnvelopes !== 0) {
        const progressAtStart = this.#progressVersion;
        // Only this wait is cancellable. No cancellation reaches the receiver's actual writes.
        await new Promise<void>((resolve, reject) => {
          this.#cancelIdleWait = resolve;
          void this.#receiver.whenIdle().then(resolve, reject);
        });
        this.#cancelIdleWait = null;
        if (this.#stopped()) break;
        if (this.#receiver.pendingEnvelopes !== 0) continue;

        const snapshot = this.#receiver.snapshot;
        const heads = this.#headVersion();
        const stage = snapshot.audit !== null ? 2 : snapshot.ledger.deal === null ? 1 : 0;
        const index = stage === 2 ? 0 : stage === 0 ? snapshot.ledger.dealIndex : snapshot.ledger.actionIndex;
        const pendingBeforeSelection = this.#pendingEnvelopes;
        let selected: PendingEnvelope | undefined;
        let reason: "broken_prev" | "equivocation" | null = null;
        for (let offset = 0; offset < 4; offset += 1) {
          const head = this.#queues[(this.#nextSeat + offset) % 4]![0];
          if (head === undefined) continue;
          const chain = this.#session.classify(decodeAndVerifyEnvelope(head.bytes));
          if (chain.status === "rejected") {
            if (chain.reason === "gap") continue;
            if (chain.reason !== "broken_prev" && chain.reason !== "equivocation") {
              throw new Error("Chain classification contradicts the admitted round scope");
            }
            reason = chain.reason;
          } else {
            if (chain.status !== "accepted" && chain.status !== "duplicate") {
              throw new Error("Invalid chain classification status");
            }
            if (head.stage > stage || (head.stage === stage && head.index > index)) continue;
          }
          selected = head;
          break;
        }
        if (selected === undefined) {
          // A wake during classification must observe newly committed prerequisites, not spin on a redundant wake.
          const observedVersion = this.#progressVersion;
          const changed = observedVersion !== progressAtStart && (this.#receiver.pendingEnvelopes !== 0 ||
            this.#receiver.snapshot !== snapshot || this.#headVersion() !== heads);
          // Source callbacks above may admit another head or issue a newer wake themselves.
          if (this.#pendingEnvelopes !== pendingBeforeSelection || changed || this.#progressVersion !== observedVersion) continue;
          break;
        }
        const argument = reason === null ? decodeAndVerifyEnvelope(selected.bytes) : null;
        if (this.#stopped()) break;
        // Local work admitted since the idle barrier requires fresh eligibility, not this snapshot.
        if (this.#receiver.pendingEnvelopes !== 0 || this.#queues[selected.seat]![0] !== selected) continue;
        this.#queues[selected.seat]!.shift();
        this.#nextSeat = (selected.seat + 1) % 4;
        this.#active = selected;
        try {
          const result: SaskuRoundReceiveResult = argument === null
            ? Object.freeze({ status: "rejected", reason: reason!, received: decodeAndVerifyEnvelope(selected.bytes) })
            : this.#validateReceipt(selected, await this.#receiver.receive(argument));
          this.#stopped();
          if (this.#failure !== null) throw this.#failure;
          selected.resolve(result);
        } catch (cause) {
          this.#stopped();
          selected.reject(this.#failure ?? cause);
        } finally {
          this.#release(selected.bytes.length);
          this.#active = null;
        }
      }
    } catch (cause) {
      this.#fail(this.#receiver.failure ?? new SaskuRoundInboxError("invalid_receipt", { cause }));
    } finally {
      this.#cancelIdleWait = null;
      this.#draining = false;
      const resolve = this.#resolveIdle;
      this.#resolveIdle = null;
      resolve?.();
    }
  }

  #validateReceipt(job: PendingEnvelope, receipt: SaskuRoundReceiveResult): SaskuRoundReceiveResult {
    try {
      const returnedBytes = copyExactBytes(receipt.received.canonicalBytes, job.bytes.length);
      if (!bytesEqual(returnedBytes, job.bytes)) {
        throw new Error("Round receipt does not match the submitted artifact");
      }
      const received = decodeAndVerifyEnvelope(job.bytes);
      const status = receipt.status;
      if (status === "rejected") {
        const reason = receipt.reason;
        if (reason !== "gap" && reason !== "broken_prev" && reason !== "equivocation" && reason !== "durable_conflict") {
          throw new Error("Invalid round rejection reason");
        }
        return Object.freeze({ status, reason, received });
      }
      if (status !== "accepted" && status !== "duplicate") { throw new Error("Invalid round receipt status"); }
      const chainStatus = receipt.chainStatus;
      const persistenceStatus = receipt.persistenceStatus;
      const snapshot = receipt.snapshot;
      if ((chainStatus !== "accepted" && chainStatus !== "duplicate") ||
          (persistenceStatus !== "stored" && persistenceStatus !== "duplicate") ||
          typeof snapshot !== "object" || snapshot === null) {
        throw new Error("Invalid round success receipt");
      }
      const recorded = this.#session.readRange(parseIdentityPublicKey(this.#roster[job.seat]!), job.seq, job.seq);
      if (this.#session.classify(decodeAndVerifyEnvelope(job.bytes)).status !== "duplicate" ||
          recorded.status !== "complete" || recorded.envelopes.length !== 1 ||
          !bytesEqual(copyExactBytes(recorded.envelopes[0]!.canonicalBytes, job.bytes.length), job.bytes)) {
        throw new Error("Round receipt is not reflected in its bound session registry");
      }
      return Object.freeze({ status, chainStatus, persistenceStatus, received, snapshot });
    } catch (cause) { throw this.#fail(new SaskuRoundInboxError("invalid_receipt", { cause })); }
  }

  #stopped(): boolean {
    const failure = this.#receiver.failure;
    if (failure !== null) this.#fail(failure);
    if (this.#receiver.closed) this.close();
    return this.#closed || this.#failure !== null;
  }

  #headVersion(): string {
    return this.#session.heads().map(({ from, seq, hash }) => `${bytesToHex(from)}:${seq}:${bytesToHex(hash)}`).join("|");
  }

  #reserve(bytes: number): void {
    if (this.#pendingEnvelopes >= this.#maxPendingEnvelopes || bytes > this.#maxPendingBytes - this.#pendingBytes) {
      throw new SaskuRoundInboxError("queue_limit");
    }
    this.#pendingEnvelopes += 1;
    this.#pendingBytes += bytes;
  }

  #release(bytes: number): void {
    this.#pendingEnvelopes -= 1;
    this.#pendingBytes -= bytes;
  }

  #rejectQueued(cause: Error): void {
    for (const queue of this.#queues) {
      for (const job of queue.splice(0)) {
        this.#release(job.bytes.length);
        job.reject(cause);
      }
    }
  }

  #fail(cause: Error): Error {
    this.#failure ??= cause;
    this.#rejectQueued(this.#failure);
    this.#cancelIdleWait?.();
    return this.#failure;
  }
}

function positiveInteger(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) { throw new RangeError("Sasku inbox limits must be positive safe integers"); }
  return value;
}

function copyExactBytes(value: unknown, length: number): Uint8Array {
  // Dependency-owned views can shadow length/byteLength; read internal typed-array sizes before bounded copying.
  if (!(value instanceof Uint8Array) || value.constructor !== Uint8Array ||
      typedArrayLength.call(value) !== length || typedArrayByteLength.call(value) !== length) {
    throw new Error("Invalid round receipt byte view");
  }
  const bytes = new Uint8Array(length);
  bytes.set(value);
  return bytes;
}
