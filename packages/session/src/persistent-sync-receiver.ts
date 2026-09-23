import { bytesEqual } from "@p2pcards/crypto";
import {
  decodeAndVerifyEnvelope,
  decodeSyncRequestBody,
  decodeSyncResponseBody,
  encodeSyncRequestBody,
  expectArray,
  expectExactMap,
  type EnvelopeArtifact,
  type SyncRequestBody,
} from "@p2pcards/protocol";

import { SessionChainRegistry } from "./chain-registry";
import { PersistentSessionReceiver } from "./persistent-receiver";
import {
  DEFAULT_MAX_SYNC_RANGE_ENVELOPES,
  DEFAULT_MAX_SYNC_RESPONSE_BYTES,
  preflightSyncResponse,
} from "./sync";

export const DEFAULT_MAX_PENDING_SYNC_RESPONSES = 8;
export const DEFAULT_MAX_PENDING_SYNC_RESPONSE_BYTES = 16 * 1024 * 1024;

export type SyncHistoryReceiveResult =
  | { readonly status: "accepted" | "duplicate" | "failed"; readonly received: EnvelopeArtifact }
  | { readonly status: "rejected"; readonly reason: string; readonly received: EnvelopeArtifact };

export interface SyncHistoryReceiver {
  /** Validate semantics, durably receive, then commit semantic state; never execute historical control effects. */
  receive(candidate: EnvelopeArtifact): Promise<SyncHistoryReceiveResult>;
}

/** The AbortSignal surface used by this platform-independent package. */
export interface SyncCancellationSignal {
  readonly aborted: boolean;
  addEventListener(type: "abort", listener: () => void, options?: { readonly once?: boolean }): void;
  removeEventListener(type: "abort", listener: () => void): void;
}

export interface PersistentSyncReceiverOptions {
  readonly maxEnvelopes?: number;
  readonly maxResponseBytes?: number;
  readonly maxPendingResponses?: number;
  readonly maxPendingBytes?: number;
}

export interface SyncReceiptProgress {
  readonly outerStatus: "accepted" | "duplicate" | null;
  /** Confirmed durable receipt statuses, in requested sequence order; not a session completion signal. */
  readonly receipts: readonly ("accepted" | "duplicate" | "failed")[];
}

type Stage = "outer" | "preflight" | "history";

export type PersistentSyncReceiveResult = SyncReceiptProgress & (
  | { readonly status: "range_received" }
  | { readonly status: "cancelled" }
  | { readonly status: "stopped"; readonly stage: Stage; readonly index: number | null; readonly reason: string }
  | { readonly status: "failed"; readonly stage: Stage; readonly index: number | null; readonly error: Error }
);

interface PendingResponse {
  readonly bytes: Uint8Array;
  readonly request: SyncRequestBody;
  readonly signal: SyncCancellationSignal | undefined;
  readonly onAbort: () => void;
  readonly resolve: (result: PersistentSyncReceiveResult) => void;
}

export class PersistentSyncReceiver {
  readonly #registry: SessionChainRegistry;
  readonly #controls: PersistentSessionReceiver;
  readonly #history: SyncHistoryReceiver;
  readonly #maxEnvelopes: number;
  readonly #maxResponseBytes: number;
  readonly #maxPendingResponses: number;
  readonly #maxPendingBytes: number;
  readonly #queue: PendingResponse[] = [];
  #active: PendingResponse | null = null;
  #pendingBytes = 0;

  constructor(
    registry: SessionChainRegistry,
    controls: PersistentSessionReceiver,
    history: SyncHistoryReceiver,
    options: PersistentSyncReceiverOptions = {},
  ) {
    if (!(registry instanceof SessionChainRegistry) ||
        !(controls instanceof PersistentSessionReceiver) || !controls.isBoundTo(registry)) {
      throw new TypeError("Synchronization requires the durable receiver bound to its registry");
    }
    if (typeof history !== "object" || history === null || typeof history.receive !== "function" ||
        history instanceof PersistentSessionReceiver) {
      throw new TypeError("Synchronization requires an explicit semantic-capable durable history receiver");
    }
    this.#registry = registry;
    this.#controls = controls;
    this.#history = history;
    this.#maxEnvelopes = positiveInteger(options.maxEnvelopes ?? DEFAULT_MAX_SYNC_RANGE_ENVELOPES);
    this.#maxResponseBytes = positiveInteger(options.maxResponseBytes ?? DEFAULT_MAX_SYNC_RESPONSE_BYTES);
    this.#maxPendingResponses = positiveInteger(options.maxPendingResponses ?? DEFAULT_MAX_PENDING_SYNC_RESPONSES);
    this.#maxPendingBytes = positiveInteger(options.maxPendingBytes ?? DEFAULT_MAX_PENDING_SYNC_RESPONSE_BYTES);
  }

  receiveResponse(
    candidate: EnvelopeArtifact,
    request: SyncRequestBody,
    options: { readonly signal?: SyncCancellationSignal } = {},
  ): Promise<PersistentSyncReceiveResult> {
    try {
      const signal = options.signal;
      if (signal !== undefined && (typeof signal.aborted !== "boolean" ||
          typeof signal.addEventListener !== "function" || typeof signal.removeEventListener !== "function")) {
        throw new TypeError("Synchronization cancellation requires an AbortSignal");
      }
      if (signal?.aborted) {
        return Promise.resolve(cancelled());
      }
      if (this.#queue.length + (this.#active === null ? 0 : 1) >= this.#maxPendingResponses) {
        throw new RangeError("Pending synchronization response limit exceeded");
      }
      const normalized = decodeSyncRequestBody(encodeSyncRequestBody(request));
      if (normalized.toSeq - normalized.fromSeq >= this.#maxEnvelopes) {
        throw new RangeError("Requested synchronization range exceeds the envelope limit");
      }
      const bytes = candidate.canonicalBytes;
      if (!(bytes instanceof Uint8Array) || bytes.constructor !== Uint8Array) {
        throw new TypeError("Synchronization response must contain canonical envelope bytes");
      }
      if (bytes.length > this.#maxResponseBytes || bytes.length > this.#maxPendingBytes - this.#pendingBytes) {
        throw new RangeError("Synchronization response byte limit exceeded");
      }
      let resolve!: (result: PersistentSyncReceiveResult) => void;
      const promise = new Promise<PersistentSyncReceiveResult>((complete) => { resolve = complete; });
      const job: PendingResponse = {
        bytes: bytes.slice(),
        request: normalized,
        signal,
        resolve,
        onAbort: () => {
          const index = this.#queue.indexOf(job);
          if (index !== -1) {
            this.#queue.splice(index, 1);
            this.#release(job);
            job.resolve(cancelled());
          }
        },
      };
      this.#pendingBytes += job.bytes.length;
      this.#queue.push(job);
      try {
        signal?.addEventListener("abort", job.onAbort, { once: true });
      } catch (cause) {
        const index = this.#queue.indexOf(job);
        if (index !== -1) {
          this.#queue.splice(index, 1);
          this.#release(job);
        }
        throw cause;
      }
      if (signal?.aborted) {
        job.onAbort();
      }
      this.#drain();
      return promise;
    } catch (cause) {
      return Promise.reject(cause);
    }
  }

  #drain(): void {
    if (this.#active !== null) {
      return;
    }
    const job = this.#queue.shift();
    if (job === undefined) {
      return;
    }
    this.#active = job;
    void Promise.resolve().then(() => this.#receive(job)).then((result) => {
      this.#release(job);
      this.#active = null;
      job.resolve(result);
      this.#drain();
    });
  }

  #release(job: PendingResponse): void {
    this.#pendingBytes -= job.bytes.length;
    try {
      job.signal?.removeEventListener("abort", job.onAbort);
    } catch {
      // A broken external signal must not retain the receiver's queue lock.
    }
  }

  async #receive(job: PendingResponse): Promise<PersistentSyncReceiveResult> {
    let outerStatus: SyncReceiptProgress["outerStatus"] = null;
    const receipts: Array<"accepted" | "duplicate" | "failed"> = [];
    let stage: Stage = "outer";
    let index: number | null = null;
    const progress = (): SyncReceiptProgress => ({ outerStatus, receipts: Object.freeze([...receipts]) });
    const stop = (reason: string): PersistentSyncReceiveResult =>
      Object.freeze({ status: "stopped", stage, index, reason, ...progress() });
    const wasCancelled = (): PersistentSyncReceiveResult =>
      Object.freeze({ status: "cancelled", ...progress() });
    try {
      if (job.signal?.aborted) {
        return wasCancelled();
      }
      const outer = decodeAndVerifyEnvelope(job.bytes);
      if (outer.envelope.type !== "SYNC_RESP") {
        return stop("wrong_type");
      }
      const classification = this.#registry.classify(outer);
      if (classification.status === "rejected") {
        return stop(classification.reason);
      }

      // The outer chain must already be admissible; its nested history cannot repair its own gap.
      stage = "preflight";
      const body = expectExactMap(outer.envelope.body, ["envelopes"], "SYNC_RESP.body");
      const values = expectArray(body["envelopes"], "SYNC_RESP.body.envelopes");
      if (values.length > this.#maxEnvelopes) {
        return stop("limit_exceeded");
      }
      const preflight = preflightSyncResponse(
        this.#registry,
        job.request,
        decodeSyncResponseBody(outer.envelope.body),
        { maxEnvelopes: this.#maxEnvelopes, maxBytes: this.#maxResponseBytes },
      );
      if (preflight.status === "rejected") {
        index = "index" in preflight ? preflight.index : null;
        return stop(preflight.reason);
      }
      if (job.signal?.aborted) {
        return wasCancelled();
      }

      stage = "outer";
      index = null;
      const control = await this.#controls.receive(outer);
      if (control.status === "rejected") {
        return stop(control.reason);
      }
      this.#requireCommitted(outer, control.received);
      outerStatus = control.status;

      stage = "history";
      for (const [position, artifact] of preflight.response.envelopes.entries()) {
        index = position;
        if (job.signal?.aborted) {
          return wasCancelled();
        }
        const chain = this.#registry.classify(artifact);
        if (chain.status === "rejected") {
          return stop(chain.reason);
        }
        const receipt = await this.#history.receive(decodeAndVerifyEnvelope(artifact.canonicalBytes));
        const returned = decodeAndVerifyEnvelope(receipt.received.canonicalBytes);
        if (!bytesEqual(returned.canonicalBytes, artifact.canonicalBytes)) {
          throw new Error("History receiver returned a receipt for a different artifact");
        }
        if (receipt.status === "rejected") {
          if (typeof receipt.reason !== "string") {
            throw new TypeError("History receiver returned an invalid rejection");
          }
          return stop(receipt.reason);
        }
        if (receipt.status !== "accepted" && receipt.status !== "duplicate" && receipt.status !== "failed") {
          throw new TypeError("History receiver returned an invalid receipt status");
        }
        this.#requireCommitted(artifact, returned);
        receipts.push(receipt.status);
        if (receipt.status === "failed") {
          return stop("terminal_history_failure");
        }
      }
      if (job.signal?.aborted) {
        return wasCancelled();
      }
      return Object.freeze({ status: "range_received", ...progress() });
    } catch (cause) {
      return Object.freeze({
        status: "failed", stage, index, ...progress(),
        error: cause instanceof Error ? cause : new Error("Synchronization receipt failed", { cause }),
      });
    }
  }

  #requireCommitted(expected: EnvelopeArtifact, returned: EnvelopeArtifact): void {
    const snapshot = decodeAndVerifyEnvelope(returned.canonicalBytes);
    if (!bytesEqual(expected.canonicalBytes, snapshot.canonicalBytes) ||
        this.#registry.classify(expected).status !== "duplicate") {
      throw new Error("Durable receiver did not commit the exact artifact to the shared registry");
    }
  }
}

function cancelled(): PersistentSyncReceiveResult {
  return Object.freeze({ status: "cancelled", outerStatus: null, receipts: Object.freeze([]) });
}

function positiveInteger(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError("Synchronization limits must be positive safe integers");
  }
  return value;
}
