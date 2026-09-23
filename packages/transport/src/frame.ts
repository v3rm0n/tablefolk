import {
  decodeCanonical,
  encodeCanonical,
  type CanonicalCbor,
  type CborValue,
} from "@p2pcards/encoding";
import {
  expectByteString,
  expectExactMap,
  expectUnsignedInteger,
  ProtocolSchemaError,
} from "@p2pcards/protocol";

export const MAX_FRAME_PAYLOAD_BYTES = 16 * 1024;
export const MAX_ENCODED_FRAME_BYTES = MAX_FRAME_PAYLOAD_BYTES + 128;
export const MAX_FRAME_COUNT = 0xffff;
export const MAX_FRAME_ID = 0xffff_ffff;
export const INCOMPLETE_FRAME_TIMEOUT_MS = 30_000;
export const DEFAULT_MAX_REASSEMBLED_BYTES = 8 * 1024 * 1024;
export const DEFAULT_MAX_PENDING_BYTES = 16 * 1024 * 1024;
export const DEFAULT_MAX_PENDING_GROUPS = 64;

export interface DataFrame {
  readonly id: number;
  readonly index: number;
  readonly count: number;
  readonly bytes: Uint8Array;
}

export interface FrameReassemblerOptions {
  readonly timeoutMs?: number;
  readonly maxMessageBytes?: number;
  readonly maxPendingBytes?: number;
  readonly maxPendingGroups?: number;
  readonly maxFramesPerMessage?: number;
  readonly scheduleExpiry?: boolean;
  readonly now?: () => number;
}

export type FrameReassemblyResult =
  | {
      readonly status: "incomplete" | "duplicate";
      readonly id: number;
      readonly received: number;
      readonly count: number;
    }
  | {
      readonly status: "complete";
      readonly id: number;
      readonly payload: Uint8Array;
    }
  | {
      readonly status: "rejected";
      readonly id: number;
      readonly reason:
        | "capacity_exceeded"
        | "chunk_conflict"
        | "count_mismatch"
        | "frame_count_exceeded"
        | "message_too_large";
    };

interface PendingFrameGroup {
  readonly id: number;
  readonly count: number;
  readonly createdAt: number;
  readonly chunks: Map<number, Uint8Array>;
  byteLength: number;
}

const FRAME_KEYS = ["id", "index", "count", "bytes"] as const;

export function encodeDataFrame(frame: DataFrame): CanonicalCbor {
  const normalized = normalizeFrame(frame);
  return encodeCanonical({
    id: normalized.id,
    index: normalized.index,
    count: normalized.count,
    bytes: normalized.bytes,
  });
}

export function decodeDataFrame(encoded: Uint8Array): DataFrame {
  requireEncodedFrame(encoded);
  const value = decodeCanonical(encoded);
  const frame = expectExactMap(value, FRAME_KEYS, "Frame");
  return normalizeFrame({
    id: expectUnsignedInteger(frame["id"], "Frame.id", MAX_FRAME_ID),
    index: expectUnsignedInteger(frame["index"], "Frame.index", MAX_FRAME_COUNT),
    count: expectUnsignedInteger(frame["count"], "Frame.count", MAX_FRAME_COUNT),
    bytes: expectByteString(frame["bytes"], "Frame.bytes"),
  });
}

export function splitDataFrames(payload: Uint8Array, id: number): readonly DataFrame[] {
  requireBytes(payload, "Frame payload");
  const normalizedId = expectUnsignedInteger(id, "Frame.id", MAX_FRAME_ID);
  const count = Math.max(1, Math.ceil(payload.length / MAX_FRAME_PAYLOAD_BYTES));
  if (count > MAX_FRAME_COUNT) {
    throw new RangeError(`Frame payload requires more than ${MAX_FRAME_COUNT} chunks`);
  }

  const frames = Array.from({ length: count }, (_, index) =>
    Object.freeze({
      id: normalizedId,
      index,
      count,
      bytes: payload.slice(
        index * MAX_FRAME_PAYLOAD_BYTES,
        Math.min(payload.length, (index + 1) * MAX_FRAME_PAYLOAD_BYTES),
      ),
    }),
  );
  return Object.freeze(frames);
}

export class FrameReassembler {
  readonly #timeoutMs: number;
  readonly #maxMessageBytes: number;
  readonly #maxPendingBytes: number;
  readonly #maxPendingGroups: number;
  readonly #maxFramesPerMessage: number;
  readonly #scheduleExpiryEnabled: boolean;
  readonly #now: () => number;
  readonly #groups = new Map<number, PendingFrameGroup>();
  #pendingBytes = 0;
  #expiryTimer: ReturnType<typeof globalThis.setTimeout> | null = null;

  constructor(options: FrameReassemblerOptions = {}) {
    this.#timeoutMs = positiveInteger(
      options.timeoutMs ?? INCOMPLETE_FRAME_TIMEOUT_MS,
      "Frame timeout",
    );
    this.#maxMessageBytes = positiveInteger(
      options.maxMessageBytes ?? DEFAULT_MAX_REASSEMBLED_BYTES,
      "Maximum reassembled message bytes",
    );
    this.#maxPendingBytes = positiveInteger(
      options.maxPendingBytes ?? DEFAULT_MAX_PENDING_BYTES,
      "Maximum pending frame bytes",
    );
    this.#maxPendingGroups = positiveInteger(
      options.maxPendingGroups ?? DEFAULT_MAX_PENDING_GROUPS,
      "Maximum pending frame groups",
    );
    this.#maxFramesPerMessage = positiveInteger(
      options.maxFramesPerMessage ??
        Math.ceil(this.#maxMessageBytes / MAX_FRAME_PAYLOAD_BYTES),
      "Maximum frames per message",
    );
    this.#scheduleExpiryEnabled = options.scheduleExpiry ?? false;
    if (typeof this.#scheduleExpiryEnabled !== "boolean") {
      throw new TypeError("Scheduled frame expiry must be a boolean");
    }
    this.#now = options.now ?? Date.now;
    if (typeof this.#now !== "function") {
      throw new TypeError("Frame clock must be a function");
    }
  }

  get pendingGroups(): number {
    return this.#groups.size;
  }

  get pendingBytes(): number {
    return this.#pendingBytes;
  }

  get nextExpiryAt(): number | null {
    let next: number | null = null;
    for (const group of this.#groups.values()) {
      const expiresAt = group.createdAt + this.#timeoutMs;
      if (next === null || expiresAt < next) {
        next = expiresAt;
      }
    }
    return next;
  }

  acceptEncoded(encoded: Uint8Array): FrameReassemblyResult {
    return this.accept(decodeDataFrame(encoded));
  }

  accept(candidate: DataFrame): FrameReassemblyResult {
    const frame = normalizeFrame(candidate);
    const now = this.#readTime();
    this.expire(now);
    if (frame.count > this.#maxFramesPerMessage) {
      this.#delete(frame.id);
      return rejected(frame.id, "frame_count_exceeded");
    }

    let group = this.#groups.get(frame.id);
    if (group === undefined) {
      if (this.#groups.size >= this.#maxPendingGroups) {
        return rejected(frame.id, "capacity_exceeded");
      }
      group = {
        id: frame.id,
        count: frame.count,
        createdAt: now,
        chunks: new Map(),
        byteLength: 0,
      };
      this.#groups.set(frame.id, group);
    } else if (group.count !== frame.count) {
      this.#delete(frame.id);
      return rejected(frame.id, "count_mismatch");
    }

    const existing = group.chunks.get(frame.index);
    if (existing !== undefined) {
      if (!equalBytes(existing, frame.bytes)) {
        this.#delete(frame.id);
        return rejected(frame.id, "chunk_conflict");
      }
      return Object.freeze({
        status: "duplicate",
        id: frame.id,
        received: group.chunks.size,
        count: group.count,
      });
    }
    if (group.byteLength + frame.bytes.length > this.#maxMessageBytes) {
      this.#delete(frame.id);
      return rejected(frame.id, "message_too_large");
    }
    if (this.#pendingBytes + frame.bytes.length > this.#maxPendingBytes) {
      if (group.chunks.size === 0) {
        this.#delete(frame.id);
      }
      return rejected(frame.id, "capacity_exceeded");
    }

    const chunk = frame.bytes.slice();
    group.chunks.set(frame.index, chunk);
    group.byteLength += chunk.length;
    this.#pendingBytes += chunk.length;
    if (group.chunks.size !== group.count) {
      this.#scheduleExpiry();
      return Object.freeze({
        status: "incomplete",
        id: frame.id,
        received: group.chunks.size,
        count: group.count,
      });
    }

    const payload = new Uint8Array(group.byteLength);
    let offset = 0;
    for (let index = 0; index < group.count; index += 1) {
      const part = group.chunks.get(index);
      if (part === undefined) {
        throw new Error("Complete frame group is missing a chunk");
      }
      payload.set(part, offset);
      offset += part.length;
    }
    this.#delete(frame.id);
    return Object.freeze({ status: "complete", id: frame.id, payload });
  }

  expire(now = this.#readTime()): readonly number[] {
    requireTime(now);
    const expired: number[] = [];
    for (const [id, group] of this.#groups) {
      if (now - group.createdAt >= this.#timeoutMs) {
        expired.push(id);
        this.#delete(id);
      }
    }
    expired.sort((left, right) => left - right);
    return Object.freeze(expired);
  }

  clear(): void {
    if (this.#expiryTimer !== null) {
      globalThis.clearTimeout(this.#expiryTimer);
      this.#expiryTimer = null;
    }
    this.#groups.clear();
    this.#pendingBytes = 0;
  }

  #delete(id: number): void {
    const group = this.#groups.get(id);
    if (group === undefined) {
      return;
    }
    this.#pendingBytes -= group.byteLength;
    this.#groups.delete(id);
    if (this.#groups.size === 0 && this.#expiryTimer !== null) {
      globalThis.clearTimeout(this.#expiryTimer);
      this.#expiryTimer = null;
    }
  }

  #readTime(): number {
    const now = this.#now();
    requireTime(now);
    return now;
  }

  #scheduleExpiry(): void {
    if (
      !this.#scheduleExpiryEnabled ||
      this.#expiryTimer !== null ||
      this.#groups.size === 0
    ) {
      return;
    }
    let expiryAt = Number.POSITIVE_INFINITY;
    for (const group of this.#groups.values()) {
      expiryAt = Math.min(expiryAt, group.createdAt + this.#timeoutMs);
    }
    const delay = Math.max(0, expiryAt - this.#readTime());
    this.#expiryTimer = globalThis.setTimeout(() => {
      this.#expiryTimer = null;
      this.expire();
      this.#scheduleExpiry();
    }, delay);
  }
}

function normalizeFrame(frame: DataFrame): DataFrame {
  if (typeof frame !== "object" || frame === null) {
    throw new ProtocolSchemaError("Frame", "must be a map");
  }
  const id = expectUnsignedInteger(frame.id as CborValue, "Frame.id", MAX_FRAME_ID);
  const index = expectUnsignedInteger(
    frame.index as CborValue,
    "Frame.index",
    MAX_FRAME_COUNT,
  );
  const count = expectUnsignedInteger(
    frame.count as CborValue,
    "Frame.count",
    MAX_FRAME_COUNT,
  );
  if (count === 0) {
    throw new ProtocolSchemaError("Frame.count", "must be at least one");
  }
  if (index >= count) {
    throw new ProtocolSchemaError("Frame.index", "must be less than count");
  }
  const bytes = expectByteString(frame.bytes as CborValue, "Frame.bytes");
  if (bytes.length > MAX_FRAME_PAYLOAD_BYTES) {
    throw new ProtocolSchemaError(
      "Frame.bytes",
      `must contain at most ${MAX_FRAME_PAYLOAD_BYTES} bytes`,
    );
  }
  if (count > 1 && bytes.length === 0) {
    throw new ProtocolSchemaError("Frame.bytes", "must not be empty in a multi-frame message");
  }
  return Object.freeze({ id, index, count, bytes: bytes.slice() });
}

function requireBytes(value: Uint8Array, label: string): void {
  if (!(value instanceof Uint8Array) || value.constructor !== Uint8Array) {
    throw new TypeError(`${label} must be a Uint8Array`);
  }
}

function requireEncodedFrame(value: Uint8Array): void {
  requireBytes(value, "Encoded frame");
  if (value.length > MAX_ENCODED_FRAME_BYTES) {
    throw new ProtocolSchemaError(
      "Frame",
      `must encode to at most ${MAX_ENCODED_FRAME_BYTES} bytes`,
    );
  }
}

function positiveInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(`${label} must be a positive safe integer`);
  }
  return value;
}

function requireTime(value: number): void {
  if (!Number.isFinite(value) || value < 0) {
    throw new RangeError("Frame clock must return a finite non-negative time");
  }
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false;
  }
  return left.every((byte, index) => byte === right[index]);
}

function rejected(
  id: number,
  reason: Extract<FrameReassemblyResult, { readonly status: "rejected" }>['reason'],
): FrameReassemblyResult {
  return Object.freeze({ status: "rejected", id, reason });
}
