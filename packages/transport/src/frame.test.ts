import { encodeCanonical } from "@p2pcards/encoding";
import { ProtocolSchemaError } from "@p2pcards/protocol";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  decodeDataFrame,
  encodeDataFrame,
  FrameReassembler,
  INCOMPLETE_FRAME_TIMEOUT_MS,
  MAX_ENCODED_FRAME_BYTES,
  MAX_FRAME_PAYLOAD_BYTES,
  splitDataFrames,
} from "./frame";

describe("data-channel frame codec", () => {
  it("round-trips the exact deterministic CBOR map", () => {
    const encoded = encodeDataFrame({
      id: 1,
      index: 0,
      count: 1,
      bytes: new Uint8Array([1, 2]),
    });

    expect(toHex(encoded)).toBe(
      "a46269640165627974657342010265636f756e740165696e64657800",
    );
    expect(decodeDataFrame(encoded)).toEqual({
      id: 1,
      index: 0,
      count: 1,
      bytes: new Uint8Array([1, 2]),
    });
  });

  it("rejects non-canonical CBOR, extension fields, and invalid integer ranges", () => {
    const nonCanonical = new Uint8Array([
      0xa4,
      0x65,
      ...new TextEncoder().encode("index"),
      0x00,
      0x62,
      ...new TextEncoder().encode("id"),
      0x01,
      0x65,
      ...new TextEncoder().encode("count"),
      0x01,
      0x65,
      ...new TextEncoder().encode("bytes"),
      0x40,
    ]);
    expect(() => decodeDataFrame(nonCanonical)).toThrow(/canonical/i);
    expect(() =>
      decodeDataFrame(
        encodeCanonical({ id: 1, index: 0, count: 1, bytes: new Uint8Array(), extra: 1 }),
      ),
    ).toThrow(ProtocolSchemaError);
    expect(() =>
      encodeDataFrame({ id: -1, index: 0, count: 1, bytes: new Uint8Array() }),
    ).toThrow(ProtocolSchemaError);
    expect(() =>
      encodeDataFrame({ id: 1, index: 0, count: 0, bytes: new Uint8Array() }),
    ).toThrow(/at least one/);
    expect(() =>
      encodeDataFrame({ id: 1, index: 1, count: 1, bytes: new Uint8Array() }),
    ).toThrow(/less than count/);
  });

  it("enforces the 16 KiB chunk ceiling and excludes empty multi-frame chunks", () => {
    expect(() =>
      encodeDataFrame({
        id: 1,
        index: 0,
        count: 1,
        bytes: new Uint8Array(MAX_FRAME_PAYLOAD_BYTES + 1),
      }),
    ).toThrow(/at most 16384/);
    expect(() =>
      encodeDataFrame({ id: 1, index: 0, count: 2, bytes: new Uint8Array() }),
    ).toThrow(/must not be empty/);
    expect(() => decodeDataFrame(new Uint8Array(MAX_ENCODED_FRAME_BYTES + 1))).toThrow(
      /encode to at most/,
    );
  });

  it("splits empty, boundary-sized, and larger payloads without retaining aliases", () => {
    expect(splitDataFrames(new Uint8Array(), 7)).toEqual([
      { id: 7, index: 0, count: 1, bytes: new Uint8Array() },
    ]);
    expect(splitDataFrames(new Uint8Array(MAX_FRAME_PAYLOAD_BYTES), 8)).toHaveLength(1);

    const payload = Uint8Array.from(
      { length: MAX_FRAME_PAYLOAD_BYTES + 2 },
      (_, index) => index & 0xff,
    );
    const frames = splitDataFrames(payload, 9);
    const firstByte = frames[0]!.bytes[0];
    payload.fill(0xff);

    expect(frames).toHaveLength(2);
    expect(frames[0]).toMatchObject({ id: 9, index: 0, count: 2 });
    expect(frames[0]!.bytes).toHaveLength(MAX_FRAME_PAYLOAD_BYTES);
    expect(frames[0]!.bytes[0]).toBe(firstByte);
    expect(frames[1]!.bytes).toEqual(new Uint8Array([0, 1]));
  });
});

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

describe("frame reassembly", () => {
  afterEach(() => vi.useRealTimers());

  it("reassembles out-of-order encoded frames and snapshots accepted chunks", () => {
    const payload = Uint8Array.from(
      { length: MAX_FRAME_PAYLOAD_BYTES * 2 + 3 },
      (_, index) => index & 0xff,
    );
    const frames = splitDataFrames(payload, 42);
    const reassembler = new FrameReassembler();

    expect(reassembler.acceptEncoded(encodeDataFrame(frames[2]!))).toMatchObject({
      status: "incomplete",
      received: 1,
      count: 3,
    });
    const mutable = frames[0]!.bytes.slice();
    expect(reassembler.accept({ ...frames[0]!, bytes: mutable })).toMatchObject({
      status: "incomplete",
      received: 2,
    });
    mutable.fill(0xff);
    const completed = reassembler.accept(frames[1]!);

    expect(completed.status).toBe("complete");
    if (completed.status === "complete") {
      expect(completed.payload).toEqual(payload);
    }
    expect(reassembler.pendingGroups).toBe(0);
    expect(reassembler.pendingBytes).toBe(0);
  });

  it("treats byte-identical chunks as duplicates and discards conflicting groups", () => {
    const reassembler = new FrameReassembler();
    const first = { id: 4, index: 0, count: 2, bytes: new Uint8Array([1]) };

    expect(reassembler.accept(first).status).toBe("incomplete");
    expect(reassembler.accept(first)).toMatchObject({ status: "duplicate", received: 1 });
    expect(
      reassembler.accept({ ...first, bytes: new Uint8Array([2]) }),
    ).toEqual({ status: "rejected", id: 4, reason: "chunk_conflict" });
    expect(reassembler.pendingGroups).toBe(0);

    expect(reassembler.accept(first).status).toBe("incomplete");
    expect(
      reassembler.accept({ id: 4, index: 1, count: 3, bytes: new Uint8Array([2]) }),
    ).toEqual({ status: "rejected", id: 4, reason: "count_mismatch" });
    expect(reassembler.pendingBytes).toBe(0);
  });

  it("expires incomplete groups 30 seconds after their first frame", () => {
    let now = 100;
    const reassembler = new FrameReassembler({ now: () => now });
    reassembler.accept({ id: 8, index: 0, count: 3, bytes: new Uint8Array([1]) });
    expect(reassembler.nextExpiryAt).toBe(100 + INCOMPLETE_FRAME_TIMEOUT_MS);
    now += INCOMPLETE_FRAME_TIMEOUT_MS - 1;
    reassembler.accept({ id: 8, index: 1, count: 3, bytes: new Uint8Array([2]) });

    expect(reassembler.pendingGroups).toBe(1);
    now += 1;
    expect(reassembler.expire()).toEqual([8]);
    expect(reassembler.pendingBytes).toBe(0);
    expect(reassembler.nextExpiryAt).toBeNull();
  });

  it("enforces configurable message, frame-count, group, and pending-byte limits", () => {
    const reassembler = new FrameReassembler({
      maxMessageBytes: 3,
      maxPendingBytes: 2,
      maxPendingGroups: 1,
      maxFramesPerMessage: 2,
    });

    expect(
      reassembler.accept({ id: 1, index: 0, count: 3, bytes: new Uint8Array([1]) }),
    ).toEqual({ status: "rejected", id: 1, reason: "frame_count_exceeded" });
    expect(
      reassembler.accept({ id: 2, index: 0, count: 2, bytes: new Uint8Array([1, 2]) }),
    ).toMatchObject({ status: "incomplete" });
    expect(
      reassembler.accept({ id: 3, index: 0, count: 2, bytes: new Uint8Array([3]) }),
    ).toEqual({ status: "rejected", id: 3, reason: "capacity_exceeded" });
    expect(
      reassembler.accept({ id: 2, index: 1, count: 2, bytes: new Uint8Array([3, 4]) }),
    ).toEqual({ status: "rejected", id: 2, reason: "message_too_large" });
    expect(reassembler.pendingGroups).toBe(0);

    const pendingLimited = new FrameReassembler({
      maxMessageBytes: 4,
      maxPendingBytes: 2,
      maxPendingGroups: 2,
      maxFramesPerMessage: 2,
    });
    pendingLimited.accept({ id: 1, index: 0, count: 2, bytes: new Uint8Array([1, 2]) });
    expect(
      pendingLimited.accept({ id: 2, index: 0, count: 2, bytes: new Uint8Array([3]) }),
    ).toEqual({ status: "rejected", id: 2, reason: "capacity_exceeded" });
    expect(pendingLimited.pendingGroups).toBe(1);
  });

  it("can own its 30-second idle expiry timer", () => {
    vi.useFakeTimers();
    const reassembler = new FrameReassembler({ scheduleExpiry: true });
    reassembler.accept({ id: 9, index: 0, count: 2, bytes: new Uint8Array([1]) });

    vi.advanceTimersByTime(INCOMPLETE_FRAME_TIMEOUT_MS);

    expect(reassembler.pendingGroups).toBe(0);
    expect(reassembler.pendingBytes).toBe(0);
    reassembler.clear();
  });
});
