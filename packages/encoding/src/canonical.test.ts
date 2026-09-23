import { describe, expect, it } from "vitest";

import { decodeCanonical, encodeCanonical } from "./canonical";
import { CanonicalCborError } from "./errors";
import type { CborValue } from "./value";

describe("canonical CBOR encoding", () => {
  it.each([
    [null, "f6"],
    [false, "f4"],
    [true, "f5"],
    [0, "00"],
    [23, "17"],
    [24, "1818"],
    [-1, "20"],
    ["a", "6161"],
    [new Uint8Array([0, 1, 2]), "43000102"],
  ] satisfies ReadonlyArray<readonly [CborValue, string]>) (
    "encodes %j to its known value",
    (value, expected) => {
      expect(toHex(encodeCanonical(value))).toBe(expected);
    },
  );

  it("sorts map keys by Core Deterministic Encoding order", () => {
    expect(toHex(encodeCanonical({ aa: 2, b: 1 }))).toBe("a261620162616102");
  });

  it("is independent of object insertion order", () => {
    expect(encodeCanonical({ alpha: 1, beta: 2 })).toEqual(
      encodeCanonical({ beta: 2, alpha: 1 }),
    );
  });

  it("round-trips nested protocol values", () => {
    const value: CborValue = {
      body: { ready: true },
      bytes: new Uint8Array([5, 4, 3]),
      seats: [0, 1, 2, 3],
    };

    const decoded = decodeCanonical(encodeCanonical(value));
    expect(decoded).toEqual(value);
    expect(Object.getPrototypeOf(decoded)).toBeNull();
  });

  it.each([
    undefined,
    1.5,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    -0,
    1n,
    new Date(0),
    new Map([["a", 1]]),
    new Uint16Array([1]),
    "\ud800",
  ])("rejects unsupported value %#", (value) => {
    expect(() => encodeCanonical(value as CborValue)).toThrow(CanonicalCborError);
  });

  it("rejects sparse and cyclic arrays", () => {
    const sparse: CborValue[] = [];
    sparse.length = 1;
    const cyclic: unknown[] = [];
    cyclic.push(cyclic);

    expect(() => encodeCanonical(sparse)).toThrow(CanonicalCborError);
    expect(() => encodeCanonical(cyclic as CborValue)).toThrow(CanonicalCborError);
  });
});

describe("canonical CBOR decoding", () => {
  it("copies decoded byte strings away from the encoded input", () => {
    const encoded = encodeCanonical({ bytes: new Uint8Array([1, 2, 3]) });
    const decoded = decodeCanonical(encoded) as { readonly bytes: Uint8Array };

    encoded.fill(0xff);
    expect(decoded.bytes).toEqual(new Uint8Array([1, 2, 3]));
  });

  it.each([
    ["1801", "non-preferred integer"],
    ["9f01ff", "indefinite-length array"],
    ["a2616101616102", "duplicate map key"],
    ["a262616102616201", "map keys in the wrong order"],
    ["f93c00", "floating-point value"],
    ["c001", "tagged value"],
    ["0102", "multiple top-level values"],
    ["", "empty input"],
  ])("rejects %s (%s)", (hex) => {
    expect(() => decodeCanonical(fromHex(hex))).toThrow(CanonicalCborError);
  });

  it("rejects non-text map keys", () => {
    expect(() => decodeCanonical(fromHex("a1016161"))).toThrow(CanonicalCborError);
  });

  it("rejects values deeper than the profile limit", () => {
    const bytes = fromHex(`${"81".repeat(33)}00`);
    expect(() => decodeCanonical(bytes)).toThrow(CanonicalCborError);
  });

  it("decodes prototype-like keys into a null-prototype record", () => {
    const decoded = decodeCanonical(fromHex("a1695f5f70726f746f5f5f01"));

    expect(Object.getPrototypeOf(decoded)).toBeNull();
    expect((decoded as { readonly __proto__: number }).__proto__).toBe(1);
    expect(Object.prototype).not.toHaveProperty("polluted");
  });
});

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("Hex input must contain whole bytes");
  }

  return Uint8Array.from(
    { length: hex.length / 2 },
    (_, index) => Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16),
  );
}
