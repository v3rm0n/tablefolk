import { RistrettoPoint, RISTRETTO_SCALAR_ORDER, encodeRistrettoScalar, scalarFromBigInt } from "@p2pcards/crypto";
import { encodeCanonical } from "@p2pcards/encoding";
import { describe, expect, it } from "vitest";
import {
  CANDIDATE_SHUFFLE_PROOF_36_PROFILE as PROFILE,
  CANDIDATE_SHUFFLE_PROOF_36_BYTES as SIZE,
  decodeCandidateShuffleProof36 as decode,
  encodeCandidateShuffleProof36 as encode,
} from "./shuffle-proof-codec";

const isScalar = (i: number) => (i >= 24 && i <= 44) || (i >= 48 && i <= 67) || i >= 93;
const elements = Array.from({ length: 106 }, (_, i) => isScalar(i)
  ? encodeRistrettoScalar(scalarFromBigInt(BigInt(i)))
  : RistrettoPoint.base().multiply(scalarFromBigInt(BigInt(i))).toBytes());
const canonical = encodeCanonical([PROFILE, elements]);
const headerLength = canonical.length - 106 * 34;

describe("candidate fixed 36-card proof codec", () => {
  it("matches canonical CBOR independently of the fixed grammar parser", () => {
    expect(encode(elements)).toEqual(canonical);
    expect(decode(canonical)).toEqual(elements);
    expect(SIZE).toBe(canonical.length);
  });

  it("permits zero scalars and identity points without claiming proof validity", () => {
    const zeros = Array.from({ length: 106 }, () => new Uint8Array(32));
    expect(decode(encode(zeros))).toEqual(zeros);
  });

  it("copies all buffers on encode and decode", () => {
    const encoded = encode(elements);
    const decoded = decode(encoded);
    expect(Object.isFrozen(decoded)).toBe(true);
    decoded[0]!.fill(255);
    expect(encoded).toEqual(canonical);
    encoded.fill(0);
    expect(decoded[1]).toEqual(elements[1]);
    expect(encode(elements)).toEqual(canonical);
  });

  it("rejects every truncated prefix, suffixes, and oversized input", () => {
    for (let i = 0; i < SIZE; i++) { expect(() => decode(canonical.slice(0, i))).toThrow(); }
    expect(() => decode(new Uint8Array([...canonical, 0]))).toThrow();
    expect(() => decode(new Uint8Array(SIZE * 2))).toThrow();
  });

  it("rejects every altered header byte", () => {
    for (let i = 0; i < headerLength; i++) {
      const bytes = canonical.slice(); bytes[i] = bytes[i]! ^ 1;
      expect(() => decode(bytes)).toThrow();
    }
  });

  it.each(Array.from({ length: 106 }, (_, i) => i))("validates element %i and its byte-string header", (i) => {
    const offset = headerLength + 34 * i;
    for (const [at, value] of [[offset, 0x78], [offset + 1, 31]]) {
      const bytes = canonical.slice(); bytes[at!] = value!;
      expect(() => decode(bytes)).toThrow();
    }
    const invalid = canonical.slice(); invalid.fill(255, offset + 2, offset + 34);
    expect(() => decode(invalid)).toThrow();
    const badElements = elements.map((e) => e.slice()); badElements[i]!.fill(255);
    expect(() => encode(badElements)).toThrow();
  });

  it.each([RISTRETTO_SCALAR_ORDER, RISTRETTO_SCALAR_ORDER + 1n])("rejects scalar modulus boundary %s", (value) => {
    const bytes = canonical.slice();
    let n = value;
    for (let i = 0; i < 32; i++) { bytes[headerLength + 24 * 34 + 2 + i] = Number(n & 255n); n >>= 8n; }
    expect(() => decode(bytes)).toThrow();
  });

  it("rejects alternate CBOR structures and unknown profiles", () => {
    for (const value of [
      [PROFILE + "x", elements], [PROFILE, elements.slice(1)], [PROFILE, [...elements, elements[0]!]],
      { profile: PROFILE, elements }, [PROFILE, elements, 0],
    ]) { expect(() => decode(encodeCanonical(value))).toThrow(); }
    const overlongArray = new Uint8Array([0x98, 2, ...canonical.slice(1)]);
    expect(() => decode(overlongArray)).toThrow();
  });

  it("rejects wrong counts, sparse arrays, nonbytes, and wrong element sizes", () => {
    for (const values of [[], elements.slice(1), [...elements, elements[0]!], new Array<Uint8Array>(106)]) {
      expect(() => encode(values)).toThrow();
    }
    for (const size of [0, 31, 33]) {
      expect(() => encode([new Uint8Array(size), ...elements.slice(1)])).toThrow();
    }
    class Subclass extends Uint8Array {}
    expect(() => decode(new Subclass(canonical))).toThrow();
    expect(() => encode([new Subclass(elements[0]!), ...elements.slice(1)])).toThrow();
    expect(() => decode(null as unknown as Uint8Array)).toThrow();
  });
});
