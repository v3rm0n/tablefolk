import { describe, expect, it } from "vitest";

import { bytesToHex, hexToBytes } from "./bytes";
import type { RandomSource } from "./random";
import {
  addRistrettoScalars,
  decodeRistrettoScalar,
  encodeRistrettoScalar,
  multiplyRistrettoScalars,
  randomNonZeroRistrettoScalar,
  reduceWideRistrettoScalar,
  RISTRETTO_SCALAR_ONE,
  RISTRETTO_SCALAR_ORDER,
  RISTRETTO_SCALAR_ZERO,
  RistrettoEncodingError,
  RistrettoPoint,
  scalarFromBigInt,
  subtractRistrettoScalars,
} from "./ristretto";

const GENERATOR_MULTIPLES = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
  "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
  "94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259",
  "da80862773358b466ffadfe0b3293ab3d9fd53c5ea6c955358f568322daf6a57",
] as const;

const INVALID_POINT_ENCODINGS = [
  "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371",
] as const;

describe("Ristretto255 points", () => {
  it("matches RFC 9496 generator multiples", () => {
    const base = RistrettoPoint.base();
    let sum = RistrettoPoint.identity();

    for (const expected of GENERATOR_MULTIPLES) {
      expect(bytesToHex(sum.toBytes())).toBe(expected);
      expect(RistrettoPoint.fromBytes(sum.toBytes()).equals(sum)).toBe(true);
      sum = sum.add(base);
    }

    expect(bytesToHex(base.multiply(scalarFromBigInt(4n)).toBytes())).toBe(
      GENERATOR_MULTIPLES[4],
    );
    expect(base.subtract(base).isIdentity()).toBe(true);
    expect(base.add(base.negate()).isIdentity()).toBe(true);
    expect(base.multiply(RISTRETTO_SCALAR_ZERO).isIdentity()).toBe(true);
  });

  it.each(INVALID_POINT_ENCODINGS)("rejects RFC 9496 invalid encoding %s", (encoding) => {
    expect(() => RistrettoPoint.fromBytes(hexToBytes(encoding))).toThrow(
      RistrettoEncodingError,
    );
  });

  it("derives the RFC 9496 element from uniform bytes", () => {
    const input = hexToBytes(
      "5d1be09e3d0c82fc538112490e35701979d99e06ca3e2b5b54bffe8b4dc772c1" +
        "4d98b696a1bbfb5ca32c436cc61c16563790306c79eaca7705668b47dffe5bb6",
    );

    expect(bytesToHex(RistrettoPoint.fromUniformBytes(input).toBytes())).toBe(
      "3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46",
    );
  });

  it("rejects incorrect point and uniform-input lengths", () => {
    expect(() => RistrettoPoint.fromBytes(new Uint8Array(31))).toThrow(
      RistrettoEncodingError,
    );
    expect(() => RistrettoPoint.fromUniformBytes(new Uint8Array(63))).toThrow(
      RistrettoEncodingError,
    );
  });
});

describe("Ristretto255 scalars", () => {
  it("uses the RFC 9496 group order", () => {
    expect(RISTRETTO_SCALAR_ORDER).toBe(
      2n ** 252n + 27742317777372353535851937790883648493n,
    );
  });

  it.each([0n, 1n, RISTRETTO_SCALAR_ORDER - 1n])(
    "round-trips canonical scalar %s",
    (value) => {
      const scalar = scalarFromBigInt(value);
      expect(decodeRistrettoScalar(encodeRistrettoScalar(scalar))).toBe(scalar);
    },
  );

  it("rejects the group order and incorrect lengths as non-canonical", () => {
    expect(() => decodeRistrettoScalar(bigIntToLittleEndian(RISTRETTO_SCALAR_ORDER, 32))).toThrow(
      RistrettoEncodingError,
    );
    expect(() => decodeRistrettoScalar(new Uint8Array(31))).toThrow(RistrettoEncodingError);
    expect(() => scalarFromBigInt(-1n)).toThrow(RangeError);
    expect(() => scalarFromBigInt(RISTRETTO_SCALAR_ORDER)).toThrow(RangeError);
  });

  it("reduces 64-byte little-endian challenge material modulo the order", () => {
    const wide = bigIntToLittleEndian(RISTRETTO_SCALAR_ORDER + 5n, 64);
    expect(reduceWideRistrettoScalar(wide)).toBe(5n);
    expect(() => reduceWideRistrettoScalar(new Uint8Array(32))).toThrow(
      RistrettoEncodingError,
    );
  });

  it("performs scalar arithmetic modulo the group order", () => {
    const last = scalarFromBigInt(RISTRETTO_SCALAR_ORDER - 1n);
    expect(addRistrettoScalars(last, RISTRETTO_SCALAR_ONE)).toBe(RISTRETTO_SCALAR_ZERO);
    expect(subtractRistrettoScalars(RISTRETTO_SCALAR_ONE, scalarFromBigInt(2n))).toBe(last);
    expect(multiplyRistrettoScalars(scalarFromBigInt(2n), scalarFromBigInt(3n))).toBe(6n);
  });

  it("rejection-samples a non-zero scalar from the injected source", () => {
    let call = 0;
    const source: RandomSource = {
      fill(target) {
        call += 1;
        if (call === 1) {
          target.fill(0xff);
        } else if (call === 3) {
          target[0] = 7;
        }
      },
    };

    expect(randomNonZeroRistrettoScalar(source)).toBe(7n);
    expect(call).toBe(3);
  });
});

function bigIntToLittleEndian(value: bigint, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  let remaining = value;
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  if (remaining !== 0n) {
    throw new RangeError("Value does not fit in the requested byte length");
  }
  return bytes;
}
