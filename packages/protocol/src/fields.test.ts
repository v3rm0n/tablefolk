import { describe, expect, it, vi } from "vitest";

import { bytesToHex, encodeRistrettoScalar, hexToBytes, RistrettoPoint, scalarFromBigInt } from "@p2pcards/crypto";

import {
  ProtocolFieldError,
  parseDtlsFingerprint,
  parseEd25519Signature,
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  parseRandomSecret,
  parseRistrettoPointEncoding,
  parseScalarEncoding,
} from "./fields";

const FIXED_FIELD_CASES = [
  {
    field: "game_id",
    parse: parseGameId,
    hex: "000102030405060708090a0b0c0d0e0f",
  },
  {
    field: "identity_public_key",
    parse: parseIdentityPublicKey,
    hex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  },
  {
    field: "sha256_digest",
    parse: parseHash256,
    hex: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  },
  {
    field: "dtls_sha256_fingerprint",
    parse: parseDtlsFingerprint,
    hex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  },
  {
    field: "random_secret",
    parse: parseRandomSecret,
    hex: "5a".repeat(32),
  },
  {
    field: "ristretto255_point",
    parse: parseRistrettoPointEncoding,
    hex: "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
  },
  {
    field: "ristretto255_scalar",
    parse: parseScalarEncoding,
    hex: "07" + "00".repeat(31),
  },
  {
    field: "ed25519_signature",
    parse: parseEd25519Signature,
    hex:
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901" +
      "555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  },
] as const;

describe("fixed-length protocol fields", () => {
  it("accepts and copies a field of the exact required length", () => {
    const source = Uint8Array.from({ length: 16 }, (_, index) => index);
    const gameId = parseGameId(source);

    source[0] = 255;

    expect(gameId).toHaveLength(16);
    expect(gameId[0]).toBe(0);
  });

  it.each([
    ["game_id", () => parseGameId(new Uint8Array(15))],
    ["identity_public_key", () => parseIdentityPublicKey(new Uint8Array(33))],
    ["ed25519_signature", () => parseEd25519Signature(new Uint8Array(63))],
  ])("rejects an invalid %s length", (field, parse) => {
    expect(parse).toThrow(ProtocolFieldError);
    expect(parse).toThrow(field);
  });

  it("rejects values that are not plain Uint8Array instances", () => {
    expect(() => parseGameId([1, 2, 3])).toThrow(ProtocolFieldError);
    expect(() => parseGameId(new Uint16Array(8))).toThrow(ProtocolFieldError);
  });

  it("accepts canonical Ristretto point and scalar encodings", () => {
    expect(parseRistrettoPointEncoding(RistrettoPoint.base().toBytes())).toHaveLength(32);
    expect(parseScalarEncoding(encodeRistrettoScalar(scalarFromBigInt(7n)))).toHaveLength(32);
  });

  it("rejects invalid Ristretto point and non-canonical scalar encodings", () => {
    expect(() =>
      parseRistrettoPointEncoding(
        hexToBytes("0100000000000000000000000000000000000000000000000000000000000000"),
      ),
    ).toThrow(ProtocolFieldError);
    expect(() =>
      parseScalarEncoding(
        hexToBytes("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"),
      ),
    ).toThrow(ProtocolFieldError);
  });
});

describe.each(FIXED_FIELD_CASES)("$field physical byte boundaries", ({ field, parse, hex }) => {
  const size = hex.length / 2;

  it("preserves known-answer bytes from an offset view without copying its surroundings", () => {
    const backing = new Uint8Array(size + 10).fill(0xff);
    backing.set(hexToBytes(hex), 5);
    const source = backing.subarray(5, size + 5);
    const copy = parse(source);

    expect(bytesToHex(copy)).toBe(hex);
    expect(Object.getPrototypeOf(copy)).toBe(Uint8Array.prototype);
    expect(copy).not.toBe(source);
    expect(copy.buffer).not.toBe(source.buffer);
    expect(copy.byteOffset).toBe(0);
    expect(copy.buffer.byteLength).toBe(size);

    backing.fill(0xff);
    expect(bytesToHex(copy)).toBe(hex);
  });

  it.each([0, size - 1, size + 1])("rejects forged length metadata for %s physical bytes", (physicalLength) => {
    const source = new Uint8Array(physicalLength).fill(0xa5);
    const readLength = vi.fn(() => size);
    const readByteLength = vi.fn(() => size);
    const readSlice = vi.fn(() => {
      throw new Error("private field contents must not escape");
    });
    Object.defineProperties(source, {
      length: { get: readLength },
      byteLength: { get: readByteLength },
      slice: { get: readSlice },
    });

    expect(() => parse(source)).toThrowError(expect.objectContaining({
      name: "ProtocolFieldError",
      field,
      message: `${field}: must contain exactly ${size} bytes; got ${physicalLength}`,
    }));
    expect(readLength).not.toHaveBeenCalled();
    expect(readByteLength).not.toHaveBeenCalled();
    expect(readSlice).not.toHaveBeenCalled();
  });

  it("ignores throwing length, byteLength, and slice getters on valid physical bytes", () => {
    const source = hexToBytes(hex);
    const readMetadata = vi.fn(() => {
      throw new Error("private field contents must not escape");
    });
    Object.defineProperties(source, {
      length: { get: readMetadata },
      byteLength: { get: readMetadata },
      slice: { get: readMetadata },
    });

    const copy = parse(source);

    expect(bytesToHex(copy)).toBe(hex);
    expect(copy.buffer).not.toBe(source.buffer);
    expect(readMetadata).not.toHaveBeenCalled();
  });

  it("ignores an overridden slice and keeps input and separate copies independent", () => {
    const source = hexToBytes(hex);
    const slice = vi.fn(() => source);
    Object.defineProperty(source, "slice", { value: slice });

    const first = parse(source);
    const second = parse(source);
    first.fill(0xff);

    expect(bytesToHex(source)).toBe(hex);
    expect(bytesToHex(second)).toBe(hex);
    source.fill(0xee);
    expect(first).toEqual(new Uint8Array(size).fill(0xff));
    expect(bytesToHex(second)).toBe(hex);
    expect(first.buffer).not.toBe(second.buffer);
    expect(slice).not.toHaveBeenCalled();
  });

  it.each([1, 2])("rejects a Uint16Array prototype spoof with size divisor %s", (divisor) => {
    const source = new Uint16Array(size / divisor).fill(0xa5);
    Object.setPrototypeOf(source, Uint8Array.prototype);
    Object.defineProperties(source, {
      length: { value: size },
      byteLength: { value: size },
    });

    expect(source instanceof Uint8Array).toBe(true);
    expect(source.constructor).toBe(Uint8Array);
    expect(ArrayBuffer.isView(source)).toBe(true);
    expect(() => parse(source)).toThrowError(expect.objectContaining({
      name: "ProtocolFieldError",
      field,
      message: `${field}: must be a Uint8Array`,
    }));
  });

  it("rejects prototype-only and incompatible internal views despite convincing metadata", () => {
    const impostor = Object.create(Uint8Array.prototype) as Uint8Array;
    const dataView = new DataView(new ArrayBuffer(size));
    Object.setPrototypeOf(dataView, Uint8Array.prototype);
    for (const source of [impostor, dataView]) {
      const slice = vi.fn(() => hexToBytes(hex));
      Object.defineProperties(source, {
        length: { value: size },
        byteLength: { value: size },
        slice: { value: slice },
      });

      expect(source instanceof Uint8Array).toBe(true);
      expect(source.constructor).toBe(Uint8Array);
      expect(() => parse(source)).toThrowError(expect.objectContaining({
        name: "ProtocolFieldError",
        field,
        message: `${field}: must be a Uint8Array`,
      }));
      expect(slice).not.toHaveBeenCalled();
    }
  });

  it("rejects a proxy even when it supplies valid bytes and fake view metadata", () => {
    const target = hexToBytes(hex);
    const readMetadata = vi.fn(() => size);
    const slice = vi.fn(() => target);
    const source = new Proxy(target, {
      get(value, key) {
        if (key === "length" || key === "byteLength") { return readMetadata(); }
        if (key === "slice") { return slice; }
        return Reflect.get(value, key, value);
      },
    });

    expect(source instanceof Uint8Array).toBe(true);
    expect(() => parse(source)).toThrowError(expect.objectContaining({
      name: "ProtocolFieldError",
      field,
      message: `${field}: must be a Uint8Array`,
    }));
    expect(readMetadata).not.toHaveBeenCalled();
    expect(slice).not.toHaveBeenCalled();
  });

  it("reports only field and physical width, without coercing or leaking rejected bytes", () => {
    const source = new Uint8Array(size + 1).fill(0xa5);
    const format = vi.fn(() => {
      throw new Error("secret serialized field contents");
    });
    Object.defineProperties(source, {
      toString: { value: format },
      toJSON: { value: format },
      [Symbol.toPrimitive]: { value: format },
    });

    let failure: unknown;
    try {
      parse(source);
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(ProtocolFieldError);
    expect(failure).toMatchObject({
      field,
      message: `${field}: must contain exactly ${size} bytes; got ${size + 1}`,
    });
    expect(String(failure)).not.toContain(bytesToHex(source));
    expect(JSON.stringify(failure)).not.toContain(bytesToHex(source));
    expect(format).not.toHaveBeenCalled();
  });
});
