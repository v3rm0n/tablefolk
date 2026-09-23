import {
  bytesToHex,
  hexToBytes,
  importEd25519SecretKey,
  type Ed25519SecretKey,
} from "@p2pcards/crypto";
import { decodeCanonical, encodeCanonical, type CborMap } from "@p2pcards/encoding";
import { describe, expect, it } from "vitest";

import {
  decodeAndVerifyEnvelope,
  encodeUnsignedEnvelope,
  EnvelopeValidationError,
  signEnvelope,
  type UnsignedEnvelope,
} from "./envelope";
import { parseGameId, parseHash256, parseIdentityPublicKey } from "./fields";

const SECRET_KEY = importEd25519SecretKey(
  hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
);
const PUBLIC_KEY = parseIdentityPublicKey(
  hexToBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
);

function readyEnvelope(overrides: Partial<UnsignedEnvelope> = {}): UnsignedEnvelope {
  return {
    v: 1,
    game: parseGameId(hexToBytes("000102030405060708090a0b0c0d0e0f")),
    from: PUBLIC_KEY,
    seq: 0,
    prev: parseHash256(new Uint8Array(32)),
    round: 0,
    phase: "lobby",
    type: "READY",
    body: { roster_hash: new Uint8Array(32) },
    ...overrides,
  };
}

describe("signed envelopes", () => {
  it("signs, hashes, decodes, and verifies a canonical envelope", () => {
    const signed = signEnvelope(readyEnvelope(), SECRET_KEY);
    const verified = decodeAndVerifyEnvelope(signed.canonicalBytes);

    expect(bytesToHex(encodeUnsignedEnvelope(signed.envelope))).toBe(
      "a9617601637365710064626f6479a16b726f737465725f686173685820" +
        "00".repeat(32) +
        "6466726f6d5820d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" +
        "6467616d6550000102030405060708090a0b0c0d0e0f64707265765820" +
        "00".repeat(32) +
        "6474797065655245414459657068617365656c6f62627965726f756e6400",
    );
    expect(bytesToHex(signed.envelope.sig)).toBe(
      "1548007c25306e23ee0b6c575316963c0480f5d17c33d3dcdcdcfb60ae41689c" +
        "53869f62c15721bde031d29f45f872206d94f2dd64eda0d612310e5914a31601",
    );
    expect(bytesToHex(signed.hash)).toBe(
      "238d40850e09faff9ba99f2641cabfd1dbfd7f7d290687de6b2d5b12670d48d9",
    );
    expect(verified.envelope).toEqual(signed.envelope);
    expect(verified.canonicalBytes).toEqual(signed.canonicalBytes);
    expect(verified.hash).toEqual(signed.hash);
    expect(verified.hash).toHaveLength(32);
    expect(verified.envelope.sig).toHaveLength(64);
  });

  it("signs the canonical envelope projection without sig", () => {
    const unsigned = readyEnvelope();
    const signed = signEnvelope(unsigned, SECRET_KEY);
    const decoded = decodeCanonical(signed.canonicalBytes) as CborMap;

    expect(Object.hasOwn(decoded, "sig")).toBe(true);
    expect(encodeUnsignedEnvelope(signed.envelope)).toEqual(encodeUnsignedEnvelope(unsigned));
  });

  it("produces stable bytes for the same key and envelope", () => {
    const first = signEnvelope(readyEnvelope(), SECRET_KEY);
    const second = signEnvelope(readyEnvelope(), SECRET_KEY);

    expect(bytesToHex(first.canonicalBytes)).toBe(bytesToHex(second.canonicalBytes));
    expect(first.hash).toEqual(second.hash);
  });

  it("snapshots body values away from signing input and decoded bytes", () => {
    const inputHash = new Uint8Array(32);
    const signed = signEnvelope(
      readyEnvelope({ body: { roster_hash: inputHash } }),
      SECRET_KEY,
    );
    inputHash.fill(1);
    expect((signed.envelope.body as CborMap)["roster_hash"]).toEqual(new Uint8Array(32));

    const encoded = signed.canonicalBytes.slice();
    const verified = decodeAndVerifyEnvelope(encoded);
    encoded.fill(0xff);
    expect((verified.envelope.body as CborMap)["roster_hash"]).toEqual(new Uint8Array(32));
  });

  it("refuses to sign an envelope claiming another identity", () => {
    const anotherSender = parseIdentityPublicKey(new Uint8Array(32).fill(1));

    expect(() => signEnvelope(readyEnvelope({ from: anotherSender }), SECRET_KEY)).toThrowError(
      expect.objectContaining({ code: "SENDER_KEY_MISMATCH" }),
    );
  });

  it("rejects a body modified after signing", () => {
    const signed = signEnvelope(readyEnvelope(), SECRET_KEY);
    const decoded = decodeCanonical(signed.canonicalBytes) as CborMap;
    const tampered = encodeCanonical({ ...decoded, body: { roster_hash: new Uint8Array(32).fill(1) } });

    expect(() => decodeAndVerifyEnvelope(tampered)).toThrowError(
      expect.objectContaining({ code: "INVALID_SIGNATURE" }),
    );
  });

  it("rejects unknown and missing fields", () => {
    const signed = signEnvelope(readyEnvelope(), SECRET_KEY);
    const decoded = decodeCanonical(signed.canonicalBytes) as CborMap;
    const { sig: _signature, ...missingSignature } = decoded;
    const withUnknown = encodeCanonical({ ...decoded, extension: true });

    expect(() => decodeAndVerifyEnvelope(encodeCanonical(missingSignature))).toThrowError(
      EnvelopeValidationError,
    );
    expect(() => decodeAndVerifyEnvelope(withUnknown)).toThrowError(
      expect.objectContaining({ code: "MALFORMED_ENVELOPE" }),
    );
  });

  it.each([
    { field: "v", value: 2, code: "UNSUPPORTED_VERSION" },
    { field: "seq", value: -1, code: "MALFORMED_ENVELOPE" },
    { field: "round", value: "1", code: "MALFORMED_ENVELOPE" },
    { field: "phase", value: "", code: "MALFORMED_ENVELOPE" },
    { field: "type", value: "HELLO", code: "MALFORMED_ENVELOPE" },
  ] as const)("rejects invalid $field", ({ field, value, code }) => {
    const signed = signEnvelope(readyEnvelope(), SECRET_KEY);
    const decoded = decodeCanonical(signed.canonicalBytes) as CborMap;
    const malformed = encodeCanonical({ ...decoded, [field]: value });

    expect(() => decodeAndVerifyEnvelope(malformed)).toThrowError(expect.objectContaining({ code }));
  });

  it("rejects invalid sender public-key encodings without leaking a curve exception", () => {
    const signed = signEnvelope(readyEnvelope(), SECRET_KEY);
    const decoded = decodeCanonical(signed.canonicalBytes) as CborMap;
    const malformed = encodeCanonical({ ...decoded, from: new Uint8Array(32) });

    expect(() => decodeAndVerifyEnvelope(malformed)).toThrowError(
      expect.objectContaining({ code: "INVALID_SIGNATURE" }),
    );
  });

  it("rejects non-canonical input before signature verification", () => {
    expect(() => decodeAndVerifyEnvelope(hexToBytes("a0a0"))).toThrowError(
      expect.objectContaining({ code: "MALFORMED_ENVELOPE" }),
    );
  });

  it("validates the secret key again at the signing boundary", () => {
    expect(() => signEnvelope(readyEnvelope(), new Uint8Array(31) as Ed25519SecretKey)).toThrow(
      RangeError,
    );
  });
});
