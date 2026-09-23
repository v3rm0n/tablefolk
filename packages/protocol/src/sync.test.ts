import {
  hexToBytes,
  importEd25519SecretKey,
} from "@p2pcards/crypto";
import {
  decodeCanonical,
  encodeCanonical,
  type CborMap,
} from "@p2pcards/encoding";
import { describe, expect, it } from "vitest";

import {
  decodeAndVerifyEnvelope,
  signEnvelope,
  type EnvelopeArtifact,
  type UnsignedEnvelope,
} from "./envelope";
import { parseGameId, parseHash256, parseIdentityPublicKey } from "./fields";
import { ProtocolSchemaError } from "./schema";
import {
  decodeSyncRequestBody,
  decodeSyncResponseBody,
  encodeSyncRequestBody,
  encodeSyncResponseBody,
} from "./sync";

const SECRET_KEY = importEd25519SecretKey(
  hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
);
const PUBLIC_KEY = parseIdentityPublicKey(
  hexToBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
);
const GAME_ID = parseGameId(hexToBytes("000102030405060708090a0b0c0d0e0f"));
const ZERO_HASH = parseHash256(new Uint8Array(32));

describe("sync body codecs", () => {
  it("round-trips a bounded inclusive request", () => {
    const request = { from: PUBLIC_KEY, fromSeq: 2, toSeq: 7 };
    const decoded = decodeSyncRequestBody(
      decodeCanonical(encodeCanonical(encodeSyncRequestBody(request))),
    );

    expect(decoded).toEqual(request);
    expect(encodeSyncRequestBody(request)).toEqual({
      from: PUBLIC_KEY,
      from_seq: 2,
      to_seq: 7,
    });
  });

  it("rejects malformed and descending requests", () => {
    expect(() =>
      decodeSyncRequestBody({ from: PUBLIC_KEY, from_seq: 3, to_seq: 2 }),
    ).toThrow(ProtocolSchemaError);
    expect(() =>
      decodeSyncRequestBody({ from: new Uint8Array(31), from_seq: 0, to_seq: 0 }),
    ).toThrow(ProtocolSchemaError);
    expect(() =>
      decodeSyncRequestBody({ from: PUBLIC_KEY, from_seq: 0, to_seq: 0, extra: true }),
    ).toThrow(ProtocolSchemaError);
  });

  it("round-trips nested canonical envelopes and verifies each signature", () => {
    const first = signedReady(0, ZERO_HASH, "first");
    const second = signedReady(1, first.hash, "second");
    const encoded = encodeSyncResponseBody({ envelopes: [first, second] });
    const decoded = decodeSyncResponseBody(
      decodeCanonical(encodeCanonical(encoded)),
    );

    expect(decoded.envelopes.map(({ canonicalBytes }) => canonicalBytes)).toEqual([
      first.canonicalBytes,
      second.canonicalBytes,
    ]);
    expect(decoded.envelopes.map(({ envelope }) => envelope.seq)).toEqual([0, 1]);
  });

  it("rejects an empty response because every valid request covers at least one sequence", () => {
    expect(() => decodeSyncResponseBody({ envelopes: [] })).toThrow(ProtocolSchemaError);
    expect(() => encodeSyncResponseBody({ envelopes: [] })).toThrow(ProtocolSchemaError);
  });

  it("rejects malformed or signature-tampered nested envelopes", () => {
    const artifact = signedReady(0, ZERO_HASH, "original");
    const nested = decodeCanonical(artifact.canonicalBytes) as CborMap;
    const tampered = { ...nested, body: { marker: "tampered" } };

    expect(() => decodeSyncResponseBody({ envelopes: [new Uint8Array(4)] })).toThrow(
      ProtocolSchemaError,
    );
    expect(() => decodeSyncResponseBody({ envelopes: [tampered] })).toThrow(
      ProtocolSchemaError,
    );
  });

  it("detaches encoded responses from mutable artifact bytes", () => {
    const artifact = signedReady(0, ZERO_HASH, "stable");
    const encoded = encodeSyncResponseBody({ envelopes: [artifact] });
    artifact.canonicalBytes.fill(0);

    const decoded = decodeSyncResponseBody(encoded);
    expect(decodeAndVerifyEnvelope(decoded.envelopes[0]!.canonicalBytes).envelope.seq).toBe(0);
  });
});

function signedReady(seq: number, prev: Uint8Array, marker: string): EnvelopeArtifact {
  const envelope: UnsignedEnvelope = {
    v: 1,
    game: GAME_ID,
    from: PUBLIC_KEY,
    seq,
    prev: parseHash256(prev),
    round: 0,
    phase: "lobby",
    type: "READY",
    body: { marker },
  };
  return signEnvelope(envelope, SECRET_KEY);
}
