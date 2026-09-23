import { scalarFromBigInt, type RandomSource, RistrettoPoint } from "@p2pcards/crypto";
import { decodeCanonical, encodeCanonical, type CborMap } from "@p2pcards/encoding";
import { parseGameId, ProtocolSchemaError, type ProofContext } from "@p2pcards/protocol";
import { describe, expect, it } from "vitest";

import { createGameKeyShare, createProvenDecryptionShare, verifyGameKeyShare, verifyProvenDecryptionShare } from "./proofs";
import {
  decodeGameKeyShareBody,
  decodeSharesBody,
  encodeGameKeyShareBody,
  encodeSharesBody,
  type PositionShare,
} from "./wire";

const CONTEXT: ProofContext = {
  gameId: parseGameId(new Uint8Array(16).fill(4)),
  round: 1,
  phase: "round.1.deal.0",
};

describe("deck protocol wire bodies", () => {
  it("round-trips KEY_SHARE and preserves proof validity", () => {
    const original = createGameKeyShare(CONTEXT, scalarFromBigInt(3n), scalarSource(9));
    const decoded = decodeGameKeyShareBody(
      decodeCanonical(encodeCanonical(encodeGameKeyShareBody(original))),
    );

    expect(decoded.H.equals(original.H)).toBe(true);
    expect(decoded.pop.R.equals(original.pop.R)).toBe(true);
    expect(decoded.pop.z).toBe(original.pop.z);
    expect(verifyGameKeyShare(CONTEXT, decoded)).toBe(true);
  });

  it("rejects unknown KEY_SHARE fields and invalid point encodings", () => {
    const original = createGameKeyShare(CONTEXT, scalarFromBigInt(3n), scalarSource(9));
    const body = encodeGameKeyShareBody(original);

    expect(() => decodeGameKeyShareBody({ ...body, extra: true })).toThrow(ProtocolSchemaError);
    expect(() => decodeGameKeyShareBody({ ...body, H_i: new Uint8Array(32).fill(1) })).toThrow(
      ProtocolSchemaError,
    );
  });

  it("round-trips a batched SHARES body and preserves each DLEQ proof", () => {
    const secret = scalarFromBigInt(3n);
    const publicKey = RistrettoPoint.base().multiply(secret);
    const cardA = RistrettoPoint.base().multiply(scalarFromBigInt(11n));
    const items: PositionShare[] = [2, 5].map((pos) => ({
      pos,
      ...createProvenDecryptionShare(CONTEXT, pos, secret, cardA, scalarSource(pos + 7)),
    }));
    const decoded = decodeSharesBody(
      decodeCanonical(encodeCanonical(encodeSharesBody({ to: 1, items }))),
    );

    expect(decoded.to).toBe(1);
    expect(decoded.items.map(({ pos }) => pos)).toEqual([2, 5]);
    for (const item of decoded.items) {
      expect(verifyProvenDecryptionShare(CONTEXT, item.pos, publicKey, cardA, item)).toBe(true);
    }
  });

  it("rejects empty batches, duplicate positions, invalid seats, and extra item fields", () => {
    const secret = scalarFromBigInt(3n);
    const cardA = RistrettoPoint.base().multiply(scalarFromBigInt(11n));
    const share: PositionShare = {
      pos: 2,
      ...createProvenDecryptionShare(CONTEXT, 2, secret, cardA, scalarSource(9)),
    };

    expect(() => encodeSharesBody({ to: 1, items: [] })).toThrow(ProtocolSchemaError);
    expect(() => encodeSharesBody({ to: 8, items: [share] })).toThrow(ProtocolSchemaError);
    expect(() => encodeSharesBody({ to: 1, items: [share, share] })).toThrow(ProtocolSchemaError);

    const encoded = encodeSharesBody({ to: 1, items: [share] });
    const first = (encoded["items"] as readonly CborMap[])[0]!;
    expect(() => decodeSharesBody({ ...encoded, items: [{ ...first, extra: 1 }] })).toThrow(
      ProtocolSchemaError,
    );
  });
});

function scalarSource(value: number): RandomSource {
  return {
    fill(target) {
      target.fill(0);
      target[0] = value;
    },
  };
}
