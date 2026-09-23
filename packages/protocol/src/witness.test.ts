import { decodeCanonical, encodeCanonical } from "@p2pcards/encoding";
import { describe, expect, it } from "vitest";

import { parseHash256, parseIdentityPublicKey } from "./fields";
import { ProtocolSchemaError } from "./schema";
import { decodeWitnessBody, encodeWitnessBody, type WitnessHead } from "./witness";

describe("WITNESS body codec", () => {
  it("round-trips an empty body and up to eight unique heads", () => {
    expect(decodeWitnessBody(decodeCanonical(encodeCanonical(encodeWitnessBody({ heads: [] }))))).toEqual({
      heads: [],
    });

    const heads = Array.from({ length: 8 }, (_, index) => witnessHead(index));
    const stateHash = parseHash256(new Uint8Array(32).fill(0x44));
    expect(
      decodeWitnessBody(
        decodeCanonical(encodeCanonical(encodeWitnessBody({ heads, stateHash }))),
      ),
    ).toEqual({ heads, stateHash });
  });

  it("rejects extension fields and malformed head fields", () => {
    expect(() => decodeWitnessBody({ heads: [], extra: true })).toThrow(ProtocolSchemaError);
    expect(() =>
      decodeWitnessBody({ heads: [{ from: new Uint8Array(31), seq: 0, hash: new Uint8Array(32) }] }),
    ).toThrow(ProtocolSchemaError);
    expect(() =>
      decodeWitnessBody({ heads: [{ from: new Uint8Array(32), seq: -1, hash: new Uint8Array(32) }] }),
    ).toThrow(ProtocolSchemaError);
    expect(() =>
      decodeWitnessBody({ heads: [{ from: new Uint8Array(32), seq: 0, hash: new Uint8Array(31) }] }),
    ).toThrow(ProtocolSchemaError);
    expect(() => decodeWitnessBody({ heads: [], state_hash: new Uint8Array(31) })).toThrow(
      ProtocolSchemaError,
    );
  });

  it("rejects more than eight heads and duplicate senders", () => {
    expect(() => encodeWitnessBody({ heads: Array.from({ length: 9 }, (_, i) => witnessHead(i)) })).toThrow(
      ProtocolSchemaError,
    );
    expect(() => encodeWitnessBody({ heads: [witnessHead(0), witnessHead(0)] })).toThrow(
      ProtocolSchemaError,
    );
    expect(() =>
      decodeWitnessBody({
        heads: [
          { from: new Uint8Array(32).fill(1), seq: 0, hash: new Uint8Array(32) },
          { from: new Uint8Array(32).fill(1), seq: 1, hash: new Uint8Array(32).fill(2) },
        ],
      }),
    ).toThrow(ProtocolSchemaError);
  });

  it("copies mutable byte fields at both codec boundaries", () => {
    const source = witnessHead(2);
    const stateHash = parseHash256(new Uint8Array(32).fill(7));
    const encoded = encodeWitnessBody({ heads: [source], stateHash });
    source.from.fill(0);
    source.hash.fill(0);
    stateHash.fill(0);
    const decoded = decodeWitnessBody(encoded);
    const stableFrom = decoded.heads[0]!.from.slice();
    const stableHash = decoded.heads[0]!.hash.slice();
    (encoded["heads"] as Array<{ from: Uint8Array; hash: Uint8Array }>)[0]!.from.fill(9);
    (encoded["heads"] as Array<{ from: Uint8Array; hash: Uint8Array }>)[0]!.hash.fill(9);
    (encoded["state_hash"] as Uint8Array).fill(9);

    expect(decoded.heads[0]!.from).toEqual(stableFrom);
    expect(decoded.heads[0]!.hash).toEqual(stableHash);
    expect(decoded.stateHash).toEqual(new Uint8Array(32).fill(7));
  });
});

function witnessHead(index: number): WitnessHead {
  return {
    from: parseIdentityPublicKey(new Uint8Array(32).fill(index + 1)),
    seq: index,
    hash: parseHash256(new Uint8Array(32).fill(0x80 + index)),
  };
}
