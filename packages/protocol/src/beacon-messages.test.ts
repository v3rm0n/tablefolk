import { decodeCanonical, encodeCanonical } from "@p2pcards/encoding";
import { describe, expect, it } from "vitest";

import {
  decodeRandCommitBody,
  decodeRandRevealBody,
  encodeRandCommitBody,
  encodeRandRevealBody,
} from "./beacon-messages";
import { parseHash256, parseRandomSecret } from "./fields";
import { ProtocolSchemaError } from "./schema";

describe("randomness beacon message bodies", () => {
  it("round-trips exact commitment and reveal maps", () => {
    const commitment = { cm: parseHash256(new Uint8Array(32).fill(1)) };
    const reveal = { s: parseRandomSecret(new Uint8Array(32).fill(2)) };

    expect(decodeRandCommitBody(decodeCanonical(encodeCanonical(encodeRandCommitBody(commitment))))).toEqual(
      commitment,
    );
    expect(decodeRandRevealBody(decodeCanonical(encodeCanonical(encodeRandRevealBody(reveal))))).toEqual(
      reveal,
    );
  });

  it("rejects extra fields and incorrect lengths", () => {
    expect(() => decodeRandCommitBody({ cm: new Uint8Array(32), extra: true })).toThrow(
      ProtocolSchemaError,
    );
    expect(() => decodeRandCommitBody({ cm: new Uint8Array(31) })).toThrow(
      ProtocolSchemaError,
    );
    expect(() => decodeRandRevealBody({ s: new Uint8Array(33) })).toThrow(
      ProtocolSchemaError,
    );
  });
});
