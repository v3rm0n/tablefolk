import { deriveEd25519PublicKey, importEd25519SecretKey } from "@p2pcards/crypto";
import { parseGameId, parseHash256, parseIdentityPublicKey, signEnvelope } from "@p2pcards/protocol";
import { describe, expect, it } from "vitest";

import { planHeadSyncRequest } from "./sync-plan";

const key = importEd25519SecretKey(new Uint8Array(32).fill(3));
const from = parseIdentityPublicKey(deriveEd25519PublicKey(key));
const hash = parseHash256(new Uint8Array(32));
const original = signEnvelope({
  v: 1, game: parseGameId(new Uint8Array(16)), from, seq: 0, prev: hash,
  type: "ACTION", round: 1, phase: "round.1.play.0", body: {},
}, key);

describe("HEADS sync planning", () => {
  it("requests bounded missing ranges without overflowing a large sequence", () => {
    expect(planHeadSyncRequest({ from, seq: Number.MAX_SAFE_INTEGER, hash }, { from, seq: 10, hash }, () => undefined, 4))
      .toMatchObject({ status: "missing", request: { from, fromSeq: 11, toSeq: 14 } });
  });

  it("compares historical heads as well as the local tip and requests a conflicting original", () => {
    const head = { from, seq: 8, hash };
    expect(planHeadSyncRequest({ from, seq: 0, hash: original.hash }, head, () => original)).toEqual({ status: "known" });
    expect(planHeadSyncRequest({ from, seq: 0, hash }, head, () => original)).toMatchObject({
      status: "conflict", request: { from, fromSeq: 0, toSeq: 0 },
    });
  });
});
