import {
  hexToBytes,
  importEd25519SecretKey,
  type Ed25519SecretKey,
} from "@p2pcards/crypto";
import {
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  signEnvelope,
  type EnvelopeArtifact,
  type Hash256,
  type IdentityPublicKey,
  type UnsignedEnvelope,
} from "@p2pcards/protocol";
import { describe, expect, it } from "vitest";

import { SenderChain } from "./sender-chain";

const ALICE_SECRET = importEd25519SecretKey(
  hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
);
const ALICE_PUBLIC = parseIdentityPublicKey(
  hexToBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
);
const BOB_SECRET = importEd25519SecretKey(
  hexToBytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
);
const BOB_PUBLIC = parseIdentityPublicKey(
  hexToBytes("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
);
const GAME_ID = parseGameId(hexToBytes("000102030405060708090a0b0c0d0e0f"));
const ZERO_HASH = parseHash256(new Uint8Array(32));

describe("per-sender envelope chains", () => {
  it("classifies the next artifact without mutating the chain", () => {
    const chain = new SenderChain(ALICE_PUBLIC);
    const first = signedReady(ALICE_SECRET, ALICE_PUBLIC, 0, ZERO_HASH, "first");

    expect(chain.classify(first)).toMatchObject({ status: "accepted", head: { seq: 0 } });
    expect(chain.head).toBeNull();
    expect(chain.size).toBe(0);
    expect(chain.ingest(first)).toMatchObject({ status: "accepted", head: { seq: 0 } });
  });

  it("accepts sequence zero with a zero predecessor and advances in order", () => {
    const chain = new SenderChain(ALICE_PUBLIC);
    const first = signedReady(ALICE_SECRET, ALICE_PUBLIC, 0, ZERO_HASH, "first");
    const firstResult = chain.ingest(first);
    const second = signedReady(ALICE_SECRET, ALICE_PUBLIC, 1, first.hash, "second");
    const secondResult = chain.ingest(second);

    expect(firstResult).toMatchObject({ status: "accepted", head: { seq: 0 } });
    expect(secondResult).toMatchObject({ status: "accepted", head: { seq: 1 } });
    expect(chain.size).toBe(2);
    expect(chain.head).toMatchObject({ seq: 1, hash: second.hash });
    expect(chain.get(0)).toBe(first);
  });

  it("classifies an identical retransmission as a duplicate", () => {
    const chain = new SenderChain(ALICE_PUBLIC);
    const first = signedReady(ALICE_SECRET, ALICE_PUBLIC, 0, ZERO_HASH, "same");

    expect(chain.ingest(first).status).toBe("accepted");
    expect(chain.ingest(first)).toMatchObject({ status: "duplicate", existing: first });
    expect(chain.size).toBe(1);
  });

  it("returns self-certifying evidence for equal sequence numbers with different hashes", () => {
    const chain = new SenderChain(ALICE_PUBLIC);
    const first = signedReady(ALICE_SECRET, ALICE_PUBLIC, 0, ZERO_HASH, "left");
    const conflicting = signedReady(ALICE_SECRET, ALICE_PUBLIC, 0, ZERO_HASH, "right");

    chain.ingest(first);
    const result = chain.ingest(conflicting);

    expect(result).toMatchObject({
      status: "rejected",
      reason: "equivocation",
      existing: first,
      received: conflicting,
    });
    expect(chain.head).toMatchObject({ seq: 0, hash: first.hash });
  });

  it("reports a sequence gap without advancing", () => {
    const chain = new SenderChain(ALICE_PUBLIC);
    const gap = signedReady(ALICE_SECRET, ALICE_PUBLIC, 2, ZERO_HASH, "gap");

    expect(chain.ingest(gap)).toMatchObject({
      status: "rejected",
      reason: "gap",
      expectedSeq: 0,
      actualSeq: 2,
    });
    expect(chain.head).toBeNull();
    expect(chain.size).toBe(0);
  });

  it("reports a broken predecessor without advancing", () => {
    const chain = new SenderChain(ALICE_PUBLIC);
    const wrongPrev = parseHash256(new Uint8Array(32).fill(1));
    const first = signedReady(ALICE_SECRET, ALICE_PUBLIC, 0, wrongPrev, "broken");

    expect(chain.ingest(first)).toMatchObject({
      status: "rejected",
      reason: "broken_prev",
      expectedPrev: ZERO_HASH,
      actualPrev: wrongPrev,
    });
    expect(chain.head).toBeNull();
  });

  it("rejects a valid artifact authored by another sender", () => {
    const chain = new SenderChain(ALICE_PUBLIC);
    const fromBob = signedReady(BOB_SECRET, BOB_PUBLIC, 0, ZERO_HASH, "bob");

    expect(chain.ingest(fromBob)).toMatchObject({
      status: "rejected",
      reason: "wrong_sender",
      expected: ALICE_PUBLIC,
      actual: BOB_PUBLIC,
    });
    expect(chain.head).toBeNull();
  });

  it("can accept the missing next envelope after rejecting a future one", () => {
    const chain = new SenderChain(ALICE_PUBLIC);
    const first = signedReady(ALICE_SECRET, ALICE_PUBLIC, 0, ZERO_HASH, "first");
    const future = signedReady(ALICE_SECRET, ALICE_PUBLIC, 2, first.hash, "future");

    chain.ingest(first);
    expect(chain.ingest(future)).toMatchObject({ status: "rejected", reason: "gap" });

    const second = signedReady(ALICE_SECRET, ALICE_PUBLIC, 1, first.hash, "second");
    expect(chain.ingest(second)).toMatchObject({ status: "accepted", head: { seq: 1 } });
  });

  it("keeps defensive sender and head hashes for future validation", () => {
    const senderInput = parseIdentityPublicKey(ALICE_PUBLIC);
    const chain = new SenderChain(senderInput);
    const first = signedReady(ALICE_SECRET, ALICE_PUBLIC, 0, ZERO_HASH, "first");
    const stableFirstHash = parseHash256(first.hash);

    chain.ingest(first);
    senderInput[0] = 0;
    first.hash[0] = first.hash[0]! ^ 1;
    const exposedHead = chain.head;
    if (exposedHead === null) {
      throw new Error("Expected an accepted chain head");
    }
    exposedHead.hash[0] = exposedHead.hash[0]! ^ 1;

    const second = signedReady(ALICE_SECRET, ALICE_PUBLIC, 1, stableFirstHash, "second");
    expect(chain.ingest(second)).toMatchObject({ status: "accepted", head: { seq: 1 } });
  });
});

function signedReady(
  secretKey: Ed25519SecretKey,
  publicKey: IdentityPublicKey,
  seq: number,
  prev: Hash256,
  marker: string,
): EnvelopeArtifact {
  const envelope: UnsignedEnvelope = {
    v: 1,
    game: GAME_ID,
    from: publicKey,
    seq,
    prev: parseHash256(prev),
    round: 0,
    phase: "lobby",
    type: "READY",
    body: { marker },
  };
  return signEnvelope(envelope, secretKey);
}
