import {
  deriveEd25519PublicKey,
  importEd25519SecretKey,
  type Ed25519SecretKey,
} from "@p2pcards/crypto";
import {
  ENVELOPE_MESSAGE_TYPES,
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  signEnvelope,
  type EnvelopeArtifact,
  type Hash256,
  type IdentityPublicKey,
  type UnsignedEnvelope,
  type WitnessBody,
} from "@p2pcards/protocol";
import { describe, expect, it } from "vitest";

import { SessionChainRegistry } from "./chain-registry";
import {
  assessWitness,
  currentWitnessBody,
  HOUSEKEEPING_ENVELOPE_TYPES,
  shouldEmitImmediateWitness,
} from "./witness";

interface Identity {
  readonly secret: Ed25519SecretKey;
  readonly publicKey: IdentityPublicKey;
}

const GAME_ID = parseGameId(new Uint8Array(16).fill(6));
const ZERO_HASH = parseHash256(new Uint8Array(32));
const IDENTITIES = [1, 2, 3, 4].map(identity);

describe("witness handling", () => {
  it("builds current heads in finalized seat order", () => {
    const registry = registryWithLocalMessages();
    const stateHash = parseHash256(new Uint8Array(32).fill(0x33));

    expect(currentWitnessBody(registry).heads.map(({ from, seq }) => ({ from, seq }))).toEqual([
      { from: IDENTITIES[0]!.publicKey, seq: 1 },
      { from: IDENTITIES[1]!.publicKey, seq: 0 },
    ]);
    expect(currentWitnessBody(registry, stateHash).stateHash).toEqual(stateHash);
  });

  it("classifies matching, stale, and missing ranges deterministically", () => {
    const registry = registryWithLocalMessages();
    const aliceZero = registry.readRange(IDENTITIES[0]!.publicKey, 0, 0);
    if (aliceZero.status !== "complete") {
      throw new Error("Expected Alice sequence zero");
    }
    const body: WitnessBody = {
      heads: [
        { from: IDENTITIES[0]!.publicKey, seq: 0, hash: aliceZero.envelopes[0]!.hash },
        { from: IDENTITIES[1]!.publicKey, seq: 2, hash: parseHash256(new Uint8Array(32).fill(8)) },
        { from: IDENTITIES[2]!.publicKey, seq: 0, hash: parseHash256(new Uint8Array(32).fill(9)) },
      ],
    };

    expect(assessWitness(registry, body)).toMatchObject({
      status: "assessed",
      outcomes: [
        { status: "stale", seat: 0 },
        { status: "need_sync", seat: 1, fromSeq: 1, toSeq: 2 },
        { status: "need_sync", seat: 2, fromSeq: 0, toSeq: 0 },
      ],
    });

    const current = currentWitnessBody(registry);
    expect(assessWitness(registry, current)).toMatchObject({
      status: "assessed",
      outcomes: [{ status: "matching", seat: 0 }, { status: "matching", seat: 1 }],
    });
  });

  it("returns the local signed artifact for a conflicting claim", () => {
    const registry = registryWithLocalMessages();
    const wrongHash = parseHash256(new Uint8Array(32).fill(0xff));
    const assessment = assessWitness(registry, {
      heads: [{ from: IDENTITIES[0]!.publicKey, seq: 0, hash: wrongHash }],
    });

    expect(assessment).toMatchObject({
      status: "assessed",
      outcomes: [
        {
          status: "conflict",
          seat: 0,
          claimed: { hash: wrongHash },
          fromSeq: 0,
          toSeq: 0,
        },
      ],
    });
    if (assessment.status !== "assessed" || assessment.outcomes[0]?.status !== "conflict") {
      throw new Error("Expected a conflict outcome");
    }
    expect(assessment.outcomes[0].local.envelope.seq).toBe(0);
  });

  it("rejects unknown, duplicate, and non-roster-ordered head lists", () => {
    const registry = registryWithLocalMessages();
    const head = currentWitnessBody(registry).heads[0]!;

    expect(
      assessWitness(registry, {
        heads: [{ ...head, from: IDENTITIES[3]!.publicKey }],
      }),
    ).toEqual({ status: "rejected", reason: "unknown_sender", index: 0 });
    expect(assessWitness(registry, { heads: [head, head] })).toEqual({
      status: "rejected",
      reason: "duplicate_sender",
      index: 1,
    });
    expect(
      assessWitness(registry, {
        heads: [currentWitnessBody(registry).heads[1]!, head],
      }),
    ).toEqual({ status: "rejected", reason: "non_roster_order", index: 1 });
  });

  it("suppresses immediate recursive witnesses for every housekeeping type", () => {
    expect(HOUSEKEEPING_ENVELOPE_TYPES).toEqual([
      "WITNESS",
      "SYNC_REQ",
      "SYNC_RESP",
      "TIMEOUT_VOTE",
      "VIOLATION",
    ]);
    for (const type of ENVELOPE_MESSAGE_TYPES) {
      expect(shouldEmitImmediateWitness(type)).toBe(!HOUSEKEEPING_ENVELOPE_TYPES.includes(type as never));
    }
    expect(shouldEmitImmediateWitness("KEY_SHARE")).toBe(true);
    expect(shouldEmitImmediateWitness("READY")).toBe(true);
  });
});

function registryWithLocalMessages(): SessionChainRegistry {
  const registry = new SessionChainRegistry(
    GAME_ID,
    IDENTITIES.slice(0, 3).map(({ publicKey }) => publicKey),
  );
  const aliceZero = signedReady(IDENTITIES[0]!, 0, ZERO_HASH, "alice-0");
  registry.ingest(aliceZero);
  registry.ingest(signedReady(IDENTITIES[0]!, 1, aliceZero.hash, "alice-1"));
  registry.ingest(signedReady(IDENTITIES[1]!, 0, ZERO_HASH, "bob-0"));
  return registry;
}

function identity(seed: number): Identity {
  const bytes = new Uint8Array(32);
  bytes[0] = seed;
  const secret = importEd25519SecretKey(bytes);
  return {
    secret,
    publicKey: parseIdentityPublicKey(deriveEd25519PublicKey(secret)),
  };
}

function signedReady(
  author: Identity,
  seq: number,
  prev: Hash256,
  marker: string,
): EnvelopeArtifact {
  const envelope: UnsignedEnvelope = {
    v: 1,
    game: GAME_ID,
    from: author.publicKey,
    seq,
    prev,
    round: 0,
    phase: "lobby",
    type: "READY",
    body: { marker },
  };
  return signEnvelope(envelope, author.secret);
}
