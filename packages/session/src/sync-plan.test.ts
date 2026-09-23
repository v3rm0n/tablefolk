import {
  deriveEd25519PublicKey,
  importEd25519SecretKey,
  type Ed25519SecretKey,
} from "@p2pcards/crypto";
import {
  decodeCanonical,
  encodeCanonical,
  type CanonicalCbor,
  type CborMap,
  type CborValue,
} from "@p2pcards/encoding";
import {
  decodeAndVerifyEnvelope,
  encodeWitnessBody,
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  signEnvelope,
  type EnvelopeArtifact,
  type IdentityPublicKey,
  type UnsignedEnvelope,
  type WitnessHead,
} from "@p2pcards/protocol";
import { describe, expect, it, vi } from "vitest";

import { SessionChainRegistry } from "./chain-registry";
import { DEFAULT_MAX_SYNC_RANGE_ENVELOPES, DEFAULT_MAX_SYNC_RESPONSE_BYTES } from "./sync";
import { planWitnessSyncRequests } from "./sync-plan";

interface Identity {
  readonly secret: Ed25519SecretKey;
  readonly publicKey: IdentityPublicKey;
}

const GAME_ID = parseGameId(new Uint8Array(16).fill(0x31));
const ZERO_HASH = parseHash256(new Uint8Array(32));
const IDENTITIES = [1, 2, 3, 4].map(identity);

describe("witness sync planning", () => {
  it("plans one next inclusive range per claimed sender in roster order, including conflicts", () => {
    const target = registry();
    const bob = ready(1);
    const alice = ready(0);
    target.ingest(bob);
    target.ingest(alice);
    const aliceOne = ready(0, { seq: 1, prev: alice.hash });
    target.ingest(aliceOne);
    const witness = signedWitness(encodeWitnessBody({
      heads: [claim(0, 10), claim(1, 0), claim(2, 2)],
    }));
    target.ingest(witness);
    const before = target.heads();

    expect(planWitnessSyncRequests(target, witness, 3)).toEqual({
      status: "planned",
      requests: [
        { from: IDENTITIES[0]!.publicKey, fromSeq: 2, toSeq: 4 },
        { from: IDENTITIES[1]!.publicKey, fromSeq: 0, toSeq: 0 },
        { from: IDENTITIES[2]!.publicKey, fromSeq: 1, toSeq: 2 },
      ],
    });
    expect(target.heads()).toEqual(before);
  });

  it("caps giant claimed heads to one default page each instead of expanding page lists", () => {
    const target = registry();
    const witness = signedWitness(encodeWitnessBody({
      heads: [claim(0, Number.MAX_SAFE_INTEGER), claim(1, Number.MAX_SAFE_INTEGER)],
    }));
    target.ingest(witness);

    expect(planWitnessSyncRequests(target, witness)).toEqual({
      status: "planned",
      requests: [
        { from: IDENTITIES[0]!.publicKey, fromSeq: 0, toSeq: DEFAULT_MAX_SYNC_RANGE_ENVELOPES - 1 },
        { from: IDENTITIES[1]!.publicKey, fromSeq: 0, toSeq: DEFAULT_MAX_SYNC_RANGE_ENVELOPES - 1 },
      ],
    });
    expect(planWitnessSyncRequests(target, witness, 1)).toEqual({
      status: "planned",
      requests: [
        { from: IDENTITIES[0]!.publicKey, fromSeq: 0, toSeq: 0 },
        { from: IDENTITIES[1]!.publicKey, fromSeq: 0, toSeq: 0 },
      ],
    });
    expect(planWitnessSyncRequests(target, witness, Number.MAX_SAFE_INTEGER)).toEqual({
      status: "planned",
      requests: [
        { from: IDENTITIES[0]!.publicKey, fromSeq: 0, toSeq: Number.MAX_SAFE_INTEGER - 1 },
        { from: IDENTITIES[1]!.publicKey, fromSeq: 0, toSeq: Number.MAX_SAFE_INTEGER - 1 },
      ],
    });
  });

  it.each([1, 2, 129])("safely caps a next range with a head %s below MAX_SAFE_INTEGER", (distance) => {
    const target = registry();
    const max = Number.MAX_SAFE_INTEGER;
    const witness = signedWitness(encodeWitnessBody({ heads: [claim(0, max)] }));
    target.ingest(witness);
    // Model an extreme local head without allocating an impossibly large chain fixture.
    vi.spyOn(target, "heads").mockReturnValue([
      { from: IDENTITIES[0]!.publicKey, seq: max - distance, hash: ZERO_HASH },
      ...target.heads(),
    ]);

    expect(planWitnessSyncRequests(target, witness)).toEqual({
      status: "planned",
      requests: [{
        from: IDENTITIES[0]!.publicKey,
        fromSeq: max - distance + 1,
        toSeq: distance > DEFAULT_MAX_SYNC_RANGE_ENVELOPES ? max - 1 : max,
      }],
    });
  });

  it.each([false, true])("handles a known MAX_SAFE_INTEGER claim (conflict: %s)", (conflict) => {
    const target = registry();
    const max = Number.MAX_SAFE_INTEGER;
    const local = ready(0, { seq: max });
    const witness = signedWitness(encodeWitnessBody({
      heads: [{ from: IDENTITIES[0]!.publicKey, seq: max, hash: conflict ? ZERO_HASH : local.hash }],
    }));
    target.ingest(witness);
    vi.spyOn(target, "heads").mockReturnValue([
      { from: IDENTITIES[0]!.publicKey, seq: max, hash: local.hash },
      ...target.heads(),
    ]);
    vi.spyOn(target, "readRange").mockReturnValue({ status: "complete", envelopes: [local] });

    expect(planWitnessSyncRequests(target, witness)).toEqual({
      status: "planned",
      requests: conflict ? [{ from: IDENTITIES[0]!.publicKey, fromSeq: max, toSeq: max }] : [],
    });
  });

  it("requires the exact outer to have been accepted, not merely be acceptable", () => {
    const target = registry();
    const witness = signedWitness(encodeWitnessBody({ heads: [claim(0, 5)] }));
    expect(target.classify(witness).status).toBe("accepted");
    expect(planWitnessSyncRequests(target, witness)).toEqual({
      status: "rejected", reason: "witness_not_accepted",
    });
    expect(target.heads()).toEqual([]);

    target.ingest(witness);
    expect(planWitnessSyncRequests(target, witness)).toEqual({
      status: "planned",
      requests: [{ from: IDENTITIES[0]!.publicKey, fromSeq: 0, toSeq: 5 }],
    });
  });

  it.each([
    { reason: "gap", seq: 2 },
    { reason: "broken_prev", seq: 1 },
    { reason: "equivocation", seq: 0 },
  ])("does not act on a $reason outer even with a misleading accepted hash", ({ reason, seq }) => {
    const target = registry();
    const accepted = signedWitness({ heads: [] });
    target.ingest(accepted);
    const witness = signedWitness(encodeWitnessBody({ heads: [claim(0, 5)] }), { seq });
    expect(target.classify(witness)).toMatchObject({ status: "rejected", reason });
    const before = target.heads();

    expect(planWitnessSyncRequests(target, { ...witness, hash: accepted.hash })).toEqual({
      status: "rejected", reason: "witness_not_accepted",
    });
    expect(target.heads()).toEqual(before);
  });

  it("rejects wrong-game and non-roster outer witnesses", () => {
    const target = registry();
    const wrongGame = signedWitness({ heads: [] }, { game: parseGameId(new Uint8Array(16)) });
    const unknownSender = signEnvelope({
      ...signedWitness({ heads: [] }).envelope,
      from: IDENTITIES[3]!.publicKey,
    }, IDENTITIES[3]!.secret);

    for (const witness of [wrongGame, unknownSender]) {
      expect(planWitnessSyncRequests(target, witness)).toEqual({
        status: "rejected", reason: "witness_not_accepted",
      });
    }
    expect(target.heads()).toEqual([]);
  });

  it("checks the canonical type, not a WITNESS-looking artifact view", () => {
    const target = registry();
    const artifact = ready(2, { body: { heads: [] } });
    target.ingest(artifact);

    expect(planWitnessSyncRequests(target, {
      ...artifact,
      envelope: { ...artifact.envelope, type: "WITNESS" },
    })).toEqual({ status: "rejected", reason: "wrong_type" });
  });

  it("uses only reverified canonical witness claims and identity", () => {
    const target = registry();
    const witness = signedWitness(encodeWitnessBody({ heads: [claim(0, 2)] }));
    target.ingest(witness);
    const misleading = {
      ...witness,
      get envelope(): never { throw new Error("Untrusted witness view"); },
      get hash(): never { throw new Error("Untrusted witness hash"); },
    };

    expect(planWitnessSyncRequests(target, misleading)).toEqual({
      status: "planned",
      requests: [{ from: IDENTITIES[0]!.publicKey, fromSeq: 0, toSeq: 2 }],
    });
  });

  it.each(["signature", "body", "noncanonical", "trailing"] as const)(
    "reverifies an accepted witness against %s tampering",
    (variant) => {
      const target = registry();
      const witness = signedWitness(encodeWitnessBody({ heads: [claim(0, 2)] }));
      target.ingest(witness);
      const decoded = decodeCanonical(witness.canonicalBytes) as CborMap;
      const variants = {
        signature: encodeCanonical({ ...decoded, sig: new Uint8Array(64) }),
        body: encodeCanonical({ ...decoded, body: { heads: [] } }),
        noncanonical: new Uint8Array([0xb8, 10, ...witness.canonicalBytes.subarray(1)]),
        trailing: new Uint8Array([...witness.canonicalBytes, 0]),
      };

      expect(planWitnessSyncRequests(target, {
        ...witness, canonicalBytes: variants[variant] as CanonicalCbor,
      })).toEqual({ status: "rejected", reason: "invalid_artifact" });
    },
  );

  it("bounds witness bytes before decoding or classifying the outer", () => {
    const target = registry();
    const classify = vi.spyOn(target, "classify");
    const witness = signedWitness({ heads: [] });

    expect(planWitnessSyncRequests(target, {
      ...witness,
      canonicalBytes: new Uint8Array(DEFAULT_MAX_SYNC_RESPONSE_BYTES + 1) as CanonicalCbor,
    })).toEqual({ status: "rejected", reason: "limit_exceeded" });
    expect(planWitnessSyncRequests(target, {
      ...witness,
      canonicalBytes: new Uint8Array(DEFAULT_MAX_SYNC_RESPONSE_BYTES) as CanonicalCbor,
    })).toEqual({ status: "rejected", reason: "invalid_artifact" });
    expect(classify).not.toHaveBeenCalled();
  });

  it("rejects unknown senders and non-roster order without returning a partial plan", () => {
    const cases = [
      { heads: [claim(0, 5), claim(3, 5)], reason: "unknown_sender" },
      { heads: [claim(1, 5), claim(0, 5)], reason: "non_roster_order" },
    ];
    for (const { heads, reason } of cases) {
      const target = registry();
      const witness = signedWitness(encodeWitnessBody({ heads }));
      target.ingest(witness);

      expect(planWitnessSyncRequests(target, witness)).toEqual({ status: "rejected", reason, index: 1 });
    }
  });

  it("strictly decodes the existing witness schema, including duplicate and oversized head lists", () => {
    const head = { from: IDENTITIES[0]!.publicKey, seq: 0, hash: ZERO_HASH };
    const bodies: CborValue[] = [
      { heads: [], extra: true },
      { heads: [], stateHash: ZERO_HASH },
      { heads: [], state_hash: new Uint8Array(31) },
      { heads: [head, head] },
      { heads: Array.from({ length: 9 }, () => head) },
      { heads: [{ ...head, seq: -1 }] },
      { heads: [{ ...head, from: new Uint8Array(31) }] },
      { heads: [{ ...head, extra: true }] },
      { heads: "not a list" },
    ];
    for (const body of bodies) {
      const target = registry();
      const witness = signedWitness(body);
      target.ingest(witness);

      expect(planWitnessSyncRequests(target, witness)).toEqual({
        status: "rejected", reason: "invalid_witness",
      });
    }
  });

  it.each(["empty", "partial matching", "partial stale"])(
    "%s witnesses return zero requests without any completion or readiness claim",
    (variant) => {
      const target = registry();
      const first = ready(0);
      target.ingest(first);
      if (variant === "partial stale") {
        target.ingest(ready(0, { seq: 1, prev: first.hash }));
      }
      const witness = signedWitness(encodeWitnessBody({
        heads: variant === "empty" ? [] : [{ from: first.envelope.from, seq: 0, hash: first.hash }],
        stateHash: ZERO_HASH,
      }));
      target.ingest(witness);

      expect(planWitnessSyncRequests(target, witness)).toEqual({ status: "planned", requests: [] });
      expect(target.readRange(IDENTITIES[1]!.publicKey, 0, 0).status).toBe("missing");
    },
  );

  it("isolates returned requests from input claims, registry artifacts, and other plans", () => {
    const target = registry();
    const witness = signedWitness(encodeWitnessBody({ heads: [claim(0, 5)] }));
    target.ingest(witness);
    const saved = decodeAndVerifyEnvelope(witness.canonicalBytes);
    const first = planWitnessSyncRequests(target, witness);
    const second = planWitnessSyncRequests(target, witness);
    if (first.status !== "planned" || second.status !== "planned") {
      throw new Error("Expected planned requests");
    }
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(first.requests)).toBe(true);
    expect(Object.isFrozen(first.requests[0])).toBe(true);
    first.requests[0]!.from.fill(0);
    expect(witness).toEqual(saved);
    expect(target.readRange(IDENTITIES[2]!.publicKey, 0, 0)).toEqual({
      status: "complete", envelopes: [saved],
    });

    witness.canonicalBytes.fill(0);
    witness.hash.fill(0);
    const heads = (witness.envelope.body as CborMap)["heads"] as CborMap[];
    (heads[0]!["from"] as Uint8Array).fill(0);
    expect(second).toEqual({
      status: "planned",
      requests: [{ from: IDENTITIES[0]!.publicKey, fromSeq: 0, toSeq: 5 }],
    });
  });

  it.each([0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1])(
    "rejects an invalid request page limit: %s",
    (limit) => {
      expect(() => planWitnessSyncRequests(registry(), signedWitness({ heads: [] }), limit))
        .toThrow(RangeError);
    },
  );
});

function registry(): SessionChainRegistry {
  return new SessionChainRegistry(GAME_ID, IDENTITIES.slice(0, 3).map(({ publicKey }) => publicKey));
}

function claim(seat: number, seq: number): WitnessHead {
  return { from: IDENTITIES[seat]!.publicKey, seq, hash: ZERO_HASH };
}

function signedWitness(body: CborValue, overrides: Partial<UnsignedEnvelope> = {}): EnvelopeArtifact {
  return ready(2, { type: "WITNESS", body, ...overrides });
}

function ready(seat: number, overrides: Partial<UnsignedEnvelope> = {}): EnvelopeArtifact {
  const author = IDENTITIES[seat]!;
  return signEnvelope({
    v: 1,
    game: GAME_ID,
    from: author.publicKey,
    seq: 0,
    prev: ZERO_HASH,
    round: 0,
    phase: "lobby",
    type: "READY",
    body: { marker: "ready" },
    ...overrides,
  }, author.secret);
}

function identity(seed: number): Identity {
  const bytes = new Uint8Array(32);
  bytes[0] = seed;
  const secret = importEd25519SecretKey(bytes);
  return { secret, publicKey: parseIdentityPublicKey(deriveEd25519PublicKey(secret)) };
}
