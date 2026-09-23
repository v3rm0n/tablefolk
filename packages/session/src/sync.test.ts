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
} from "@p2pcards/encoding";
import {
  decodeAndVerifyEnvelope,
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  signEnvelope,
  type EnvelopeArtifact,
  type GameId,
  type Hash256,
  type IdentityPublicKey,
  type SyncRequestBody,
  type SyncResponseBody,
  type UnsignedEnvelope,
} from "@p2pcards/protocol";
import { describe, expect, it, vi } from "vitest";

import { SessionChainRegistry } from "./chain-registry";
import {
  applySyncResponse,
  DEFAULT_MAX_SYNC_RANGE_ENVELOPES,
  DEFAULT_MAX_SYNC_RESPONSE_BYTES,
  preflightSyncResponse,
  serveSyncRequest,
  type SyncResponseLimits,
} from "./sync";

interface Identity {
  readonly secret: Ed25519SecretKey;
  readonly publicKey: IdentityPublicKey;
}

const GAME_ID = parseGameId(new Uint8Array(16).fill(0x21));
const OTHER_GAME_ID = parseGameId(new Uint8Array(16).fill(0x22));
const ZERO_HASH = parseHash256(new Uint8Array(32));
const IDENTITIES = [1, 2, 3, 4].map(identity);

describe("session synchronization", () => {
  it("serves and applies a complete inclusive range", () => {
    const source = registry();
    const target = registry();
    const artifacts = appendChain(source, IDENTITIES[0]!, GAME_ID, ["zero", "one", "two"]);
    const request = syncRequest(IDENTITIES[0]!.publicKey, 0, 2);
    const served = serveSyncRequest(source, request);
    if (served.status !== "complete") {
      throw new Error("Expected a complete source range");
    }

    const applied = applySyncResponse(target, request, served.body);

    expect(applied).toMatchObject({
      status: "applied",
      results: [{ status: "accepted" }, { status: "accepted" }, { status: "accepted" }],
    });
    expect(target.heads()).toMatchObject([{ seq: 2, hash: artifacts[2]!.hash }]);
  });

  it("classifies replayed synchronization records as duplicates", () => {
    const source = registry();
    const target = registry();
    appendChain(source, IDENTITIES[0]!, GAME_ID, ["zero", "one"]);
    const request = syncRequest(IDENTITIES[0]!.publicKey, 0, 1);
    const served = serveSyncRequest(source, request);
    if (served.status !== "complete") {
      throw new Error("Expected a complete source range");
    }
    applySyncResponse(target, request, served.body);

    expect(applySyncResponse(target, request, served.body)).toMatchObject({
      status: "applied",
      results: [{ status: "duplicate" }, { status: "duplicate" }],
    });
  });

  it("surfaces signed equivocation for a requested known sequence", () => {
    const target = registry();
    const existing = signedReady(IDENTITIES[0]!, GAME_ID, 0, ZERO_HASH, "left");
    const conflicting = signedReady(IDENTITIES[0]!, GAME_ID, 0, ZERO_HASH, "right");
    target.ingest(existing);

    expect(
      applySyncResponse(target, syncRequest(IDENTITIES[0]!.publicKey, 0, 0), {
        envelopes: [conflicting],
      }),
    ).toMatchObject({
      status: "applied",
      results: [
        {
          status: "rejected",
          reason: "equivocation",
          existing,
          received: conflicting,
        },
      ],
    });
  });

  it("preflights every artifact before advancing a valid prefix", () => {
    const target = registry();
    const first = signedReady(IDENTITIES[0]!, GAME_ID, 0, ZERO_HASH, "valid");
    const wrongSender = signedReady(IDENTITIES[1]!, GAME_ID, 1, first.hash, "wrong sender");

    expect(
      applySyncResponse(target, syncRequest(IDENTITIES[0]!.publicKey, 0, 1), {
        envelopes: [first, wrongSender],
      }),
    ).toEqual({ status: "rejected", reason: "wrong_sender", index: 1 });
    expect(target.heads()).toEqual([]);
  });

  it("rejects wrong game, sequence, count, and request sender", () => {
    const target = registry();
    const wrongGame = signedReady(IDENTITIES[0]!, OTHER_GAME_ID, 0, ZERO_HASH, "wrong game");
    const sequenceOne = signedReady(IDENTITIES[0]!, GAME_ID, 1, ZERO_HASH, "wrong sequence");

    expect(
      applySyncResponse(target, syncRequest(IDENTITIES[0]!.publicKey, 0, 0), {
        envelopes: [wrongGame],
      }),
    ).toEqual({ status: "rejected", reason: "wrong_game", index: 0 });
    expect(
      applySyncResponse(target, syncRequest(IDENTITIES[0]!.publicKey, 0, 0), {
        envelopes: [sequenceOne],
      }),
    ).toEqual({ status: "rejected", reason: "wrong_sequence", index: 0 });
    expect(
      applySyncResponse(target, syncRequest(IDENTITIES[0]!.publicKey, 0, 1), {
        envelopes: [sequenceOne],
      }),
    ).toEqual({ status: "rejected", reason: "wrong_count", expectedCount: 2, actualCount: 1 });
    expect(
      applySyncResponse(target, syncRequest(IDENTITIES[3]!.publicKey, 0, 0), {
        envelopes: [sequenceOne],
      }),
    ).toEqual({ status: "rejected", reason: "unknown_sender" });
  });

  it("reports missing and unknown ranges without constructing a response", () => {
    const source = registry();
    appendChain(source, IDENTITIES[0]!, GAME_ID, ["zero"]);

    expect(serveSyncRequest(source, syncRequest(IDENTITIES[0]!.publicKey, 0, 1))).toEqual({
      status: "missing",
      firstMissingSeq: 1,
    });
    expect(serveSyncRequest(source, syncRequest(IDENTITIES[3]!.publicKey, 0, 0))).toEqual({
      status: "unknown_sender",
    });
  });

  it("bounds served ranges before reading the registry", () => {
    const source = registry();
    const readRange = vi.spyOn(source, "readRange");

    expect(() => serveSyncRequest(source, syncRequest(IDENTITIES[0]!.publicKey, 0, 128)))
      .toThrow(RangeError);
    expect(() => serveSyncRequest(
      source,
      syncRequest(IDENTITIES[0]!.publicKey, 0, Number.MAX_SAFE_INTEGER),
    )).toThrow(RangeError);
    expect(readRange).not.toHaveBeenCalled();
    expect(serveSyncRequest(source, syncRequest(IDENTITIES[0]!.publicKey, 0, 127))).toEqual({
      status: "missing",
      firstMissingSeq: 0,
    });
  });

  it("bounds served bytes and re-verifies source artifacts before exposing them", () => {
    const source = registry();
    const large = signedReady(IDENTITIES[0]!, GAME_ID, 0, ZERO_HASH, "x".repeat(DEFAULT_MAX_SYNC_RESPONSE_BYTES));
    source.ingest(large);
    expect(() => serveSyncRequest(source, syncRequest(IDENTITIES[0]!.publicKey, 0, 0))).toThrow(/byte limit/);

    const corrupted = registry();
    const first = appendChain(corrupted, IDENTITIES[0]!, GAME_ID, ["first"])[0]!;
    first.canonicalBytes.fill(0xff);
    expect(() => serveSyncRequest(corrupted, syncRequest(IDENTITIES[0]!.publicKey, 0, 0))).toThrow(/source range is invalid/);
  });

  it("serves independent snapshots rather than aliases of accepted source artifacts", () => {
    const source = registry();
    const original = appendChain(source, IDENTITIES[0]!, GAME_ID, ["stable"])[0]!;
    const served = serveSyncRequest(source, syncRequest(IDENTITIES[0]!.publicKey, 0, 0));
    if (served.status !== "complete") {
      throw new Error("Expected a complete source range");
    }
    served.body.envelopes[0]!.canonicalBytes.fill(0xff);
    served.body.envelopes[0]!.hash.fill(0xff);
    expect(decodeAndVerifyEnvelope(original.canonicalBytes).hash).toEqual(original.hash);
    expect(serveSyncRequest(source, syncRequest(IDENTITIES[0]!.publicKey, 0, 0)).status).toBe("complete");
  });

  it("retains in-memory chain rejections after a valid preflight", () => {
    const target = registry();
    const first = signedReady(IDENTITIES[0]!, GAME_ID, 1, ZERO_HASH, "gap");
    const second = signedReady(IDENTITIES[0]!, GAME_ID, 2, first.hash, "linked gap");

    expect(applySyncResponse(target, syncRequest(IDENTITIES[0]!.publicKey, 1, 2), {
      envelopes: [first, second],
    })).toMatchObject({
      status: "applied",
      results: [{ status: "rejected", reason: "gap" }, { status: "rejected", reason: "gap" }],
    });
    const brokenStart = signedReady(IDENTITIES[0]!, GAME_ID, 0, first.hash, "broken start");
    expect(applySyncResponse(target, syncRequest(IDENTITIES[0]!.publicKey, 0, 0), {
      envelopes: [brokenStart],
    })).toMatchObject({
      status: "applied",
      results: [{ status: "rejected", reason: "broken_prev" }],
    });
    expect(target.heads()).toEqual([]);
  });

  it("leaves a known-sequence conflict with a different predecessor for equivocation classification", () => {
    const target = registry();
    appendChain(target, IDENTITIES[0]!, GAME_ID, ["zero", "one"]);
    const conflict = signedReady(IDENTITIES[0]!, GAME_ID, 1, ZERO_HASH, "conflict");
    const request = syncRequest(IDENTITIES[0]!.publicKey, 1, 1);

    expect(preflightSyncResponse(target, request, { envelopes: [conflict] }).status).toBe("valid");
    expect(applySyncResponse(target, request, { envelopes: [conflict] })).toMatchObject({
      status: "applied",
      results: [{ status: "rejected", reason: "equivocation" }],
    });
  });

  it("snapshots the entire batch before the first ingestion", () => {
    const target = registry();
    const first = signedReady(IDENTITIES[0]!, GAME_ID, 0, ZERO_HASH, "zero");
    const second = signedReady(IDENTITIES[0]!, GAME_ID, 1, first.hash, "one");
    const savedSecond = decodeAndVerifyEnvelope(second.canonicalBytes);
    const envelopes = [first, second];
    const ingest = target.ingest.bind(target);
    vi.spyOn(target, "ingest").mockImplementation((artifact) => {
      second.canonicalBytes.fill(0);
      second.hash.fill(0);
      envelopes[1] = first;
      return ingest(artifact);
    });

    expect(applySyncResponse(target, syncRequest(IDENTITIES[0]!.publicKey, 0, 1), {
      envelopes,
    })).toMatchObject({
      status: "applied",
      results: [{ status: "accepted" }, { status: "accepted" }],
    });
    expect(target.readRange(IDENTITIES[0]!.publicKey, 1, 1)).toEqual({
      status: "complete",
      envelopes: [savedSecond],
    });
  });
});

describe("sync response preflight", () => {
  it("returns a normalized defensive snapshot without advancing any chain", () => {
    const target = registry();
    const first = signedReady(IDENTITIES[0]!, GAME_ID, 0, ZERO_HASH, "zero");
    const saved = decodeAndVerifyEnvelope(first.canonicalBytes);
    const request = {
      from: parseIdentityPublicKey(IDENTITIES[0]!.publicKey),
      fromSeq: 0,
      toSeq: 0,
      extra: true,
    };
    const envelopes = [first];
    const result = preflightSyncResponse(target, request, { envelopes });

    expect(result).toEqual({
      status: "valid",
      request: syncRequest(IDENTITIES[0]!.publicKey, 0, 0),
      response: { envelopes: [saved] },
    });
    if (result.status !== "valid") {
      throw new Error("Expected a valid preflight");
    }
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.request)).toBe(true);
    expect(Object.isFrozen(result.response)).toBe(true);
    expect(Object.isFrozen(result.response.envelopes)).toBe(true);
    request.from.fill(0);
    request.fromSeq = 10;
    first.canonicalBytes.fill(0);
    first.hash.fill(0);
    first.envelope.from.fill(0);
    envelopes.length = 0;
    expect(result.request).toEqual(syncRequest(IDENTITIES[0]!.publicKey, 0, 0));
    expect(result.response.envelopes).toEqual([saved]);
    expect(target.heads()).toEqual([]);
  });

  it("does not alias registry artifacts, including nested body bytes", () => {
    const target = registry();
    const original = signEnvelope({
      ...signedReady(IDENTITIES[0]!, GAME_ID, 0, ZERO_HASH, "zero").envelope,
      body: { nested: { payload: new Uint8Array([1, 2, 3]) } },
    }, IDENTITIES[0]!.secret);
    target.ingest(original);
    const saved = decodeAndVerifyEnvelope(original.canonicalBytes);
    const request = syncRequest(parseIdentityPublicKey(IDENTITIES[0]!.publicKey), 0, 0);
    const result = preflightSyncResponse(target, request, { envelopes: [original] });
    if (result.status !== "valid") {
      throw new Error("Expected a valid preflight");
    }

    const copy = result.response.envelopes[0]!;
    expect(copy).not.toBe(original);
    copy.canonicalBytes.fill(0);
    copy.hash.fill(0);
    copy.envelope.game.fill(0);
    copy.envelope.from.fill(0);
    copy.envelope.prev.fill(1);
    copy.envelope.sig.fill(0);
    const nested = (copy.envelope.body as CborMap)["nested"] as CborMap;
    (nested["payload"] as Uint8Array).fill(0);
    result.request.from.fill(0);

    expect(request.from).toEqual(IDENTITIES[0]!.publicKey);
    expect(original).toEqual(saved);
    expect(target.readRange(IDENTITIES[0]!.publicKey, 0, 0)).toEqual({
      status: "complete",
      envelopes: [saved],
    });
  });

  it("never reads misleading envelope or hash views", () => {
    const target = registry();
    const artifacts = appendChain(registry(), IDENTITIES[0]!, GAME_ID, ["zero", "one"]);
    const candidates = artifacts.map((artifact) => ({
      ...artifact,
      get envelope(): never { throw new Error("Untrusted envelope view"); },
      get hash(): never { throw new Error("Untrusted hash view"); },
    }));

    expect(applySyncResponse(target, syncRequest(IDENTITIES[0]!.publicKey, 0, 1), {
      envelopes: candidates,
    })).toMatchObject({
      status: "applied",
      results: [{ status: "accepted" }, { status: "accepted" }],
    });
    expect(target.readRange(IDENTITIES[0]!.publicKey, 0, 1)).toEqual({
      status: "complete",
      envelopes: artifacts,
    });
  });

  it.each([
    { reason: "wrong_game", game: OTHER_GAME_ID, author: IDENTITIES[0]!, seq: 1 },
    { reason: "wrong_sender", game: GAME_ID, author: IDENTITIES[1]!, seq: 1 },
    { reason: "wrong_sequence", game: GAME_ID, author: IDENTITIES[0]!, seq: 2 },
  ])("checks canonical metadata despite a valid-looking view: $reason", ({ reason, game, author, seq }) => {
    const target = registry();
    const first = signedReady(IDENTITIES[0]!, GAME_ID, 0, ZERO_HASH, "zero");
    const facade = signedReady(IDENTITIES[0]!, GAME_ID, 1, first.hash, "one");
    const actual = signedReady(author, game, seq, first.hash, "wrong metadata");

    expect(applySyncResponse(target, syncRequest(IDENTITIES[0]!.publicKey, 0, 1), {
      envelopes: [first, withBytes(facade, actual.canonicalBytes)],
    })).toEqual({ status: "rejected", reason, index: 1 });
    expect(target.heads()).toEqual([]);
  });

  it.each(["signature", "body", "noncanonical", "trailing", "malformed"] as const)(
    "rejects %s tampering in the tail without ingesting a prefix",
    (variant) => {
      const target = registry();
      const first = signedReady(IDENTITIES[0]!, GAME_ID, 0, ZERO_HASH, "zero");
      const second = signedReady(IDENTITIES[0]!, GAME_ID, 1, first.hash, "one");
      const decoded = decodeCanonical(second.canonicalBytes) as CborMap;
      expect(second.canonicalBytes[0]).toBe(0xaa);
      const variants = {
        signature: encodeCanonical({ ...decoded, sig: new Uint8Array(64) }),
        body: encodeCanonical({ ...decoded, body: { marker: "unsigned modification" } }),
        noncanonical: new Uint8Array([0xb8, 10, ...second.canonicalBytes.subarray(1)]),
        trailing: new Uint8Array([...second.canonicalBytes, 0]),
        malformed: new Uint8Array([0xff]),
      };

      expect(applySyncResponse(target, syncRequest(IDENTITIES[0]!.publicKey, 0, 1), {
        envelopes: [first, withBytes(second, variants[variant])],
      })).toEqual({ status: "rejected", reason: "invalid_artifact", index: 1 });
      expect(target.heads()).toEqual([]);
    },
  );

  it("rejects broken internal links using reverified hashes, not claimed hash views", () => {
    const target = registry();
    const first = signedReady(IDENTITIES[0]!, GAME_ID, 0, ZERO_HASH, "zero");
    const second = signedReady(IDENTITIES[0]!, GAME_ID, 1, ZERO_HASH, "broken link");

    expect(applySyncResponse(target, syncRequest(IDENTITIES[0]!.publicKey, 0, 1), {
      envelopes: [{ ...first, hash: ZERO_HASH }, second],
    })).toEqual({ status: "rejected", reason: "broken_prev", index: 1 });
    expect(target.heads()).toEqual([]);
  });

  it("checks every internal link, not only the first pair", () => {
    const target = registry();
    const prefix = appendChain(registry(), IDENTITIES[0]!, GAME_ID, ["zero", "one"]);
    const third = signedReady(IDENTITIES[0]!, GAME_ID, 2, prefix[0]!.hash, "broken tail");

    expect(applySyncResponse(target, syncRequest(IDENTITIES[0]!.publicKey, 0, 2), {
      envelopes: [...prefix, third],
    })).toEqual({ status: "rejected", reason: "broken_prev", index: 2 });
    expect(target.heads()).toEqual([]);
  });

  it("rejects malformed artifact entries and sparse responses", () => {
    const target = registry();
    const first = signedReady(IDENTITIES[0]!, GAME_ID, 0, ZERO_HASH, "zero");
    const candidates: unknown[] = [
      undefined,
      null,
      { canonicalBytes: "not bytes" },
      { canonicalBytes: new Uint16Array(4) },
      { get canonicalBytes() { throw new Error("Unreadable bytes"); } },
    ];
    for (const candidate of candidates) {
      expect(applySyncResponse(target, syncRequest(IDENTITIES[0]!.publicKey, 0, 1), {
        envelopes: [first, candidate as EnvelopeArtifact],
      })).toEqual({ status: "rejected", reason: "invalid_artifact", index: 1 });
    }
    const sparse = [first];
    sparse.length = 2;
    expect(preflightSyncResponse(target, syncRequest(IDENTITIES[0]!.publicKey, 0, 1), {
      envelopes: sparse,
    })).toEqual({ status: "rejected", reason: "invalid_artifact", index: 1 });
    expect(target.heads()).toEqual([]);
  });

  it("enforces default count and request-span bounds before inspecting artifacts", () => {
    expect(DEFAULT_MAX_SYNC_RANGE_ENVELOPES).toBe(128);
    const target = registry();
    const unreadable = {
      get envelopes(): never { throw new Error("Range must be checked first"); },
    } as SyncResponseBody;
    for (const toSeq of [128, Number.MAX_SAFE_INTEGER]) {
      expect(preflightSyncResponse(target, syncRequest(IDENTITIES[0]!.publicKey, 0, toSeq), unreadable))
        .toEqual({ status: "rejected", reason: "limit_exceeded" });
    }
    const envelopes = new Array<EnvelopeArtifact>(129);
    expect(preflightSyncResponse(target, syncRequest(IDENTITIES[0]!.publicKey, 0, 0), { envelopes }))
      .toEqual({ status: "rejected", reason: "limit_exceeded" });
    expect(preflightSyncResponse(target, syncRequest(IDENTITIES[0]!.publicKey, 0, 127), {
      envelopes: [],
    })).toEqual({ status: "rejected", reason: "wrong_count", expectedCount: 128, actualCount: 0 });
  });

  it("bounds the total bytes before verifying even the first artifact", () => {
    expect(DEFAULT_MAX_SYNC_RESPONSE_BYTES).toBe(4 * 1024 * 1024);
    const target = registry();
    const artifact = signedReady(IDENTITIES[0]!, GAME_ID, 0, ZERO_HASH, "zero");
    const envelopes = [
      withBytes(artifact, new Uint8Array([0xff])),
      withBytes(artifact, new Uint8Array(DEFAULT_MAX_SYNC_RESPONSE_BYTES)),
    ];

    expect(applySyncResponse(target, syncRequest(IDENTITIES[0]!.publicKey, 0, 1), { envelopes }))
      .toEqual({ status: "rejected", reason: "limit_exceeded" });
    expect(preflightSyncResponse(target, syncRequest(IDENTITIES[0]!.publicKey, 0, 0), {
      envelopes: [withBytes(artifact, new Uint8Array(DEFAULT_MAX_SYNC_RESPONSE_BYTES + 1))],
    })).toEqual({ status: "rejected", reason: "limit_exceeded" });
    expect(target.heads()).toEqual([]);
  });

  it("accepts exact custom count/aggregate-byte limits and rejects either excess", () => {
    const target = registry();
    const envelopes = appendChain(registry(), IDENTITIES[0]!, GAME_ID, ["zero", "one"]);
    const maxBytes = envelopes.reduce((sum, artifact) => sum + artifact.canonicalBytes.byteLength, 0);
    const request = syncRequest(IDENTITIES[0]!.publicKey, 0, 1);

    expect(preflightSyncResponse(target, request, { envelopes }, { maxEnvelopes: 2, maxBytes }).status)
      .toBe("valid");
    expect(preflightSyncResponse(target, request, { envelopes }, { maxEnvelopes: 1, maxBytes }))
      .toEqual({ status: "rejected", reason: "limit_exceeded" });
    expect(preflightSyncResponse(target, request, { envelopes }, { maxEnvelopes: 2, maxBytes: maxBytes - 1 }))
      .toEqual({ status: "rejected", reason: "limit_exceeded" });
  });

  it("uses safe inclusive arithmetic at MAX_SAFE_INTEGER", () => {
    const target = registry();
    const max = Number.MAX_SAFE_INTEGER;
    const first = signedReady(IDENTITIES[0]!, GAME_ID, max - 1, ZERO_HASH, "penultimate");
    const last = signedReady(IDENTITIES[0]!, GAME_ID, max, first.hash, "last");

    expect(preflightSyncResponse(target, syncRequest(IDENTITIES[0]!.publicKey, max - 1, max), {
      envelopes: [first, last],
    }).status).toBe("valid");
    expect(preflightSyncResponse(target, syncRequest(IDENTITIES[0]!.publicKey, max, max), {
      envelopes: [last],
    }).status).toBe("valid");
    expect(preflightSyncResponse(target, syncRequest(IDENTITIES[0]!.publicKey, 0, max), {
      envelopes: [],
    }, { maxEnvelopes: max })).toEqual({ status: "rejected", reason: "limit_exceeded" });
    expect(preflightSyncResponse(target, syncRequest(IDENTITIES[0]!.publicKey, 0, max - 1), {
      envelopes: [],
    }, { maxEnvelopes: max })).toEqual({
      status: "rejected", reason: "wrong_count", expectedCount: max, actualCount: 0,
    });
  });

  it.each([0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, null, "128"])(
    "rejects invalid limits: %s",
    (value) => {
      for (const field of ["maxEnvelopes", "maxBytes"]) {
        expect(() => preflightSyncResponse(
          registry(),
          syncRequest(IDENTITIES[0]!.publicKey, 0, 0),
          { envelopes: [] },
          { [field]: value } as SyncResponseLimits,
        )).toThrow(RangeError);
      }
    },
  );

  it.each([
    [-1, 0], [0.5, 1], [NaN, 1], [0, Infinity], [0, Number.MAX_SAFE_INTEGER + 1], [1, 0],
  ])("rejects malformed request sequences %s..%s", (fromSeq, toSeq) => {
    expect(() => preflightSyncResponse(
      registry(), syncRequest(IDENTITIES[0]!.publicKey, fromSeq, toSeq), { envelopes: [] },
    )).toThrow(RangeError);
  });
});

function withBytes(artifact: EnvelopeArtifact, bytes: Uint8Array): EnvelopeArtifact {
  return { ...artifact, canonicalBytes: bytes as CanonicalCbor };
}

function registry(): SessionChainRegistry {
  return new SessionChainRegistry(
    GAME_ID,
    IDENTITIES.slice(0, 3).map(({ publicKey }) => publicKey),
  );
}

function appendChain(
  target: SessionChainRegistry,
  author: Identity,
  gameId: GameId,
  markers: readonly string[],
): readonly EnvelopeArtifact[] {
  const artifacts: EnvelopeArtifact[] = [];
  let prev = ZERO_HASH;
  for (const [seq, marker] of markers.entries()) {
    const artifact = signedReady(author, gameId, seq, prev, marker);
    target.ingest(artifact);
    artifacts.push(artifact);
    prev = artifact.hash;
  }
  return artifacts;
}

function signedReady(
  author: Identity,
  gameId: GameId,
  seq: number,
  prev: Hash256,
  marker: string,
): EnvelopeArtifact {
  const envelope: UnsignedEnvelope = {
    v: 1,
    game: gameId,
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

function syncRequest(
  from: IdentityPublicKey,
  fromSeq: number,
  toSeq: number,
): SyncRequestBody {
  return { from, fromSeq, toSeq };
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
