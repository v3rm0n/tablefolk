import {
  deriveEd25519PublicKey,
  importEd25519SecretKey,
  type Ed25519SecretKey,
} from "@p2pcards/crypto";
import type { CborValue } from "@p2pcards/encoding";
import {
  encodeJoinBody,
  encodeReadyBody,
  encodeRosterBody,
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  signEnvelope,
  type EnvelopeArtifact,
  type GameId,
  type Hash256,
  type IdentityPublicKey,
  type UnsignedEnvelope,
} from "@p2pcards/protocol";
import { describe, expect, it } from "vitest";

import {
  LobbyChainRegistry,
  validateLobbyJoinEnvelope,
  validateLobbyRosterEnvelope,
  type LobbyBootstrapContext,
} from "./lobby-bootstrap";

interface TestIdentity {
  readonly secretKey: Ed25519SecretKey;
  readonly publicKey: IdentityPublicKey;
}

const HOST = identity(1);
const ALICE = identity(2);
const BOB = identity(3);
const MALLORY = identity(4);
const GAME_ID = parseGameId(new Uint8Array(16).fill(0x11));
const OTHER_GAME_ID = parseGameId(new Uint8Array(16).fill(0x12));
const RULES_HASH = parseHash256(new Uint8Array(32).fill(0x21));
const OTHER_RULES_HASH = parseHash256(new Uint8Array(32).fill(0x22));
const ICE_CONFIG_HASH = parseHash256(new Uint8Array(32).fill(0x31));
const OTHER_ICE_CONFIG_HASH = parseHash256(new Uint8Array(32).fill(0x32));
const ZERO_HASH = parseHash256(new Uint8Array(32));
const CONTEXT: LobbyBootstrapContext = {
  gameId: GAME_ID,
  host: HOST.publicKey,
  rulesHash: RULES_HASH,
  iceConfigHash: ICE_CONFIG_HASH,
};

describe("lobby JOIN bootstrap", () => {
  it("classifies an admitted JOIN without creating its sender chain", () => {
    const registry = new LobbyChainRegistry(CONTEXT);
    const join = joinEnvelope(ALICE);

    expect(registry.classifyBootstrapJoin(join)).toMatchObject({ status: "accepted" });
    expect(registry.hasSender(ALICE.publicKey)).toBe(false);
    expect(registry.headOf(ALICE.publicKey)).toBeNull();
    expect(registry.bootstrapJoin(join)).toMatchObject({ status: "accepted" });
  });

  it("requires an explicit bootstrap before accepting an unknown sender", () => {
    const registry = new LobbyChainRegistry(CONTEXT);
    const join = joinEnvelope(ALICE);

    expect(registry.ingest(join)).toMatchObject({
      status: "rejected",
      reason: "unknown_sender",
      sender: ALICE.publicKey,
    });
    expect(registry.hasSender(ALICE.publicKey)).toBe(false);

    expect(registry.bootstrapJoin(join)).toMatchObject({
      status: "accepted",
      body: { pkId: ALICE.publicKey, rulesHash: RULES_HASH, clientVersion: "test/1" },
    });
    expect(registry.hasSender(ALICE.publicKey)).toBe(true);
    expect(registry.headOf(ALICE.publicKey)).toMatchObject({
      from: ALICE.publicKey,
      seq: 0,
      hash: join.hash,
    });
    expect(registry.get(ALICE.publicKey, 0)).toBe(join);
  });

  it("preserves duplicate and equivocation outcomes at the JOIN genesis", () => {
    const registry = new LobbyChainRegistry(CONTEXT);
    const first = joinEnvelope(ALICE);
    const conflict = joinEnvelope(ALICE, {
      body: encodeJoinBody({
        pkId: ALICE.publicKey,
        rulesHash: RULES_HASH,
        clientVersion: "test/2",
      }),
    });
    registry.bootstrapJoin(first);

    expect(registry.bootstrapJoin(first)).toMatchObject({ status: "duplicate", existing: first });
    expect(registry.bootstrapJoin(conflict)).toMatchObject({
      status: "rejected",
      reason: "equivocation",
      existing: first,
      received: conflict,
    });
    expect(registry.headOf(ALICE.publicKey)).toMatchObject({ seq: 0, hash: first.hash });
  });

  it("continues a bootstrapped sender's ordinary envelope chain", () => {
    const registry = new LobbyChainRegistry(CONTEXT);
    const join = joinEnvelope(ALICE);
    registry.bootstrapJoin(join);
    const ready = readyEnvelope(ALICE, 1, join.hash);

    expect(registry.ingest(ready)).toMatchObject({ status: "accepted", head: { seq: 1 } });
    expect(registry.headOf(ALICE.publicKey)).toMatchObject({ seq: 1, hash: ready.hash });
  });

  it("rejects malformed or context-invalid JOIN genesis envelopes without admitting the sender", () => {
    const cases: ReadonlyArray<readonly [string, EnvelopeArtifact]> = [
      ["wrong_game", joinEnvelope(ALICE, { envelope: { game: OTHER_GAME_ID } })],
      ["wrong_type", joinEnvelope(ALICE, { envelope: { type: "READY" } })],
      ["wrong_phase", joinEnvelope(ALICE, { envelope: { phase: "setup.keys" } })],
      ["wrong_round", joinEnvelope(ALICE, { envelope: { round: 1 } })],
      ["not_genesis", joinEnvelope(ALICE, { envelope: { seq: 1 } })],
      [
        "not_genesis",
        joinEnvelope(ALICE, { envelope: { prev: parseHash256(new Uint8Array(32).fill(1)) } }),
      ],
      ["malformed_body", joinEnvelope(ALICE, { body: {} })],
      [
        "sender_mismatch",
        joinEnvelope(ALICE, {
          body: encodeJoinBody({
            pkId: BOB.publicKey,
            rulesHash: RULES_HASH,
            clientVersion: "test/1",
          }),
        }),
      ],
      [
        "rules_mismatch",
        joinEnvelope(ALICE, {
          body: encodeJoinBody({
            pkId: ALICE.publicKey,
            rulesHash: OTHER_RULES_HASH,
            clientVersion: "test/1",
          }),
        }),
      ],
    ];

    for (const [reason, artifact] of cases) {
      const registry = new LobbyChainRegistry(CONTEXT);
      expect(validateLobbyJoinEnvelope(artifact, CONTEXT)).toMatchObject({
        status: "rejected",
        reason,
      });
      expect(registry.bootstrapJoin(artifact)).toMatchObject({ status: "rejected", reason });
      expect(registry.hasSender(ALICE.publicKey)).toBe(false);
    }
  });
});

describe("host ROSTER validation", () => {
  it("classifies a host roster without changing the host chain or roster", () => {
    const registry = new LobbyChainRegistry(CONTEXT);
    const roster = rosterEnvelope(HOST, [HOST.publicKey, ALICE.publicKey, BOB.publicKey]);

    expect(registry.classifyRoster(roster)).toMatchObject({ status: "accepted" });
    expect(registry.headOf(HOST.publicKey)).toBeNull();
    expect(registry.roster).toBeNull();
    expect(registry.ingestRoster(roster)).toMatchObject({ status: "accepted" });
  });

  it("accepts only the host's context-bound roster and records its chain and hash", () => {
    const registry = new LobbyChainRegistry(CONTEXT);
    const roster = rosterEnvelope(HOST, [HOST.publicKey, ALICE.publicKey, BOB.publicKey]);
    const result = registry.ingestRoster(roster);
    const validation = validateLobbyRosterEnvelope(roster, CONTEXT);
    if (validation.status !== "valid") {
      throw new Error("Expected a valid roster fixture");
    }

    expect(result).toMatchObject({
      status: "accepted",
      iceConfigMatches: true,
      body: { seats: [HOST.publicKey, ALICE.publicKey, BOB.publicKey] },
    });
    expect(registry.rosterHash).toEqual(validation.rosterHash);
    expect(registry.roster?.seats).toEqual([HOST.publicKey, ALICE.publicKey, BOB.publicKey]);
    expect(registry.headOf(HOST.publicKey)).toMatchObject({ seq: 0, hash: roster.hash });
  });

  it("uses a valid roster as authorization to bootstrap a member's JOIN chain", () => {
    const registry = new LobbyChainRegistry(CONTEXT);
    const aliceJoin = joinEnvelope(ALICE);

    expect(registry.bootstrapRosterMemberJoin(aliceJoin)).toMatchObject({
      status: "rejected",
      reason: "not_roster_member",
    });
    registry.ingestRoster(rosterEnvelope(HOST, [HOST.publicKey, ALICE.publicKey]));

    expect(registry.bootstrapRosterMemberJoin(aliceJoin)).toMatchObject({ status: "accepted" });
    expect(registry.hasSender(ALICE.publicKey)).toBe(true);
    expect(registry.bootstrapRosterMemberJoin(joinEnvelope(MALLORY))).toMatchObject({
      status: "rejected",
      reason: "not_roster_member",
    });
  });

  it("keeps host roster updates on one continuous sender chain", () => {
    const registry = new LobbyChainRegistry(CONTEXT);
    const first = rosterEnvelope(HOST, [HOST.publicKey]);
    const second = rosterEnvelope(
      HOST,
      [HOST.publicKey, ALICE.publicKey],
      { seq: 1, prev: first.hash },
    );

    expect(registry.ingestRoster(first)).toMatchObject({ status: "accepted" });
    expect(registry.ingestRoster(second)).toMatchObject({ status: "accepted" });
    expect(registry.roster?.seats).toEqual([HOST.publicKey, ALICE.publicKey]);
    expect(registry.headOf(HOST.publicKey)).toMatchObject({ seq: 1, hash: second.hash });
    expect(registry.ingestRoster(second)).toMatchObject({ status: "duplicate" });
  });

  it("requires a new peer to replay the host chain from its genesis", () => {
    const first = rosterEnvelope(HOST, [HOST.publicKey]);
    const latest = rosterEnvelope(
      HOST,
      [HOST.publicKey, ALICE.publicKey],
      { seq: 1, prev: first.hash },
    );
    const registry = new LobbyChainRegistry(CONTEXT);

    expect(registry.ingestRoster(latest)).toMatchObject({
      status: "rejected",
      reason: "gap",
      expectedSeq: 0,
      actualSeq: 1,
    });
    expect(registry.ingestRoster(first)).toMatchObject({ status: "accepted" });
    expect(registry.ingestRoster(latest)).toMatchObject({ status: "accepted" });
    expect(registry.roster?.seats).toEqual([HOST.publicKey, ALICE.publicKey]);
  });

  it("reports but does not reject a different ICE configuration", () => {
    const artifact = rosterEnvelope(HOST, [HOST.publicKey], {}, {
      iceConfigHash: OTHER_ICE_CONFIG_HASH,
    });
    const validation = validateLobbyRosterEnvelope(artifact, CONTEXT);
    const registry = new LobbyChainRegistry(CONTEXT);

    expect(validation).toMatchObject({ status: "valid", iceConfigMatches: false });
    expect(registry.ingestRoster(artifact)).toMatchObject({
      status: "accepted",
      iceConfigMatches: false,
    });
  });

  it("rejects invalid roster authority, metadata, contents, and identities", () => {
    const invalidIdentity = parseIdentityPublicKey(new Uint8Array(32));
    const cases: ReadonlyArray<readonly [string, EnvelopeArtifact]> = [
      ["wrong_game", rosterEnvelope(HOST, [HOST.publicKey], { game: OTHER_GAME_ID })],
      ["wrong_sender", rosterEnvelope(ALICE, [HOST.publicKey, ALICE.publicKey])],
      ["wrong_type", rosterEnvelope(HOST, [HOST.publicKey], { type: "READY" })],
      ["wrong_phase", rosterEnvelope(HOST, [HOST.publicKey], { phase: "setup.keys" })],
      ["wrong_round", rosterEnvelope(HOST, [HOST.publicKey], { round: 1 })],
      ["malformed_body", rosterEnvelope(HOST, [HOST.publicKey], {}, {}, {})],
      [
        "body_game_mismatch",
        rosterEnvelope(HOST, [HOST.publicKey], {}, { gameId: OTHER_GAME_ID }),
      ],
      [
        "rules_mismatch",
        rosterEnvelope(HOST, [HOST.publicKey], {}, { rulesHash: OTHER_RULES_HASH }),
      ],
      [
        "invalid_roster_identity",
        rosterEnvelope(HOST, [HOST.publicKey, invalidIdentity]),
      ],
      ["host_missing", rosterEnvelope(HOST, [ALICE.publicKey])],
    ];

    for (const [reason, artifact] of cases) {
      const registry = new LobbyChainRegistry(CONTEXT);
      expect(validateLobbyRosterEnvelope(artifact, CONTEXT)).toMatchObject({
        status: "rejected",
        reason,
      });
      expect(registry.ingestRoster(artifact)).toMatchObject({ status: "rejected", reason });
      expect(registry.roster).toBeNull();
      expect(registry.headOf(HOST.publicKey)).toBeNull();
    }
  });

  it("defensively copies context and exposed roster state", () => {
    const mutableContext: LobbyBootstrapContext = {
      gameId: parseGameId(GAME_ID),
      host: parseIdentityPublicKey(HOST.publicKey),
      rulesHash: parseHash256(RULES_HASH),
      iceConfigHash: parseHash256(ICE_CONFIG_HASH),
    };
    const registry = new LobbyChainRegistry(mutableContext);
    mutableContext.gameId.fill(0xff);
    mutableContext.host.fill(0xff);
    mutableContext.rulesHash.fill(0xff);
    mutableContext.iceConfigHash.fill(0xff);
    const accepted = registry.ingestRoster(
      rosterEnvelope(HOST, [HOST.publicKey, ALICE.publicKey]),
    );
    if (accepted.status !== "accepted") {
      throw new Error("Expected roster acceptance");
    }

    const exposed = registry.roster!;
    exposed.gameId.fill(0xee);
    exposed.rulesHash.fill(0xee);
    exposed.iceConfigHash.fill(0xee);
    exposed.seats[0]!.fill(0xee);
    accepted.body.gameId.fill(0xdd);
    accepted.body.seats[0]!.fill(0xdd);

    expect(registry.roster).toMatchObject({
      gameId: GAME_ID,
      rulesHash: RULES_HASH,
      iceConfigHash: ICE_CONFIG_HASH,
      seats: [HOST.publicKey, ALICE.publicKey],
    });
  });
});

describe("lobby readiness", () => {
  it("predicts final readiness without advancing a chain or finalizing", () => {
    const fixture = readyLobby();
    const rosterHash = fixture.registry.rosterHash!;
    fixture.registry.ingestReady(
      readyEnvelope(HOST, 1, fixture.roster.hash, { rosterHash }),
    );
    fixture.registry.ingestReady(
      readyEnvelope(ALICE, 1, fixture.aliceJoin.hash, { rosterHash }),
    );
    const bobReady = readyEnvelope(BOB, 1, fixture.bobJoin.hash, { rosterHash });

    expect(fixture.registry.classifyReady(bobReady)).toMatchObject({
      status: "accepted",
      state: "finalized",
      chainResult: { status: "accepted" },
    });
    expect(fixture.registry.state).toBe("collecting_ready");
    expect(fixture.registry.headOf(BOB.publicKey)).toMatchObject({
      seq: 0,
      hash: fixture.bobJoin.hash,
    });
    expect(fixture.registry.ingestReady(bobReady)).toMatchObject({
      status: "accepted",
      state: "finalized",
    });
  });

  it("collects READY envelopes in any arrival order and transfers complete histories", () => {
    const fixture = readyLobby();
    const rosterHash = fixture.registry.rosterHash!;
    const hostReady = readyEnvelope(HOST, 1, fixture.roster.hash, { rosterHash });
    const aliceReady = readyEnvelope(ALICE, 1, fixture.aliceJoin.hash, { rosterHash });
    const bobReady = readyEnvelope(BOB, 1, fixture.bobJoin.hash, { rosterHash });

    expect(fixture.registry.state).toBe("collecting_ready");
    expect(fixture.registry.ingestReady(bobReady)).toMatchObject({
      status: "accepted",
      seat: 2,
      state: "collecting_ready",
    });
    expect(fixture.registry.ingestReady(hostReady)).toMatchObject({
      status: "accepted",
      seat: 0,
      state: "collecting_ready",
    });
    expect(fixture.registry.readySeats).toEqual([0, 2]);
    expect(fixture.registry.ingestReady(aliceReady)).toMatchObject({
      status: "accepted",
      seat: 1,
      state: "finalized",
    });

    const finalized = fixture.registry.finalizedRegistry;
    expect(fixture.registry.state).toBe("finalized");
    expect(fixture.registry.readySeats).toEqual([0, 1, 2]);
    expect(finalized?.roster).toEqual([HOST.publicKey, ALICE.publicKey, BOB.publicKey]);
    expect(finalized?.heads()).toEqual([
      expect.objectContaining({ from: HOST.publicKey, seq: 1, hash: hostReady.hash }),
      expect.objectContaining({ from: ALICE.publicKey, seq: 1, hash: aliceReady.hash }),
      expect.objectContaining({ from: BOB.publicKey, seq: 1, hash: bobReady.hash }),
    ]);
    expect(finalized?.readRange(HOST.publicKey, 0, 1)).toEqual({
      status: "complete",
      envelopes: [fixture.roster, hostReady],
    });
    expect(finalized?.readRange(ALICE.publicKey, 0, 1)).toEqual({
      status: "complete",
      envelopes: [fixture.aliceJoin, aliceReady],
    });
  });

  it("classifies exact and semantic readiness retransmissions without double-counting", () => {
    const fixture = readyLobby();
    const rosterHash = fixture.registry.rosterHash!;
    const first = readyEnvelope(ALICE, 1, fixture.aliceJoin.hash, { rosterHash });
    const repeated = readyEnvelope(ALICE, 2, first.hash, { rosterHash });

    expect(fixture.registry.ingestReady(first)).toMatchObject({
      status: "accepted",
      chainResult: { status: "accepted" },
    });
    expect(fixture.registry.ingestReady(first)).toMatchObject({
      status: "duplicate",
      chainResult: { status: "duplicate" },
    });
    expect(fixture.registry.ingestReady(repeated)).toMatchObject({
      status: "duplicate",
      chainResult: { status: "accepted" },
    });
    expect(fixture.registry.readySeats).toEqual([1]);
    expect(fixture.registry.headOf(ALICE.publicKey)).toMatchObject({ seq: 2, hash: repeated.hash });
  });

  it("selects readiness by roster hash and restores it when identical roster bytes return", () => {
    const fixture = readyLobby();
    const firstHash = fixture.registry.rosterHash!;
    const aliceReady = readyEnvelope(ALICE, 1, fixture.aliceJoin.hash, {
      rosterHash: firstHash,
    });
    fixture.registry.ingestReady(aliceReady);

    const repeatedRoster = rosterEnvelope(
      HOST,
      [HOST.publicKey, ALICE.publicKey, BOB.publicKey],
      { seq: 1, prev: fixture.roster.hash },
    );
    fixture.registry.ingestRoster(repeatedRoster);
    expect(fixture.registry.readySeats).toEqual([1]);

    const changedRoster = rosterEnvelope(
      HOST,
      [HOST.publicKey, ALICE.publicKey, BOB.publicKey, MALLORY.publicKey],
      { seq: 2, prev: repeatedRoster.hash },
    );
    fixture.registry.ingestRoster(changedRoster);
    expect(fixture.registry.readySeats).toEqual([]);
    expect(fixture.registry.ingestReady(aliceReady)).toMatchObject({
      status: "rejected",
      reason: "roster_hash_mismatch",
    });

    const restoredRoster = rosterEnvelope(
      HOST,
      [HOST.publicKey, ALICE.publicKey, BOB.publicKey],
      { seq: 3, prev: changedRoster.hash },
    );
    fixture.registry.ingestRoster(restoredRoster);
    expect(fixture.registry.rosterHash).toEqual(firstHash);
    expect(fixture.registry.readySeats).toEqual([1]);
  });

  it("rejects READY envelopes that are invalid for the current lobby context", () => {
    const noRoster = new LobbyChainRegistry(CONTEXT);
    expect(
      noRoster.ingestReady(
        readyEnvelope(HOST, 0, ZERO_HASH, {
          rosterHash: parseHash256(new Uint8Array(32).fill(1)),
        }),
      ),
    ).toMatchObject({ status: "rejected", reason: "no_roster" });

    const small = new LobbyChainRegistry(CONTEXT);
    const smallRoster = rosterEnvelope(HOST, [HOST.publicKey]);
    small.ingestRoster(smallRoster);
    expect(
      small.ingestReady(
        readyEnvelope(HOST, 1, smallRoster.hash, { rosterHash: small.rosterHash! }),
      ),
    ).toMatchObject({ status: "rejected", reason: "roster_not_finalizable" });

    const cases: ReadonlyArray<
      readonly [string, (fixture: ReturnType<typeof readyLobby>) => EnvelopeArtifact]
    > = [
      [
        "wrong_game",
        (fixture) =>
          readyEnvelope(ALICE, 1, fixture.aliceJoin.hash, {
            rosterHash: fixture.registry.rosterHash!,
            envelope: { game: OTHER_GAME_ID },
          }),
      ],
      [
        "wrong_type",
        (fixture) =>
          readyEnvelope(ALICE, 1, fixture.aliceJoin.hash, {
            rosterHash: fixture.registry.rosterHash!,
            envelope: { type: "JOIN" },
          }),
      ],
      [
        "wrong_phase",
        (fixture) =>
          readyEnvelope(ALICE, 1, fixture.aliceJoin.hash, {
            rosterHash: fixture.registry.rosterHash!,
            envelope: { phase: "setup.keys" },
          }),
      ],
      [
        "wrong_round",
        (fixture) =>
          readyEnvelope(ALICE, 1, fixture.aliceJoin.hash, {
            rosterHash: fixture.registry.rosterHash!,
            envelope: { round: 1 },
          }),
      ],
      [
        "not_roster_member",
        (fixture) =>
          readyEnvelope(MALLORY, 0, ZERO_HASH, { rosterHash: fixture.registry.rosterHash! }),
      ],
      [
        "malformed_body",
        (fixture) =>
          readyEnvelope(ALICE, 1, fixture.aliceJoin.hash, {
            rosterHash: fixture.registry.rosterHash!,
            body: {},
          }),
      ],
      [
        "roster_hash_mismatch",
        (fixture) =>
          readyEnvelope(ALICE, 1, fixture.aliceJoin.hash, {
            rosterHash: parseHash256(new Uint8Array(32).fill(0xff)),
          }),
      ],
      [
        "gap",
        (fixture) =>
          readyEnvelope(ALICE, 2, fixture.aliceJoin.hash, {
            rosterHash: fixture.registry.rosterHash!,
          }),
      ],
    ];

    for (const [reason, createArtifact] of cases) {
      const fixture = readyLobby();
      expect(fixture.registry.ingestReady(createArtifact(fixture))).toMatchObject({
        status: "rejected",
        reason,
      });
      expect(fixture.registry.readySeats).toEqual([]);
    }

    const missingChain = readyLobby({ bootstrapBob: false });
    expect(
      missingChain.registry.ingestReady(
        readyEnvelope(BOB, 1, missingChain.bobJoin.hash, {
          rosterHash: missingChain.registry.rosterHash!,
        }),
      ),
    ).toMatchObject({ status: "rejected", reason: "sender_chain_missing" });
  });

  it("freezes lobby mutation after handoff to the established registry", () => {
    const fixture = readyLobby();
    const rosterHash = fixture.registry.rosterHash!;
    fixture.registry.ingestReady(readyEnvelope(HOST, 1, fixture.roster.hash, { rosterHash }));
    fixture.registry.ingestReady(
      readyEnvelope(ALICE, 1, fixture.aliceJoin.hash, { rosterHash }),
    );
    fixture.registry.ingestReady(readyEnvelope(BOB, 1, fixture.bobJoin.hash, { rosterHash }));

    expect(
      fixture.registry.ingestRoster(
        rosterEnvelope(
          HOST,
          [HOST.publicKey, ALICE.publicKey, BOB.publicKey],
          { seq: 2, prev: fixture.registry.headOf(HOST.publicKey)!.hash },
        ),
      ),
    ).toMatchObject({ status: "rejected", reason: "lobby_finalized" });
    expect(fixture.registry.bootstrapJoin(joinEnvelope(MALLORY))).toMatchObject({
      status: "rejected",
      reason: "lobby_finalized",
    });
  });
});

function identity(fill: number): TestIdentity {
  const secretKey = importEd25519SecretKey(new Uint8Array(32).fill(fill));
  return {
    secretKey,
    publicKey: parseIdentityPublicKey(deriveEd25519PublicKey(secretKey)),
  };
}

function joinEnvelope(
  author: TestIdentity,
  options: {
    readonly envelope?: Partial<UnsignedEnvelope>;
    readonly body?: CborValue;
  } = {},
): EnvelopeArtifact {
  return signEnvelope(
    {
      v: 1,
      game: GAME_ID,
      from: author.publicKey,
      seq: 0,
      prev: ZERO_HASH,
      round: 0,
      phase: "lobby",
      type: "JOIN",
      body:
        options.body ??
        encodeJoinBody({
          pkId: author.publicKey,
          rulesHash: RULES_HASH,
          clientVersion: "test/1",
        }),
      ...options.envelope,
    },
    author.secretKey,
  );
}

function rosterEnvelope(
  author: TestIdentity,
  seats: readonly IdentityPublicKey[],
  envelope: Partial<UnsignedEnvelope> = {},
  body: Partial<{
    readonly gameId: GameId;
    readonly rulesHash: Hash256;
    readonly iceConfigHash: Hash256;
  }> = {},
  rawBody?: CborValue,
): EnvelopeArtifact {
  return signEnvelope(
    {
      v: 1,
      game: GAME_ID,
      from: author.publicKey,
      seq: 0,
      prev: ZERO_HASH,
      round: 0,
      phase: "lobby",
      type: "ROSTER",
      body:
        rawBody ??
        encodeRosterBody({
          gameId: body.gameId ?? GAME_ID,
          rulesHash: body.rulesHash ?? RULES_HASH,
          iceConfigHash: body.iceConfigHash ?? ICE_CONFIG_HASH,
          seats,
        }),
      ...envelope,
    },
    author.secretKey,
  );
}

function readyEnvelope(
  author: TestIdentity,
  seq: number,
  prev: Hash256,
  options: {
    readonly rosterHash?: Hash256;
    readonly envelope?: Partial<UnsignedEnvelope>;
    readonly body?: CborValue;
  } = {},
): EnvelopeArtifact {
  return signEnvelope(
    {
      v: 1,
      game: GAME_ID,
      from: author.publicKey,
      seq,
      prev,
      round: 0,
      phase: "lobby",
      type: "READY",
      body:
        options.body ??
        encodeReadyBody({
          rosterHash: options.rosterHash ?? parseHash256(new Uint8Array(32).fill(7)),
        }),
      ...options.envelope,
    },
    author.secretKey,
  );
}

function readyLobby(options: { readonly bootstrapBob?: boolean } = {}) {
  const registry = new LobbyChainRegistry(CONTEXT);
  const roster = rosterEnvelope(HOST, [HOST.publicKey, ALICE.publicKey, BOB.publicKey]);
  const aliceJoin = joinEnvelope(ALICE);
  const bobJoin = joinEnvelope(BOB);
  registry.ingestRoster(roster);
  registry.bootstrapRosterMemberJoin(aliceJoin);
  if (options.bootstrapBob !== false) {
    registry.bootstrapRosterMemberJoin(bobJoin);
  }
  return { registry, roster, aliceJoin, bobJoin };
}
