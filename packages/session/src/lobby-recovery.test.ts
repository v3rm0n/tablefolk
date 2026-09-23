import {
  deriveEd25519PublicKey,
  importEd25519SecretKey,
  type Ed25519SecretKey,
} from "@p2pcards/crypto";
import {
  encodeJoinBody,
  encodeReadyBody,
  encodeRosterBody,
  encodeWitnessBody,
  hashRosterBody,
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  signEnvelope,
  type EnvelopeArtifact,
  type Hash256,
  type IdentityPublicKey,
  type RosterBody,
  type UnsignedEnvelope,
} from "@p2pcards/protocol";
import { describe, expect, it } from "vitest";

import type { LobbyBootstrapContext } from "./lobby-bootstrap";
import { LobbyRecoveryError, recoverLobby } from "./lobby-recovery";

interface TestIdentity {
  readonly secretKey: Ed25519SecretKey;
  readonly publicKey: IdentityPublicKey;
}

const HOST = identity(11);
const ALICE = identity(12);
const BOB = identity(13);
const CAROL = identity(14);
const GAME_ID = parseGameId(new Uint8Array(16).fill(0x71));
const RULES_HASH = parseHash256(new Uint8Array(32).fill(0x72));
const ICE_CONFIG_HASH = parseHash256(new Uint8Array(32).fill(0x73));
const ZERO_HASH = parseHash256(new Uint8Array(32));
const CONTEXT: LobbyBootstrapContext = {
  gameId: GAME_ID,
  host: HOST.publicKey,
  rulesHash: RULES_HASH,
  iceConfigHash: ICE_CONFIG_HASH,
};

describe("pure lobby recovery", () => {
  it("rebuilds chains and partial readiness independently of arrival order", () => {
    const roster = rosterEnvelope(0, ZERO_HASH, [HOST.publicKey, ALICE.publicKey, BOB.publicKey]);
    const aliceJoin = joinEnvelope(ALICE);
    const bobJoin = joinEnvelope(BOB);
    const rosterHash = hashRosterBody(rosterBody([HOST.publicKey, ALICE.publicKey, BOB.publicKey]));
    const aliceReady = readyEnvelope(ALICE, 1, aliceJoin.hash, rosterHash);

    const recovered = recoverLobby(
      CONTEXT,
      [aliceReady, bobJoin, roster, aliceJoin],
      roster,
    );

    expect(recovered).toMatchObject({ envelopeCount: 4, restoredReadyCount: 1 });
    expect(recovered.lobby.state).toBe("collecting_ready");
    expect(recovered.lobby.readySeats).toEqual([1]);
    expect(recovered.lobby.rosterArtifact?.hash).toEqual(roster.hash);
    expect(recovered.lobby.headOf(HOST.publicKey)).toMatchObject({ seq: 0, hash: roster.hash });
    expect(recovered.lobby.headOf(ALICE.publicKey)).toMatchObject({
      seq: 1,
      hash: aliceReady.hash,
    });
    expect(recovered.lobby.headOf(BOB.publicKey)).toMatchObject({ seq: 0, hash: bobJoin.hash });
  });

  it("restores a finalized registry with complete lobby and post-READY chain tails", () => {
    const fixture = finalizedFixture();
    const recovered = recoverLobby(
      CONTEXT,
      [
        fixture.aliceTail,
        fixture.bobReady,
        fixture.hostReady,
        fixture.aliceJoin,
        fixture.roster,
        fixture.aliceReady,
        fixture.bobJoin,
      ],
      fixture.roster,
    );

    expect(recovered.restoredReadyCount).toBe(3);
    expect(recovered.lobby.state).toBe("finalized");
    expect(recovered.lobby.readySeats).toEqual([0, 1, 2]);
    const finalized = recovered.lobby.finalizedRegistry;
    expect(finalized?.heads()).toEqual([
      expect.objectContaining({ from: HOST.publicKey, seq: 1, hash: fixture.hostReady.hash }),
      expect.objectContaining({ from: ALICE.publicKey, seq: 2, hash: fixture.aliceTail.hash }),
      expect.objectContaining({ from: BOB.publicKey, seq: 1, hash: fixture.bobReady.hash }),
    ]);
    expect(finalized?.readRange(ALICE.publicKey, 0, 2)).toMatchObject({
      status: "complete",
      envelopes: [fixture.aliceJoin, fixture.aliceReady, fixture.aliceTail],
    });
  });

  it("produces identical finalized heads for different local arrival orders", () => {
    const fixture = finalizedFixture();
    const chronological = [
      fixture.roster,
      fixture.aliceJoin,
      fixture.bobJoin,
      fixture.hostReady,
      fixture.aliceReady,
      fixture.bobReady,
      fixture.aliceTail,
    ];
    const shuffled = [
      fixture.aliceTail,
      fixture.bobReady,
      fixture.bobJoin,
      fixture.roster,
      fixture.aliceReady,
      fixture.hostReady,
      fixture.aliceJoin,
    ];

    const left = recoverLobby(CONTEXT, chronological, fixture.roster);
    const right = recoverLobby(CONTEXT, shuffled, fixture.roster);

    expect(left.lobby.finalizedRegistry?.heads()).toEqual(right.lobby.finalizedRegistry?.heads());
    expect(left.lobby.readySeats).toEqual(right.lobby.readySeats);
  });

  it("retains historical hash-bound readiness when an older roster returns", () => {
    const firstBody = rosterBody([HOST.publicKey, ALICE.publicKey, BOB.publicKey]);
    const first = rosterEnvelope(0, ZERO_HASH, firstBody.seats);
    const second = rosterEnvelope(
      1,
      first.hash,
      [HOST.publicKey, ALICE.publicKey, BOB.publicKey, CAROL.publicKey],
    );
    const aliceJoin = joinEnvelope(ALICE);
    const aliceReady = readyEnvelope(ALICE, 1, aliceJoin.hash, hashRosterBody(firstBody));
    const recovered = recoverLobby(
      CONTEXT,
      [second, aliceReady, joinEnvelope(CAROL), first, joinEnvelope(BOB), aliceJoin],
      second,
    );

    expect(recovered.lobby.readySeats).toEqual([]);
    const restored = rosterEnvelope(2, second.hash, firstBody.seats);
    expect(recovered.lobby.ingestRoster(restored)).toMatchObject({ status: "accepted" });
    expect(recovered.lobby.readySeats).toEqual([1]);
  });

  it("requires a supplied durable snapshot to match the latest host roster", () => {
    const first = rosterEnvelope(0, ZERO_HASH, [HOST.publicKey]);
    const latest = rosterEnvelope(1, first.hash, [HOST.publicKey, ALICE.publicKey]);

    expect(() => recoverLobby(CONTEXT, [latest, first], first)).toThrow(
      /does not match latest host history/,
    );
    expect(() => recoverLobby(CONTEXT, [latest, first], null)).toThrow(
      /snapshot is missing/,
    );
    expect(recoverLobby(CONTEXT, [latest, first], latest).lobby.rosterArtifact?.hash).toEqual(
      latest.hash,
    );
  });

  it("rejects duplicate tuples, gaps, and invalid sender genesis records", () => {
    const first = rosterEnvelope(0, ZERO_HASH, [HOST.publicKey]);
    expect(() => recoverLobby(CONTEXT, [first, first], first)).toThrow(/repeats sender/);

    const future = rosterEnvelope(
      1,
      parseHash256(new Uint8Array(32).fill(9)),
      [HOST.publicKey],
    );
    expect(() => recoverLobby(CONTEXT, [future], future)).toThrow(/gap/);

    const unknownReady = readyEnvelope(
      ALICE,
      0,
      ZERO_HASH,
      parseHash256(new Uint8Array(32).fill(8)),
    );
    expect(() => recoverLobby(CONTEXT, [unknownReady], null)).toThrow(/wrong_type/);

    const aliceJoin = joinEnvelope(ALICE);
    const aliceRoster = signEnvelope(
      {
        ...baseEnvelope(ALICE, 1, aliceJoin.hash),
        type: "ROSTER",
        body: encodeRosterBody(rosterBody([HOST.publicKey, ALICE.publicKey])),
      },
      ALICE.secretKey,
    );
    expect(() => recoverLobby(CONTEXT, [aliceRoster, aliceJoin])).toThrow(/Non-host sender/);
  });

  it("rejects invalid signatures and semantically invalid accepted READY records", () => {
    const roster = rosterEnvelope(0, ZERO_HASH, [HOST.publicKey, ALICE.publicKey, BOB.publicKey]);
    const aliceJoin = joinEnvelope(ALICE);
    const corrupted = joinEnvelope(BOB);
    const lastIndex = corrupted.canonicalBytes.length - 1;
    corrupted.canonicalBytes[lastIndex] = corrupted.canonicalBytes[lastIndex]! ^ 1;
    expect(() => recoverLobby(CONTEXT, [roster, aliceJoin, corrupted], roster)).toThrow(
      /is invalid/,
    );

    const unknownHashReady = readyEnvelope(
      ALICE,
      1,
      aliceJoin.hash,
      parseHash256(new Uint8Array(32).fill(0xff)),
    );
    expect(() =>
      recoverLobby(CONTEXT, [unknownHashReady, aliceJoin, joinEnvelope(BOB), roster], roster),
    ).toThrow(/unknown_roster_hash/);
  });
});

function identity(fill: number): TestIdentity {
  const secretKey = importEd25519SecretKey(new Uint8Array(32).fill(fill));
  return {
    secretKey,
    publicKey: parseIdentityPublicKey(deriveEd25519PublicKey(secretKey)),
  };
}

function baseEnvelope(
  author: TestIdentity,
  seq: number,
  prev: Hash256,
): Omit<UnsignedEnvelope, "type" | "body"> {
  return {
    v: 1,
    game: GAME_ID,
    from: author.publicKey,
    seq,
    prev,
    round: 0,
    phase: "lobby",
  };
}

function joinEnvelope(author: TestIdentity): EnvelopeArtifact {
  return signEnvelope(
    {
      ...baseEnvelope(author, 0, ZERO_HASH),
      type: "JOIN",
      body: encodeJoinBody({
        pkId: author.publicKey,
        rulesHash: RULES_HASH,
        clientVersion: "recovery-test/1",
      }),
    },
    author.secretKey,
  );
}

function rosterBody(seats: readonly IdentityPublicKey[]): RosterBody {
  return {
    gameId: GAME_ID,
    rulesHash: RULES_HASH,
    iceConfigHash: ICE_CONFIG_HASH,
    seats,
  };
}

function rosterEnvelope(
  seq: number,
  prev: Hash256,
  seats: readonly IdentityPublicKey[],
): EnvelopeArtifact {
  return signEnvelope(
    {
      ...baseEnvelope(HOST, seq, prev),
      type: "ROSTER",
      body: encodeRosterBody(rosterBody(seats)),
    },
    HOST.secretKey,
  );
}

function readyEnvelope(
  author: TestIdentity,
  seq: number,
  prev: Hash256,
  rosterHash: Hash256,
): EnvelopeArtifact {
  return signEnvelope(
    {
      ...baseEnvelope(author, seq, prev),
      type: "READY",
      body: encodeReadyBody({ rosterHash }),
    },
    author.secretKey,
  );
}

function finalizedFixture() {
  const body = rosterBody([HOST.publicKey, ALICE.publicKey, BOB.publicKey]);
  const roster = rosterEnvelope(0, ZERO_HASH, body.seats);
  const aliceJoin = joinEnvelope(ALICE);
  const bobJoin = joinEnvelope(BOB);
  const rosterHash = hashRosterBody(body);
  const hostReady = readyEnvelope(HOST, 1, roster.hash, rosterHash);
  const aliceReady = readyEnvelope(ALICE, 1, aliceJoin.hash, rosterHash);
  const bobReady = readyEnvelope(BOB, 1, bobJoin.hash, rosterHash);
  const aliceTail = signEnvelope(
    {
      ...baseEnvelope(ALICE, 2, aliceReady.hash),
      type: "WITNESS",
      body: encodeWitnessBody({ heads: [] }),
    },
    ALICE.secretKey,
  );
  return { roster, aliceJoin, bobJoin, hostReady, aliceReady, bobReady, aliceTail };
}
