import {
  addRistrettoScalars,
  deriveEd25519PublicKey,
  importEd25519SecretKey,
  RISTRETTO_SCALAR_ONE,
  RISTRETTO_SCALAR_ORDER,
  scalarFromBigInt,
  sha256,
  type Ed25519SecretKey,
  type RandomSource,
} from "@p2pcards/crypto";
import {
  createGameKeyShare,
  decodeGameKeyShareBody,
  encodeGameKeyShareBody,
  verifyGameKeyShare,
  type GameKeyShare,
} from "@p2pcards/deck";
import type { CborMap, CborValue } from "@p2pcards/encoding";
import {
  beaconCommitment,
  decodeAndVerifyEnvelope,
  encodeRandCommitBody,
  encodeRandRevealBody,
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  parseRandomSecret,
  signEnvelope,
  type EnvelopeArtifact,
  type EnvelopeMessageType,
  type GameId,
  type Hash256,
  type IdentityPublicKey,
  type ProofContext,
} from "@p2pcards/protocol";
import { describe, expect, it } from "vitest";

import { SetupEnvelopeCoordinator } from "./setup-envelope-coordinator";

interface TestIdentity {
  readonly secretKey: Ed25519SecretKey;
  readonly publicKey: IdentityPublicKey;
}

const ALICE = identity(51);
const BOB = identity(52);
const CAROL = identity(53);
const MALLORY = identity(54);
const ROSTER = [ALICE.publicKey, BOB.publicKey, CAROL.publicKey] as const;
const GAME_ID = parseGameId(new Uint8Array(16).fill(0x21));
const OTHER_GAME_ID = parseGameId(new Uint8Array(16).fill(0x22));
const ROUND = 2;
const ZERO_HASH = parseHash256(new Uint8Array(32));
const KEY_CONTEXT: ProofContext = {
  gameId: GAME_ID,
  round: ROUND,
  phase: "setup.keys",
};
const KEY_SHARES = [1n, 2n, 3n].map((secret, seat) =>
  createGameKeyShare(KEY_CONTEXT, scalarFromBigInt(secret), scalarSource(seat + 61)),
);
const SECRETS = [6, 7, 8].map((fill) =>
  parseRandomSecret(new Uint8Array(32).fill(fill)),
);
const COMMITMENTS = SECRETS.map((secret, seat) =>
  parseHash256(beaconCommitment(GAME_ID, ROUND, seat, secret)),
);

describe("setup envelope coordinator", () => {
  it("validates and applies complete setup traffic independently of arrival order", () => {
    const coordinator = new SetupEnvelopeCoordinator(GAME_ID, ROUND, ROSTER);
    const keys = ROSTER.map((_, seat) => keyEnvelope(seat));
    const initial = coordinator.pendingSenders;
    expect(initial).toEqual([0, 1, 2]);
    expect(Object.isFrozen(initial)).toBe(true);
    expect(Reflect.set(initial, "0", 7)).toBe(false);
    expect(coordinator.commitmentAt(0)).toBeNull();

    expect(coordinator.ingest(keys[2]!)).toMatchObject({
      status: "accepted",
      seat: 2,
      state: "keys",
    });
    expect(coordinator.pendingSenders).toEqual([0, 1]);
    coordinator.ingest(keys[0]!);
    expect(coordinator.classify(keys[1]!)).toMatchObject({
      status: "accepted",
      seat: 1,
      state: "rand_commit",
    });
    expect(coordinator.state).toBe("keys");
    expect(coordinator.pendingSenders).toEqual([1]);
    expect(coordinator.publicKeyAt(1)).toBeNull();
    expect(coordinator.ingest(keys[1]!)).toMatchObject({ state: "rand_commit" });
    expect(coordinator.pendingSenders).toEqual([0, 1, 2]);
    expect(coordinator.ingest(keys[1]!)).toMatchObject({ status: "duplicate", state: "rand_commit" });

    const commits = ROSTER.map((_, seat) =>
      commitEnvelope(seat, 1, keys[seat]!.hash),
    );
    coordinator.ingest(commits[1]!);
    expect(coordinator.pendingSenders).toEqual([0, 2]);
    expect(coordinator.commitmentAt(0)).toBeNull();
    const exposed = coordinator.commitmentAt(1)!;
    expect(exposed).toEqual(COMMITMENTS[1]);
    expect(exposed.buffer).not.toBe(coordinator.commitmentAt(1)!.buffer);
    exposed.fill(0);
    expect(coordinator.commitmentAt(1)).toEqual(COMMITMENTS[1]);
    coordinator.ingest(commits[2]!);
    coordinator.classify(commits[0]!);
    expect(coordinator.pendingSenders).toEqual([0]);
    expect(coordinator.ingest(commits[0]!)).toMatchObject({ state: "rand_reveal" });
    expect(coordinator.pendingSenders).toEqual([0, 1, 2]);
    expect(coordinator.ingest(commits[0]!)).toMatchObject({ status: "duplicate", state: "rand_reveal" });

    const reveals = ROSTER.map((_, seat) =>
      revealEnvelope(seat, 2, commits[seat]!.hash),
    );
    coordinator.ingest(reveals[2]!);
    expect(coordinator.pendingSenders).toEqual([0, 1]);
    expect(Object.isFrozen(coordinator.pendingSenders)).toBe(true);
    coordinator.ingest(reveals[0]!);
    coordinator.classify(reveals[1]!);
    expect(coordinator.pendingSenders).toEqual([1]);
    expect(coordinator.ingest(reveals[1]!)).toMatchObject({ state: "complete" });
    for (const artifact of [keys[1]!, commits[1]!, reveals[1]!]) {
      expect(coordinator.ingest(artifact)).toMatchObject({ status: "duplicate", state: "complete" });
    }
    expect(coordinator.pendingSenders).toEqual([]);
    expect(Object.isFrozen(coordinator.pendingSenders)).toBe(true);
    expect(initial).toEqual([0, 1, 2]);
    expect(coordinator.seed).toEqual(sha256(...SECRETS));
  });

  it("exposes no pending senders or commitments after aggregate-key failure", () => {
    const coordinator = new SetupEnvelopeCoordinator(GAME_ID, ROUND, ROSTER);
    const keys = [1n, 2n, RISTRETTO_SCALAR_ORDER - 3n].map((secret, seat) => setupEnvelope(
      [ALICE, BOB, CAROL][seat]!, "KEY_SHARE", "setup.keys",
      encodeGameKeyShareBody(createGameKeyShare(KEY_CONTEXT, scalarFromBigInt(secret), scalarSource(seat + 61))),
    ));
    coordinator.ingest(keys[0]!);
    coordinator.ingest(keys[2]!);
    expect(coordinator.classify(keys[1]!)).toMatchObject({ status: "failed" });
    expect(coordinator.pendingSenders).toEqual([1]);
    expect(coordinator.ingest(keys[1]!)).toMatchObject({ status: "failed" });
    expect(coordinator.ingest(keys[1]!)).toMatchObject({ status: "duplicate", state: "failed" });
    expect(coordinator.ingest(commitEnvelope(0, 1, keys[0]!.hash))).toMatchObject({ reason: "setup_failed" });
    expect(coordinator.pendingSenders).toEqual([]);
    expect(Object.isFrozen(coordinator.pendingSenders)).toBe(true);
    ROSTER.forEach((_, seat) => expect(coordinator.commitmentAt(seat)).toBeNull());
  });

  it("classifies invalid proof, duplicate, and conflict outcomes without mutation", () => {
    const coordinator = new SetupEnvelopeCoordinator(GAME_ID, ROUND, ROSTER);
    const valid = keyEnvelope(0);
    const invalidShare: GameKeyShare = {
      H: KEY_SHARES[0]!.H,
      pop: {
        R: KEY_SHARES[0]!.pop.R,
        z: addRistrettoScalars(KEY_SHARES[0]!.pop.z, RISTRETTO_SCALAR_ONE),
      },
    };
    const invalid = setupEnvelope(
      ALICE,
      "KEY_SHARE",
      "setup.keys",
      encodeGameKeyShareBody(invalidShare),
    );

    expect(coordinator.classify(invalid)).toMatchObject({
      status: "rejected",
      reason: "invalid_key_proof",
    });
    expect(coordinator.publicKeyAt(0)).toBeNull();
    expect(coordinator.pendingSenders).toEqual([0, 1, 2]);
    coordinator.ingest(valid);
    expect(coordinator.classify(valid)).toMatchObject({ status: "duplicate" });
    expect(coordinator.ingest(keyEnvelope(1, ALICE))).toMatchObject({
      status: "rejected",
      reason: "conflicting_key_share",
    });
  });

  it("rejects envelope context, authority, type, phase, and body violations", () => {
    const cases: ReadonlyArray<readonly [string, EnvelopeArtifact]> = [
      [
        "wrong_game",
        setupEnvelope(
          ALICE,
          "KEY_SHARE",
          "setup.keys",
          encodeGameKeyShareBody(KEY_SHARES[0]!),
          { game: OTHER_GAME_ID },
        ),
      ],
      [
        "unknown_sender",
        setupEnvelope(
          MALLORY,
          "KEY_SHARE",
          "setup.keys",
          encodeGameKeyShareBody(KEY_SHARES[0]!),
        ),
      ],
      [
        "wrong_round",
        setupEnvelope(
          ALICE,
          "KEY_SHARE",
          "setup.keys",
          encodeGameKeyShareBody(KEY_SHARES[0]!),
          { round: ROUND + 1 },
        ),
      ],
      [
        "wrong_phase",
        setupEnvelope(
          ALICE,
          "KEY_SHARE",
          "setup.rand",
          encodeGameKeyShareBody(KEY_SHARES[0]!),
        ),
      ],
      ["wrong_type", setupEnvelope(ALICE, "ACTION", "setup.keys", {})],
      ["malformed_body", setupEnvelope(ALICE, "KEY_SHARE", "setup.keys", {})],
    ];

    for (const [reason, artifact] of cases) {
      const coordinator = new SetupEnvelopeCoordinator(GAME_ID, ROUND, ROSTER);
      expect(coordinator.ingest(artifact)).toMatchObject({ status: "rejected", reason });
      expect(coordinator.state).toBe("keys");
      expect(coordinator.publicKeyAt(0)).toBeNull();
      expect(coordinator.pendingSenders).toEqual([0, 1, 2]);
    }
  });

  it("defensively copies constructor inputs and exposed context", () => {
    const game = parseGameId(GAME_ID);
    const roster = ROSTER.map(parseIdentityPublicKey);
    const coordinator = new SetupEnvelopeCoordinator(game, ROUND, roster);
    game.fill(0xff);
    roster[0]!.fill(0xff);

    const exposedGame = coordinator.gameId;
    const exposedRoster = coordinator.roster;
    exposedGame.fill(0xee);
    exposedRoster[0]!.fill(0xee);
    expect(coordinator.gameId).toEqual(GAME_ID);
    expect(coordinator.roster).toEqual(ROSTER);
    expect(coordinator.ingest(keyEnvelope(0))).toMatchObject({ status: "accepted", seat: 0 });
  });

  it("ignores decoded sender, body, and hash mutations in classification, ingestion, and returned artifacts", () => {
    const original = keyEnvelope(0);
    expect(verifyGameKeyShare(KEY_CONTEXT, KEY_SHARES[1]!)).toBe(true);
    expect(KEY_SHARES[0]!.H.equals(KEY_SHARES[1]!.H)).toBe(false);
    for (const mutation of ["sender", "body", "hash", "all"]) {
      const coordinator = new SetupEnvelopeCoordinator(GAME_ID, ROUND, ROSTER);
      const candidate = decodeAndVerifyEnvelope(original.canonicalBytes);
      if (mutation === "sender" || mutation === "all") candidate.envelope.from.set(BOB.publicKey);
      if (mutation === "body" || mutation === "all") {
        Object.assign(candidate.envelope.body as CborMap, encodeGameKeyShareBody(KEY_SHARES[1]!));
        expect(verifyGameKeyShare(KEY_CONTEXT, decodeGameKeyShareBody(candidate.envelope.body))).toBe(true);
      }
      if (mutation === "hash" || mutation === "all") candidate.hash.fill(0xff);
      expect(candidate.canonicalBytes).toEqual(original.canonicalBytes);

      const classification = coordinator.classify(candidate);
      expect(classification).toMatchObject({ status: "accepted", state: "keys", seat: 0 });
      expect(classification.received).toEqual(original);
      expect(coordinator.pendingSenders).toEqual([0, 1, 2]);
      expect(coordinator.publicKeyAt(0)).toBeNull();
      expect(coordinator.publicKeyAt(1)).toBeNull();

      const result = coordinator.ingest(candidate);
      expect(result).toMatchObject({ status: "accepted", state: "keys", seat: 0 });
      expect(result.received).toEqual(original);
      expect(coordinator.publicKeyAt(0)!.toBytes()).toEqual(KEY_SHARES[0]!.H.toBytes());
      expect(coordinator.publicKeyAt(1)).toBeNull();
      expect(coordinator.pendingSenders).toEqual([1, 2]);
      expect(coordinator.ingest(original)).toMatchObject({ status: "duplicate", seat: 0 });
    }
  });

  it("rejects tampered canonical bytes despite an intact valid decoded view without changing existing setup state", () => {
    const coordinator = new SetupEnvelopeCoordinator(GAME_ID, ROUND, ROSTER);
    coordinator.ingest(keyEnvelope(0));
    const original = keyEnvelope(1);
    const candidate = decodeAndVerifyEnvelope(original.canonicalBytes);
    const last = candidate.canonicalBytes.length - 1;
    candidate.canonicalBytes[last] = candidate.canonicalBytes[last]! ^ 1;
    expect(candidate.envelope).toEqual(original.envelope);
    expect(candidate.hash).toEqual(original.hash);
    expect(verifyGameKeyShare(KEY_CONTEXT, decodeGameKeyShareBody(candidate.envelope.body))).toBe(true);
    expect(() => decodeAndVerifyEnvelope(candidate.canonicalBytes)).toThrow(expect.objectContaining({ code: "INVALID_SIGNATURE" }));

    for (const operation of ["classify", "ingest"] as const) {
      expect(() => coordinator[operation](candidate)).toThrow(expect.objectContaining({ code: "INVALID_SIGNATURE" }));
      expect(coordinator.state).toBe("keys");
      expect(coordinator.pendingSenders).toEqual([1, 2]);
      expect(coordinator.publicKeyAt(0)!.toBytes()).toEqual(KEY_SHARES[0]!.H.toBytes());
      for (const seat of [1, 2]) expect(coordinator.publicKeyAt(seat)).toBeNull();
      for (const seat of [0, 1, 2]) expect(coordinator.commitmentAt(seat)).toBeNull();
      expect(coordinator.aggregateKey).toBeNull();
      expect(coordinator.seed).toBeNull();
    }
    expect(coordinator.ingest(original)).toMatchObject({ status: "accepted", seat: 1 });
    expect(coordinator.pendingSenders).toEqual([2]);
  });

  it("validates constructor inputs", () => {
    expect(() => new SetupEnvelopeCoordinator(GAME_ID, -1, ROSTER)).toThrow(RangeError);
    expect(() => new SetupEnvelopeCoordinator(GAME_ID, ROUND, ROSTER.slice(0, 2))).toThrow(
      RangeError,
    );
    expect(
      () =>
        new SetupEnvelopeCoordinator(GAME_ID, ROUND, [
          ALICE.publicKey,
          ALICE.publicKey,
          CAROL.publicKey,
        ]),
    ).toThrow(/duplicate identity/);
    for (const seat of [-1, 3, 0.5, NaN, Infinity]) {
      expect(() => new SetupEnvelopeCoordinator(GAME_ID, ROUND, ROSTER).commitmentAt(seat)).toThrow(RangeError);
    }
  });
});

function keyEnvelope(seat: number, author: TestIdentity = [ALICE, BOB, CAROL][seat]!): EnvelopeArtifact {
  return setupEnvelope(
    author,
    "KEY_SHARE",
    "setup.keys",
    encodeGameKeyShareBody(KEY_SHARES[seat]!),
  );
}

function commitEnvelope(seat: number, seq: number, prev: Hash256): EnvelopeArtifact {
  return setupEnvelope(
    [ALICE, BOB, CAROL][seat]!,
    "RAND_COMMIT",
    "setup.rand",
    encodeRandCommitBody({ cm: COMMITMENTS[seat]! }),
    { seq, prev },
  );
}

function revealEnvelope(seat: number, seq: number, prev: Hash256): EnvelopeArtifact {
  return setupEnvelope(
    [ALICE, BOB, CAROL][seat]!,
    "RAND_REVEAL",
    "setup.rand",
    encodeRandRevealBody({ s: SECRETS[seat]! }),
    { seq, prev },
  );
}

function setupEnvelope(
  author: TestIdentity,
  type: EnvelopeMessageType,
  phase: string,
  body: CborValue,
  overrides: {
    readonly game?: GameId;
    readonly round?: number;
    readonly seq?: number;
    readonly prev?: Hash256;
  } = {},
): EnvelopeArtifact {
  return signEnvelope(
    {
      v: 1,
      game: overrides.game ?? GAME_ID,
      from: author.publicKey,
      seq: overrides.seq ?? 0,
      prev: overrides.prev ?? ZERO_HASH,
      round: overrides.round ?? ROUND,
      phase,
      type,
      body,
    },
    author.secretKey,
  );
}

function identity(fill: number): TestIdentity {
  const secretKey = importEd25519SecretKey(new Uint8Array(32).fill(fill));
  return {
    secretKey,
    publicKey: parseIdentityPublicKey(deriveEd25519PublicKey(secretKey)),
  };
}

function scalarSource(value: number): RandomSource {
  return {
    fill(target) {
      target.fill(0);
      target[0] = value;
    },
  };
}
