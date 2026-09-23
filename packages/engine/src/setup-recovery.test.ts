import {
  deriveEd25519PublicKey,
  importEd25519SecretKey,
  scalarFromBigInt,
  sha256,
  type Ed25519SecretKey,
  type RandomSource,
} from "@p2pcards/crypto";
import { createGameKeyShare, encodeGameKeyShareBody } from "@p2pcards/deck";
import type { CborValue } from "@p2pcards/encoding";
import {
  beaconCommitment,
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

import { recoverSetup, SetupRecoveryError } from "./setup-recovery";

interface TestIdentity {
  readonly secretKey: Ed25519SecretKey;
  readonly publicKey: IdentityPublicKey;
}

const ALICE = identity(91);
const BOB = identity(92);
const CAROL = identity(93);
const MALLORY = identity(94);
const AUTHORS = [ALICE, BOB, CAROL] as const;
const ROSTER = [ALICE.publicKey, BOB.publicKey, CAROL.publicKey] as const;
const GAME_ID = parseGameId(new Uint8Array(16).fill(0x61));
const OTHER_GAME_ID = parseGameId(new Uint8Array(16).fill(0x62));
const ROUND = 4;
const ZERO_HASH = parseHash256(new Uint8Array(32));
const KEY_CONTEXT: ProofContext = {
  gameId: GAME_ID,
  round: ROUND,
  phase: "setup.keys",
};
const KEY_SHARES = [4n, 5n, 6n].map((secret, seat) =>
  createGameKeyShare(KEY_CONTEXT, scalarFromBigInt(secret), scalarSource(seat + 101)),
);
const SECRETS = [9, 10, 11].map((fill) =>
  parseRandomSecret(new Uint8Array(32).fill(fill)),
);
const COMMITMENTS = SECRETS.map((secret, seat) =>
  parseHash256(beaconCommitment(GAME_ID, ROUND, seat, secret)),
);

describe("setup transcript recovery", () => {
  it("replays setup by phase and seat without trusting transcript arrival order", () => {
    const artifacts = completeSetupArtifacts();
    const unrelated = setupEnvelope(MALLORY, "ACTION", "round.4.play.0", {}, 0, ZERO_HASH);
    const shuffled = [
      artifacts[8]!,
      artifacts[4]!,
      unrelated,
      artifacts[0]!,
      artifacts[6]!,
      artifacts[2]!,
      artifacts[7]!,
      artifacts[3]!,
      artifacts[1]!,
      artifacts[5]!,
    ];

    const recovered = recoverSetup(GAME_ID, ROUND, ROSTER, shuffled);

    expect(recovered.setupEnvelopeCount).toBe(9);
    expect(recovered.coordinator.state).toBe("complete");
    expect(recovered.coordinator.seed).toEqual(sha256(...SECRETS));
    KEY_SHARES.forEach((share, seat) => {
      expect(recovered.coordinator.publicKeyAt(seat)?.equals(share.H)).toBe(true);
    });
  });

  it("restores a partial setup without requiring missing contributions", () => {
    const aliceKey = keyEnvelope(0, 0, ZERO_HASH);
    const carolKey = keyEnvelope(2, 0, ZERO_HASH);

    const recovered = recoverSetup(GAME_ID, ROUND, ROSTER, [carolKey, aliceKey]);

    expect(recovered.setupEnvelopeCount).toBe(2);
    expect(recovered.coordinator.state).toBe("keys");
    expect(recovered.coordinator.publicKeyAt(0)?.equals(KEY_SHARES[0]!.H)).toBe(true);
    expect(recovered.coordinator.publicKeyAt(1)).toBeNull();
    expect(recovered.coordinator.publicKeyAt(2)?.equals(KEY_SHARES[2]!.H)).toBe(true);
  });

  it("rejects duplicate tuples, another game, and corrupted signatures", () => {
    const key = keyEnvelope(0, 0, ZERO_HASH);
    expect(() => recoverSetup(GAME_ID, ROUND, ROSTER, [key, key])).toThrow(
      /repeats sender/,
    );

    const wrongGame = setupEnvelope(
      ALICE,
      "KEY_SHARE",
      "setup.keys",
      encodeGameKeyShareBody(KEY_SHARES[0]!),
      0,
      ZERO_HASH,
      OTHER_GAME_ID,
    );
    expect(() => recoverSetup(GAME_ID, ROUND, ROSTER, [wrongGame])).toThrow(
      /another game/,
    );

    const corrupt = keyEnvelope(0, 0, ZERO_HASH);
    const lastIndex = corrupt.canonicalBytes.length - 1;
    corrupt.canonicalBytes[lastIndex] = corrupt.canonicalBytes[lastIndex]! ^ 1;
    expect(() => recoverSetup(GAME_ID, ROUND, ROSTER, [corrupt])).toThrow(
      SetupRecoveryError,
    );
  });

  it("rejects setup traffic from a non-roster identity", () => {
    const outsider = setupEnvelope(
      MALLORY,
      "KEY_SHARE",
      "setup.keys",
      encodeGameKeyShareBody(KEY_SHARES[0]!),
      0,
      ZERO_HASH,
    );

    expect(() => recoverSetup(GAME_ID, ROUND, ROSTER, [outsider])).toThrow(
      /non-roster sender/,
    );
  });

  it("rejects a sender's first commitment or reveal before its prerequisite", () => {
    const aliceKey = keyEnvelope(0, 2, ZERO_HASH);
    const earlyCommit = commitEnvelope(0, 1, ZERO_HASH);
    expect(() => recoverSetup(GAME_ID, ROUND, ROSTER, [aliceKey, earlyCommit])).toThrow(
      /committed before its key share/,
    );

    const earlyReveal = revealEnvelope(0, 1, ZERO_HASH);
    expect(() => recoverSetup(GAME_ID, ROUND, ROSTER, [aliceKey, earlyReveal])).toThrow(
      /revealed before its commitment/,
    );
  });

  it("rejects semantically impossible or malformed setup histories", () => {
    const aliceKey = keyEnvelope(0, 0, ZERO_HASH);
    const bobKey = keyEnvelope(1, 0, ZERO_HASH);
    const prematureCommit = commitEnvelope(0, 1, aliceKey.hash);
    expect(() =>
      recoverSetup(GAME_ID, ROUND, ROSTER, [aliceKey, bobKey, prematureCommit]),
    ).toThrow(/unexpected_commit/);

    const malformed = setupEnvelope(ALICE, "KEY_SHARE", "setup.keys", {}, 0, ZERO_HASH);
    expect(() => recoverSetup(GAME_ID, ROUND, ROSTER, [malformed])).toThrow(
      /malformed_body/,
    );
  });

  it("isolates recovered setup state from later artifact mutation", () => {
    const key = keyEnvelope(0, 0, ZERO_HASH);
    const recovered = recoverSetup(GAME_ID, ROUND, ROSTER, [key]);

    key.canonicalBytes.fill(0xff);
    const body = key.envelope.body as { H_i: Uint8Array };
    body.H_i.fill(0xff);
    expect(recovered.coordinator.publicKeyAt(0)?.equals(KEY_SHARES[0]!.H)).toBe(true);
  });
});

function completeSetupArtifacts(): EnvelopeArtifact[] {
  const keys = AUTHORS.map((_, seat) => keyEnvelope(seat, 0, ZERO_HASH));
  const commits = AUTHORS.map((_, seat) => commitEnvelope(seat, 1, keys[seat]!.hash));
  const reveals = AUTHORS.map((_, seat) => revealEnvelope(seat, 2, commits[seat]!.hash));
  return [...keys, ...commits, ...reveals];
}

function keyEnvelope(seat: number, seq: number, prev: Hash256): EnvelopeArtifact {
  return setupEnvelope(
    AUTHORS[seat]!,
    "KEY_SHARE",
    "setup.keys",
    encodeGameKeyShareBody(KEY_SHARES[seat]!),
    seq,
    prev,
  );
}

function commitEnvelope(seat: number, seq: number, prev: Hash256): EnvelopeArtifact {
  return setupEnvelope(
    AUTHORS[seat]!,
    "RAND_COMMIT",
    "setup.rand",
    encodeRandCommitBody({ cm: COMMITMENTS[seat]! }),
    seq,
    prev,
  );
}

function revealEnvelope(seat: number, seq: number, prev: Hash256): EnvelopeArtifact {
  return setupEnvelope(
    AUTHORS[seat]!,
    "RAND_REVEAL",
    "setup.rand",
    encodeRandRevealBody({ s: SECRETS[seat]! }),
    seq,
    prev,
  );
}

function setupEnvelope(
  author: TestIdentity,
  type: EnvelopeMessageType,
  phase: string,
  body: CborValue,
  seq: number,
  prev: Hash256,
  game: GameId = GAME_ID,
): EnvelopeArtifact {
  return signEnvelope(
    {
      v: 1,
      game,
      from: author.publicKey,
      seq,
      prev,
      round: ROUND,
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
