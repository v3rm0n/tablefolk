import {
  deriveEd25519PublicKey,
  importEd25519SecretKey,
  type Ed25519SecretKey,
} from "@p2pcards/crypto";
import {
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

import { recoverSessionChains, SessionChainRecoveryError } from "./session-recovery";

interface TestIdentity {
  readonly secretKey: Ed25519SecretKey;
  readonly publicKey: IdentityPublicKey;
}

const ALICE = identity(31);
const BOB = identity(32);
const CAROL = identity(33);
const MALLORY = identity(34);
const GAME_ID = parseGameId(new Uint8Array(16).fill(0x51));
const OTHER_GAME_ID = parseGameId(new Uint8Array(16).fill(0x52));
const ZERO_HASH = parseHash256(new Uint8Array(32));
const ROSTER = [ALICE.publicKey, BOB.publicKey, CAROL.publicKey] as const;

describe("established session chain recovery", () => {
  it("rebuilds each sender by sequence independently of storage arrival order", () => {
    const aliceZero = envelope(ALICE, 0, ZERO_HASH, "alice zero");
    const aliceOne = envelope(ALICE, 1, aliceZero.hash, "alice one");
    const bobZero = envelope(BOB, 0, ZERO_HASH, "bob zero");

    const recovered = recoverSessionChains(
      GAME_ID,
      ROSTER,
      [aliceOne, bobZero, aliceZero],
    );

    expect(recovered.envelopeCount).toBe(3);
    expect(recovered.registry.heads()).toEqual([
      expect.objectContaining({ from: ALICE.publicKey, seq: 1, hash: aliceOne.hash }),
      expect.objectContaining({ from: BOB.publicKey, seq: 0, hash: bobZero.hash }),
    ]);
    expect(recovered.registry.readRange(ALICE.publicKey, 0, 1)).toMatchObject({
      status: "complete",
      envelopes: [aliceZero, aliceOne],
    });
  });

  it("allows roster senders with no accepted history", () => {
    const recovered = recoverSessionChains(GAME_ID, ROSTER, []);

    expect(recovered.envelopeCount).toBe(0);
    expect(recovered.registry.heads()).toEqual([]);
  });

  it("rejects duplicate sender/sequence tuples before replay", () => {
    const first = envelope(ALICE, 0, ZERO_HASH, "first");
    const conflict = envelope(ALICE, 0, ZERO_HASH, "conflict");

    expect(() => recoverSessionChains(GAME_ID, ROSTER, [first, first])).toThrow(
      /repeats sender/,
    );
    expect(() => recoverSessionChains(GAME_ID, ROSTER, [first, conflict])).toThrow(
      /repeats sender/,
    );
  });

  it("rejects wrong-game and non-roster artifacts", () => {
    const wrongGame = envelope(ALICE, 0, ZERO_HASH, "wrong game", OTHER_GAME_ID);
    const outsider = envelope(MALLORY, 0, ZERO_HASH, "outsider");

    expect(() => recoverSessionChains(GAME_ID, ROSTER, [wrongGame])).toThrow(
      /another game/,
    );
    expect(() => recoverSessionChains(GAME_ID, ROSTER, [outsider])).toThrow(
      /non-roster sender/,
    );
  });

  it("rejects sequence gaps and broken predecessor links", () => {
    const gap = envelope(ALICE, 1, ZERO_HASH, "gap");
    const broken = envelope(ALICE, 0, parseHash256(new Uint8Array(32).fill(1)), "broken");

    expect(() => recoverSessionChains(GAME_ID, ROSTER, [gap])).toThrow(/gap/);
    expect(() => recoverSessionChains(GAME_ID, ROSTER, [broken])).toThrow(/broken_prev/);
  });

  it("rejects corrupted stored artifacts", () => {
    const artifact = envelope(ALICE, 0, ZERO_HASH, "corrupt");
    const lastIndex = artifact.canonicalBytes.length - 1;
    artifact.canonicalBytes[lastIndex] = artifact.canonicalBytes[lastIndex]! ^ 1;

    expect(() => recoverSessionChains(GAME_ID, ROSTER, [artifact])).toThrow(
      SessionChainRecoveryError,
    );
  });

  it("isolates recovered chains from later caller mutation", () => {
    const artifact = envelope(ALICE, 0, ZERO_HASH, "stable");
    const expectedHash = artifact.hash.slice();
    const recovered = recoverSessionChains(GAME_ID, ROSTER, [artifact]);

    artifact.canonicalBytes.fill(0xff);
    artifact.hash.fill(0xff);
    expect(recovered.registry.heads()[0]?.hash).toEqual(expectedHash);
    expect(recovered.registry.readRange(ALICE.publicKey, 0, 0)).toMatchObject({
      status: "complete",
      envelopes: [expect.objectContaining({ hash: expectedHash })],
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

function envelope(
  author: TestIdentity,
  seq: number,
  prev: Hash256,
  marker: string,
  game: GameId = GAME_ID,
): EnvelopeArtifact {
  const value: UnsignedEnvelope = {
    v: 1,
    game,
    from: author.publicKey,
    seq,
    prev,
    round: 1,
    phase: "round.1.play.0",
    type: "ACTION",
    body: { marker },
  };
  return signEnvelope(value, author.secretKey);
}
