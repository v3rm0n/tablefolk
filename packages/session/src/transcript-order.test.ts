import {
  bytesToHex,
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
} from "@p2pcards/protocol";
import { describe, expect, it } from "vitest";

import { EnvelopeTranscriptOrderError, orderEnvelopeTranscript } from "./transcript-order";

interface TestIdentity {
  readonly secretKey: Ed25519SecretKey;
  readonly publicKey: IdentityPublicKey;
}

const ALICE = identity(131);
const BOB = identity(132);
const MALLORY = identity(133);
const GAME_ID = parseGameId(new Uint8Array(16).fill(0x21));
const OTHER_GAME_ID = parseGameId(new Uint8Array(16).fill(0x22));
const ZERO_HASH = parseHash256(new Uint8Array(32));

describe("canonical envelope transcript order", () => {
  it("orders complete sender chains by identity bytes and then sequence", () => {
    const aliceZero = artifact(ALICE, 0, ZERO_HASH, "alice zero");
    const aliceOne = artifact(ALICE, 1, aliceZero.hash, "alice one");
    const bobZero = artifact(BOB, 0, ZERO_HASH, "bob zero");
    const malloryZero = artifact(MALLORY, 0, ZERO_HASH, "mallory zero");
    const input = [aliceOne, malloryZero, bobZero, aliceZero];

    const ordered = orderEnvelopeTranscript(GAME_ID, input);
    const expected = [
      [ALICE, [aliceZero, aliceOne]],
      [BOB, [bobZero]],
      [MALLORY, [malloryZero]],
    ] as const;
    const expectedHashes = [...expected]
      .sort(([left], [right]) =>
        bytesToHex(left.publicKey).localeCompare(bytesToHex(right.publicKey)),
      )
      .flatMap(([, artifacts]) => artifacts.map(({ hash }) => hash));

    expect(ordered.map(({ hash }) => hash)).toEqual(expectedHashes);
    expect(
      orderEnvelopeTranscript(GAME_ID, [...input].reverse()).map(({ hash }) => hash),
    ).toEqual(expectedHashes);
  });

  it("accepts an empty signed-envelope set", () => {
    expect(orderEnvelopeTranscript(GAME_ID, [])).toEqual([]);
  });

  it("rejects duplicate tuples, gaps, and broken predecessor links", () => {
    const first = artifact(ALICE, 0, ZERO_HASH, "first");
    const conflict = artifact(ALICE, 0, ZERO_HASH, "conflict");
    const gap = artifact(ALICE, 2, first.hash, "gap");
    const broken = artifact(
      ALICE,
      1,
      parseHash256(new Uint8Array(32).fill(1)),
      "broken",
    );

    expect(() => orderEnvelopeTranscript(GAME_ID, [first, first])).toThrow(/repeats sender/);
    expect(() => orderEnvelopeTranscript(GAME_ID, [first, conflict])).toThrow(
      /repeats sender/,
    );
    expect(() => orderEnvelopeTranscript(GAME_ID, [gap])).toThrow(/gap/);
    expect(() => orderEnvelopeTranscript(GAME_ID, [first, broken])).toThrow(/broken_prev/);
  });

  it("rejects another game and invalid signatures", () => {
    const wrongGame = artifact(ALICE, 0, ZERO_HASH, "wrong game", OTHER_GAME_ID);
    expect(() => orderEnvelopeTranscript(GAME_ID, [wrongGame])).toThrow(/another game/);

    const corrupt = artifact(ALICE, 0, ZERO_HASH, "corrupt");
    const lastIndex = corrupt.canonicalBytes.length - 1;
    corrupt.canonicalBytes[lastIndex] = corrupt.canonicalBytes[lastIndex]! ^ 1;
    expect(() => orderEnvelopeTranscript(GAME_ID, [corrupt])).toThrow(
      EnvelopeTranscriptOrderError,
    );
  });

  it("returns verified snapshots isolated from caller mutation", () => {
    const first = artifact(ALICE, 0, ZERO_HASH, "stable");
    const expectedHash = first.hash.slice();
    const ordered = orderEnvelopeTranscript(GAME_ID, [first]);

    first.canonicalBytes.fill(0xff);
    first.hash.fill(0xff);
    expect(ordered[0]?.hash).toEqual(expectedHash);
  });
});

function identity(fill: number): TestIdentity {
  const secretKey = importEd25519SecretKey(new Uint8Array(32).fill(fill));
  return {
    secretKey,
    publicKey: parseIdentityPublicKey(deriveEd25519PublicKey(secretKey)),
  };
}

function artifact(
  author: TestIdentity,
  seq: number,
  prev: Hash256,
  marker: string,
  game: GameId = GAME_ID,
): EnvelopeArtifact {
  return signEnvelope(
    {
      v: 1,
      game,
      from: author.publicKey,
      seq,
      prev,
      round: 1,
      phase: "round.1.play.0",
      type: "ACTION",
      body: { marker },
    },
    author.secretKey,
  );
}
