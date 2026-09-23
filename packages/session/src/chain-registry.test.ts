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

import { SessionChainRegistry, SessionRosterError } from "./chain-registry";

interface TestIdentity {
  readonly secretKey: Ed25519SecretKey;
  readonly publicKey: IdentityPublicKey;
}

const ALICE = identity(1);
const BOB = identity(2);
const CAROL = identity(3);
const DAVE = identity(4);
const GAME = parseGameId(new Uint8Array(16).fill(7));
const OTHER_GAME = parseGameId(new Uint8Array(16).fill(8));
const ZERO_HASH = parseHash256(new Uint8Array(32));

describe("established session chain registry", () => {
  it("validates the roster bounds, uniqueness, and public keys", () => {
    expect(() => new SessionChainRegistry(GAME, [ALICE.publicKey, BOB.publicKey])).toThrow(
      SessionRosterError,
    );
    expect(
      () =>
        new SessionChainRegistry(GAME, [
          ALICE.publicKey,
          BOB.publicKey,
          CAROL.publicKey,
          ALICE.publicKey,
        ]),
    ).toThrow(/duplicate identity/);
    expect(
      () =>
        new SessionChainRegistry(GAME, [
          ALICE.publicKey,
          BOB.publicKey,
          parseIdentityPublicKey(new Uint8Array(32)),
        ]),
    ).toThrow(/invalid Ed25519/);
  });

  it("routes accepted envelopes and emits witness heads in seat order", () => {
    const registry = registryForThree();
    const fromCarol = signed(CAROL, GAME, 0, ZERO_HASH, "carol");
    const fromAlice = signed(ALICE, GAME, 0, ZERO_HASH, "alice");

    expect(registry.ingest(fromCarol).status).toBe("accepted");
    expect(registry.ingest(fromAlice).status).toBe("accepted");

    expect(registry.heads()).toEqual([
      expect.objectContaining({ from: ALICE.publicKey, seq: 0 }),
      expect.objectContaining({ from: CAROL.publicKey, seq: 0 }),
    ]);
    expect(registry.seatOf(ALICE.publicKey)).toBe(0);
    expect(registry.seatOf(CAROL.publicKey)).toBe(2);
    expect(registry.seatOf(DAVE.publicKey)).toBeNull();
  });

  it("classifies an accepted envelope without advancing its sender", () => {
    const registry = registryForThree();
    const fromAlice = signed(ALICE, GAME, 0, ZERO_HASH, "alice");

    expect(registry.classify(fromAlice)).toMatchObject({ status: "accepted" });
    expect(registry.heads()).toEqual([]);
    expect(registry.ingest(fromAlice)).toMatchObject({ status: "accepted" });
  });

  it("rejects envelopes for another game before touching a sender chain", () => {
    const registry = registryForThree();
    const wrongGame = signed(ALICE, OTHER_GAME, 0, ZERO_HASH, "wrong game");

    expect(registry.ingest(wrongGame)).toMatchObject({
      status: "rejected",
      reason: "wrong_game",
      expected: GAME,
      actual: OTHER_GAME,
    });
    expect(registry.heads()).toEqual([]);
  });

  it("rejects a cryptographically valid envelope from outside the roster", () => {
    const registry = registryForThree();
    const unknown = signed(DAVE, GAME, 0, ZERO_HASH, "unknown");

    expect(registry.ingest(unknown)).toMatchObject({
      status: "rejected",
      reason: "unknown_sender",
      sender: DAVE.publicKey,
    });
    expect(registry.heads()).toEqual([]);
  });

  it("returns complete inclusive synchronization ranges", () => {
    const registry = registryForThree();
    const first = signed(ALICE, GAME, 0, ZERO_HASH, "first");
    const second = signed(ALICE, GAME, 1, first.hash, "second");
    registry.ingest(first);
    registry.ingest(second);

    expect(registry.readRange(ALICE.publicKey, 0, 1)).toEqual({
      status: "complete",
      envelopes: [first, second],
    });
    expect(registry.readRange(ALICE.publicKey, 1, 1)).toEqual({
      status: "complete",
      envelopes: [second],
    });
  });

  it("reports the first unavailable synchronization sequence", () => {
    const registry = registryForThree();
    const first = signed(ALICE, GAME, 0, ZERO_HASH, "first");
    registry.ingest(first);

    expect(registry.readRange(ALICE.publicKey, 0, 2)).toEqual({
      status: "missing",
      firstMissingSeq: 1,
    });
    expect(registry.readRange(BOB.publicKey, 0, 0)).toEqual({
      status: "missing",
      firstMissingSeq: 0,
    });
    expect(registry.readRange(DAVE.publicKey, 0, 0)).toEqual({ status: "unknown_sender" });
  });

  it("rejects invalid synchronization bounds", () => {
    const registry = registryForThree();

    expect(() => registry.readRange(ALICE.publicKey, -1, 0)).toThrow(RangeError);
    expect(() => registry.readRange(ALICE.publicKey, 2, 1)).toThrow(RangeError);
  });

  it("defensively copies game and roster inputs", () => {
    const mutableGame = parseGameId(GAME);
    const mutableAlice = parseIdentityPublicKey(ALICE.publicKey);
    const registry = new SessionChainRegistry(mutableGame, [
      mutableAlice,
      BOB.publicKey,
      CAROL.publicKey,
    ]);

    mutableGame[0] = 0;
    mutableAlice[0] = 0;

    expect(registry.gameId).toEqual(GAME);
    expect(registry.roster[0]).toEqual(ALICE.publicKey);
  });
});

function registryForThree(): SessionChainRegistry {
  return new SessionChainRegistry(GAME, [ALICE.publicKey, BOB.publicKey, CAROL.publicKey]);
}

function identity(fill: number): TestIdentity {
  const secretKey = importEd25519SecretKey(new Uint8Array(32).fill(fill));
  return {
    secretKey,
    publicKey: parseIdentityPublicKey(deriveEd25519PublicKey(secretKey)),
  };
}

function signed(
  author: TestIdentity,
  game: GameId,
  seq: number,
  prev: Hash256,
  marker: string,
): EnvelopeArtifact {
  const value: UnsignedEnvelope = {
    v: 1,
    game,
    from: author.publicKey,
    seq,
    prev,
    round: 0,
    phase: "setup.keys",
    type: "KEY_SHARE",
    body: { marker },
  };
  return signEnvelope(value, author.secretKey);
}
