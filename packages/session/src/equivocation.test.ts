import {
  deriveEd25519PublicKey,
  importEd25519SecretKey,
  type Ed25519SecretKey,
} from "@p2pcards/crypto";
import {
  decodeEquivocationViolationBody,
  encodeEquivocationViolationBody,
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  signEnvelope,
  type EnvelopeArtifact,
  type GameId,
  type IdentityPublicKey,
} from "@p2pcards/protocol";
import { describe, expect, it } from "vitest";

import { SessionChainRegistry } from "./chain-registry";
import {
  assessEquivocationViolation,
  createEquivocationViolation,
  EquivocationEvidenceError,
} from "./equivocation";

interface TestIdentity {
  readonly secretKey: Ed25519SecretKey;
  readonly publicKey: IdentityPublicKey;
}

const ALICE = identity(121);
const BOB = identity(122);
const CAROL = identity(123);
const MALLORY = identity(124);
const GAME_ID = parseGameId(new Uint8Array(16).fill(0x71));
const OTHER_GAME_ID = parseGameId(new Uint8Array(16).fill(0x72));
const ZERO_HASH = parseHash256(new Uint8Array(32));

describe("session equivocation evidence", () => {
  it("constructs deterministic evidence and binds blame to the sender's seat", () => {
    const registry = sessionRegistry();
    const left = artifact(ALICE, "left");
    const right = artifact(ALICE, "right");

    const body = createEquivocationViolation(registry, right, left);
    expect(body.seat).toBe(0);
    expect(body.reason).toBe("equivocation");
    expect(assessEquivocationViolation(registry, body)).toMatchObject({
      status: "valid",
      seat: 0,
      sender: ALICE.publicKey,
    });
    expect(encodeEquivocationViolationBody(body)).toEqual(
      encodeEquivocationViolationBody(
        createEquivocationViolation(registry, left, right),
      ),
    );
  });

  it("rejects evidence that blames a different or nonexistent seat", () => {
    const registry = sessionRegistry();
    const left = artifact(ALICE, "left");
    const right = artifact(ALICE, "right");
    const wrongSeat = decodeEquivocationViolationBody(
      encodeEquivocationViolationBody({
        seat: 1,
        reason: "equivocation",
        evidence: [left, right],
      }),
    );
    const absentSeat = decodeEquivocationViolationBody(
      encodeEquivocationViolationBody({
        seat: 7,
        reason: "equivocation",
        evidence: [left, right],
      }),
    );

    expect(assessEquivocationViolation(registry, wrongSeat)).toEqual({
      status: "rejected",
      reason: "sender_seat_mismatch",
    });
    expect(assessEquivocationViolation(registry, absentSeat)).toEqual({
      status: "rejected",
      reason: "seat_out_of_roster",
    });
  });

  it("rejects another game and senders outside the finalized roster", () => {
    const registry = sessionRegistry();
    const otherLeft = artifact(ALICE, "left", OTHER_GAME_ID);
    const otherRight = artifact(ALICE, "right", OTHER_GAME_ID);
    const otherBody = decodeEquivocationViolationBody(
      encodeEquivocationViolationBody({
        seat: 0,
        reason: "equivocation",
        evidence: [otherLeft, otherRight],
      }),
    );

    expect(assessEquivocationViolation(registry, otherBody)).toEqual({
      status: "rejected",
      reason: "wrong_game",
    });
    expect(() =>
      createEquivocationViolation(
        registry,
        artifact(MALLORY, "left"),
        artifact(MALLORY, "right"),
      ),
    ).toThrow(/outside the finalized roster/);
  });

  it("rejects pairs that do not self-certify equivocation", () => {
    const registry = sessionRegistry();
    const left = artifact(ALICE, "left");

    expect(() => createEquivocationViolation(registry, left, left)).toThrow(
      EquivocationEvidenceError,
    );
    expect(() =>
      createEquivocationViolation(registry, left, artifact(BOB, "right")),
    ).toThrow(/do not prove equivocation/);
  });
});

function sessionRegistry(): SessionChainRegistry {
  return new SessionChainRegistry(GAME_ID, [
    ALICE.publicKey,
    BOB.publicKey,
    CAROL.publicKey,
  ]);
}

function identity(fill: number): TestIdentity {
  const secretKey = importEd25519SecretKey(new Uint8Array(32).fill(fill));
  return {
    secretKey,
    publicKey: parseIdentityPublicKey(deriveEd25519PublicKey(secretKey)),
  };
}

function artifact(
  author: TestIdentity,
  marker: string,
  game: GameId = GAME_ID,
): EnvelopeArtifact {
  return signEnvelope(
    {
      v: 1,
      game,
      from: author.publicKey,
      seq: 0,
      prev: ZERO_HASH,
      round: 1,
      phase: "round.1.play.0",
      type: "ACTION",
      body: { marker },
    },
    author.secretKey,
  );
}
