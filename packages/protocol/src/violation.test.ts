import {
  bytesToHex,
  deriveEd25519PublicKey,
  importEd25519SecretKey,
  type Ed25519SecretKey,
} from "@p2pcards/crypto";
import { decodeCanonical, encodeCanonical, type CborMap } from "@p2pcards/encoding";
import { describe, expect, it } from "vitest";

import {
  decodeEquivocationViolationBody,
  encodeEquivocationViolationBody,
} from "./violation";
import { parseGameId, parseHash256, parseIdentityPublicKey } from "./fields";
import { signEnvelope, type EnvelopeArtifact, type UnsignedEnvelope } from "./envelope";

interface TestIdentity {
  readonly secretKey: Ed25519SecretKey;
  readonly publicKey: ReturnType<typeof parseIdentityPublicKey>;
}

const ALICE = identity(111);
const BOB = identity(112);
const GAME_ID = parseGameId(new Uint8Array(16).fill(0x51));
const OTHER_GAME_ID = parseGameId(new Uint8Array(16).fill(0x52));
const ZERO_HASH = parseHash256(new Uint8Array(32));

describe("equivocation violation body", () => {
  it("sorts self-certifying evidence by hash and round-trips nested envelopes", () => {
    const left = artifact(ALICE, "left");
    const right = artifact(ALICE, "right");

    const forward = encodeEquivocationViolationBody({
      seat: 1,
      reason: "equivocation",
      evidence: [left, right],
    });
    const reverse = encodeEquivocationViolationBody({
      seat: 1,
      reason: "equivocation",
      evidence: [right, left],
    });
    expect(encodeCanonical(forward)).toEqual(encodeCanonical(reverse));

    const decoded = decodeEquivocationViolationBody(forward);
    expect(decoded.seat).toBe(1);
    expect(decoded.reason).toBe("equivocation");
    expect(decoded.evidence.map(({ hash }) => bytesToHex(hash))).toEqual(
      [left, right].map(({ hash }) => bytesToHex(hash)).sort(),
    );
    expect(decoded.evidence[0].envelope.seq).toBe(0);
    expect(decoded.evidence[1].envelope.seq).toBe(0);
  });

  it("rejects evidence in descending hash order at the decode boundary", () => {
    const left = artifact(ALICE, "left");
    const right = artifact(ALICE, "right");
    const ordered = [left, right].sort((a, b) => bytesToHex(a.hash).localeCompare(bytesToHex(b.hash)));
    const body: CborMap = {
      seat: 0,
      reason: "equivocation",
      evidence: [
        decodeCanonical(ordered[1]!.canonicalBytes),
        decodeCanonical(ordered[0]!.canonicalBytes),
      ],
    };

    expect(() => decodeEquivocationViolationBody(body)).toThrow(/ascending hash/);
  });

  it("requires matching game, sender, and sequence with different hashes", () => {
    const first = artifact(ALICE, "first");
    const cases = [
      [first, first, /different hashes/],
      [first, artifact(BOB, "sender"), /same game, sender, and sequence/],
      [first, artifact(ALICE, "sequence", { seq: 1 }), /same game, sender, and sequence/],
      [
        first,
        artifact(ALICE, "game", { game: OTHER_GAME_ID }),
        /same game, sender, and sequence/,
      ],
    ] as const;

    for (const [left, right, message] of cases) {
      expect(() =>
        encodeEquivocationViolationBody({
          seat: 0,
          reason: "equivocation",
          evidence: [left, right],
        }),
      ).toThrow(message);
    }
  });

  it("rejects malformed fields and invalid nested signatures", () => {
    const left = artifact(ALICE, "left");
    const right = artifact(ALICE, "right");
    const valid = encodeEquivocationViolationBody({
      seat: 0,
      reason: "equivocation",
      evidence: [left, right],
    });
    const evidence = valid["evidence"];

    expect(() => decodeEquivocationViolationBody({ ...valid, seat: 8 })).toThrow(/seat/);
    expect(() => decodeEquivocationViolationBody({ ...valid, reason: "bad-proof" })).toThrow(
      /equivocation/,
    );
    expect(() => decodeEquivocationViolationBody({ ...valid, evidence: [left] as never })).toThrow(
      /exactly two/,
    );
    expect(() => decodeEquivocationViolationBody({ ...valid, extension: true })).toThrow(
      /exactly/,
    );

    const nested = evidence as CborMap[];
    const corrupt = decodeCanonical(encodeCanonical(nested[0]!)) as CborMap;
    const signature = corrupt["sig"] as Uint8Array;
    signature[0] = signature[0]! ^ 1;
    expect(() =>
      decodeEquivocationViolationBody({ ...valid, evidence: [corrupt, nested[1]!] }),
    ).toThrow(/valid signed envelope/);
  });

  it("isolates decoded evidence from source artifact mutation", () => {
    const left = artifact(ALICE, "left");
    const right = artifact(ALICE, "right");
    const decoded = decodeEquivocationViolationBody(
      encodeEquivocationViolationBody({
        seat: 0,
        reason: "equivocation",
        evidence: [left, right],
      }),
    );
    const expected = decoded.evidence.map(({ hash }) => hash.slice());

    left.canonicalBytes.fill(0xff);
    left.hash.fill(0xff);
    right.canonicalBytes.fill(0xee);
    expect(decoded.evidence.map(({ hash }) => hash)).toEqual(expected);
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
  marker: string,
  overrides: Partial<UnsignedEnvelope> = {},
): EnvelopeArtifact {
  return signEnvelope(
    {
      v: 1,
      game: GAME_ID,
      from: author.publicKey,
      seq: 0,
      prev: ZERO_HASH,
      round: 1,
      phase: "round.1.play.0",
      type: "ACTION",
      body: { marker },
      ...overrides,
    },
    author.secretKey,
  );
}
