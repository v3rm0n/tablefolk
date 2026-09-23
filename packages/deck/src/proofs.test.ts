import {
  bytesToHex,
  RistrettoPoint,
  scalarFromBigInt,
  type RandomSource,
} from "@p2pcards/crypto";
import { parseGameId, type ProofContext } from "@p2pcards/protocol";
import { describe, expect, it } from "vitest";

import { maskCard } from "./elgamal";
import {
  createGameKeyShare,
  createProvenDecryptionShare,
  verifyGameKeyShare,
  verifyProvenDecryptionShare,
} from "./proofs";

const CONTEXT: ProofContext = {
  gameId: parseGameId(
    Uint8Array.from({ length: 16 }, (_, index) => index),
  ),
  round: 0,
  phase: "setup.keys",
};
const SECRET = scalarFromBigInt(3n);
const PUBLIC_KEY = RistrettoPoint.base().multiply(SECRET);

describe("Schnorr proof of possession", () => {
  it("creates a deterministic valid proof bound to its context", () => {
    const share = createGameKeyShare(CONTEXT, SECRET, scalarSource(9));

    expect(share.H.equals(PUBLIC_KEY)).toBe(true);
    expect(verifyGameKeyShare(CONTEXT, share)).toBe(true);
    expect(bytesToHex(share.H.toBytes())).toBe(
      "94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259",
    );
    expect(bytesToHex(share.pop.R.toBytes())).toBe(
      "02622ace8f7303a31cafc63f8fc48fdc16e1c8c8d234b2f0d6685282a9076031",
    );
    expect(share.pop.z).toBe(
      3286618691123014917690485704741519114100485961298443308437392341205801395749n,
    );
  });

  it("rejects a changed statement or context", () => {
    const share = createGameKeyShare(CONTEXT, SECRET, scalarSource(9));
    const changedPublicKey = RistrettoPoint.base().multiply(scalarFromBigInt(4n));

    expect(verifyGameKeyShare({ ...CONTEXT, round: 1 }, share)).toBe(false);
    expect(verifyGameKeyShare(CONTEXT, { ...share, H: changedPublicKey })).toBe(false);
    expect(
      verifyGameKeyShare(CONTEXT, {
        ...share,
        pop: { ...share.pop, z: scalarFromBigInt(1n) },
      }),
    ).toBe(false);
  });

  it("rejects a zero game secret", () => {
    expect(() => createGameKeyShare(CONTEXT, scalarFromBigInt(0n), scalarSource(9))).toThrow(
      TypeError,
    );
  });
});

describe("Chaum-Pedersen decryption-share proof", () => {
  const aggregateKey = PUBLIC_KEY.add(
    RistrettoPoint.base().multiply(scalarFromBigInt(5n)),
  );
  const card = maskCard(RistrettoPoint.base(), scalarFromBigInt(11n), aggregateKey);

  it("proves the same secret exponent for G/H and A/S", () => {
    const share = createProvenDecryptionShare(CONTEXT, 7, SECRET, card.A, scalarSource(13));

    expect(verifyProvenDecryptionShare(CONTEXT, 7, PUBLIC_KEY, card.A, share)).toBe(true);
    expect(share.S.equals(card.A.multiply(SECRET))).toBe(true);
    expect(bytesToHex(share.S.toBytes())).toBe(
      "6cb925752437368710235314963a2d23751898b536cab9b98a32bab56afeae45",
    );
    expect(share.proof.z).toBe(
      5178103861366086365699553586459941887979988873768770904029241163516008653583n,
    );
  });

  it("rejects changes to any bound position, context, key, or share", () => {
    const share = createProvenDecryptionShare(CONTEXT, 7, SECRET, card.A, scalarSource(13));

    expect(verifyProvenDecryptionShare(CONTEXT, 8, PUBLIC_KEY, card.A, share)).toBe(false);
    expect(
      verifyProvenDecryptionShare({ ...CONTEXT, phase: "round.0.deal.0" }, 7, PUBLIC_KEY, card.A, share),
    ).toBe(false);
    expect(
      verifyProvenDecryptionShare(
        CONTEXT,
        7,
        RistrettoPoint.base().multiply(scalarFromBigInt(4n)),
        card.A,
        share,
      ),
    ).toBe(false);
    expect(
      verifyProvenDecryptionShare(CONTEXT, 7, PUBLIC_KEY, card.A, {
        ...share,
        S: share.S.add(RistrettoPoint.base()),
      }),
    ).toBe(false);
  });

  it("rejects positions outside the platform deck limit", () => {
    expect(() =>
      createProvenDecryptionShare(CONTEXT, 128, SECRET, card.A, scalarSource(13)),
    ).toThrow(RangeError);
  });
});

function scalarSource(value: number): RandomSource {
  return {
    fill(target) {
      target.fill(0);
      target[0] = value;
    },
  };
}
