import {
  addRistrettoScalars,
  multiplyRistrettoScalars,
  randomNonZeroRistrettoScalar,
  RISTRETTO_SCALAR_ZERO,
  RistrettoPoint,
  type RandomSource,
  type RistrettoScalar,
} from "@p2pcards/crypto";
import { proofChallengeScalar, type ProofContext } from "@p2pcards/protocol";

import { decryptionShare } from "./elgamal";

export interface SchnorrProofOfPossession {
  readonly R: RistrettoPoint;
  readonly z: RistrettoScalar;
}

export interface GameKeyShare {
  readonly H: RistrettoPoint;
  readonly pop: SchnorrProofOfPossession;
}

export interface ChaumPedersenProof {
  readonly R1: RistrettoPoint;
  readonly R2: RistrettoPoint;
  readonly z: RistrettoScalar;
}

export interface ProvenDecryptionShare {
  readonly S: RistrettoPoint;
  readonly proof: ChaumPedersenProof;
}

export function createGameKeyShare(
  context: ProofContext,
  secretKey: RistrettoScalar,
  source?: RandomSource,
): GameKeyShare {
  requireNonZeroScalar(secretKey, "Game secret");

  const H = RistrettoPoint.base().multiply(secretKey);
  const nonce = randomNonZeroRistrettoScalar(source);
  const R = RistrettoPoint.base().multiply(nonce);
  const challenge = keyProofChallenge(context, H, R);
  const z = addRistrettoScalars(nonce, multiplyRistrettoScalars(challenge, secretKey));

  return Object.freeze({ H, pop: Object.freeze({ R, z }) });
}

export function verifyGameKeyShare(context: ProofContext, share: GameKeyShare): boolean {
  try {
    if (share.H.isIdentity()) {
      return false;
    }
    const challenge = keyProofChallenge(context, share.H, share.pop.R);
    const left = RistrettoPoint.base().multiply(share.pop.z);
    const right = share.pop.R.add(share.H.multiply(challenge));
    return left.equals(right);
  } catch {
    return false;
  }
}

export function createProvenDecryptionShare(
  context: ProofContext,
  position: number,
  secretKey: RistrettoScalar,
  cardA: RistrettoPoint,
  source?: RandomSource,
): ProvenDecryptionShare {
  requirePosition(position);
  requireNonZeroScalar(secretKey, "Game secret");

  const H = RistrettoPoint.base().multiply(secretKey);
  const S = decryptionShare(secretKey, cardA);
  const nonce = randomNonZeroRistrettoScalar(source);
  const R1 = RistrettoPoint.base().multiply(nonce);
  const R2 = cardA.multiply(nonce);
  const challenge = decryptionProofChallenge(context, position, H, cardA, S, R1, R2);
  const z = addRistrettoScalars(nonce, multiplyRistrettoScalars(challenge, secretKey));

  return Object.freeze({
    S,
    proof: Object.freeze({ R1, R2, z }),
  });
}

export function verifyProvenDecryptionShare(
  context: ProofContext,
  position: number,
  publicKey: RistrettoPoint,
  cardA: RistrettoPoint,
  share: ProvenDecryptionShare,
): boolean {
  try {
    requirePosition(position);
    if (publicKey.isIdentity()) {
      return false;
    }

    const { R1, R2, z } = share.proof;
    const challenge = decryptionProofChallenge(
      context,
      position,
      publicKey,
      cardA,
      share.S,
      R1,
      R2,
    );
    const firstEquation = RistrettoPoint.base()
      .multiply(z)
      .equals(R1.add(publicKey.multiply(challenge)));
    const secondEquation = cardA.multiply(z).equals(R2.add(share.S.multiply(challenge)));
    return firstEquation && secondEquation;
  } catch {
    return false;
  }
}

function keyProofChallenge(
  context: ProofContext,
  publicKey: RistrettoPoint,
  commitment: RistrettoPoint,
): RistrettoScalar {
  return proofChallengeScalar("proofOfPossession", context, {
    H: publicKey.toBytes(),
    R: commitment.toBytes(),
  });
}

function decryptionProofChallenge(
  context: ProofContext,
  position: number,
  publicKey: RistrettoPoint,
  cardA: RistrettoPoint,
  share: RistrettoPoint,
  firstCommitment: RistrettoPoint,
  secondCommitment: RistrettoPoint,
): RistrettoScalar {
  return proofChallengeScalar("decryptionShare", context, {
    pos: position,
    H: publicKey.toBytes(),
    A: cardA.toBytes(),
    S: share.toBytes(),
    R1: firstCommitment.toBytes(),
    R2: secondCommitment.toBytes(),
  });
}

function requireNonZeroScalar(value: RistrettoScalar, label: string): void {
  if (value === RISTRETTO_SCALAR_ZERO) {
    throw new TypeError(`${label} must be non-zero`);
  }
}

function requirePosition(value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 127) {
    throw new RangeError("Card position must be an integer from 0 through 127");
  }
}
