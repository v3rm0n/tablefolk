import {
  concatBytes,
  reduceWideRistrettoScalar,
  sha256,
  sha512,
  type RistrettoScalar,
  type Sha256Digest,
  type Sha512Digest,
} from "@p2pcards/crypto";
import {
  encodeCanonical,
  type CanonicalCbor,
  type CborValue,
} from "@p2pcards/encoding";

import { domainSeparator, type DomainPurpose } from "./domains";
import type { DtlsFingerprint, GameId, RandomSecret } from "./fields";

export interface ProofContext {
  readonly gameId: GameId;
  readonly round: number;
  readonly phase: string;
}

export type ProofDomainPurpose = "proofOfPossession" | "decryptionShare" | "shuffle";

export function deriveSignalingRoomId(gameId: GameId): Sha256Digest {
  return sha256(domainSeparator("room"), gameId);
}

export function channelAuthenticationInput(
  gameId: GameId,
  localFingerprint: DtlsFingerprint,
  remoteFingerprint: DtlsFingerprint,
): Uint8Array {
  return concatBytes(
    domainSeparator("channel"),
    gameId,
    localFingerprint,
    remoteFingerprint,
  );
}

export function envelopeSignatureInput(canonicalEnvelopeWithoutSignature: CanonicalCbor): Uint8Array {
  return concatBytes(domainSeparator("message"), canonicalEnvelopeWithoutSignature);
}

export function hashEnvelope(canonicalEnvelopeWithSignature: CanonicalCbor): Sha256Digest {
  return sha256(canonicalEnvelopeWithSignature);
}

export function cardDerivationHash(deckSpecId: string, cardId: string): Sha512Digest {
  requireNonEmptyText(deckSpecId, "deckSpecId");
  requireNonEmptyText(cardId, "cardId");
  return sha512(
    domainSeparator("card"),
    encodeCanonical(deckSpecId),
    encodeCanonical(cardId),
  );
}

export function beaconCommitment(
  gameId: GameId,
  round: number,
  seat: number,
  secret: RandomSecret,
): Sha256Digest {
  requireUnsignedSafeInteger(round, "round");
  requireSeat(seat);
  return sha256(
    domainSeparator("beacon"),
    gameId,
    encodeCanonical(round),
    encodeCanonical(seat),
    secret,
  );
}

export function proofChallengeInput(
  purpose: ProofDomainPurpose,
  context: ProofContext,
  statement: CborValue,
): Uint8Array {
  requireUnsignedSafeInteger(context.round, "round");
  requireNonEmptyText(context.phase, "phase");
  return concatBytes(
    domainSeparator(purpose),
    context.gameId,
    encodeCanonical(context.round),
    encodeCanonical(context.phase),
    encodeCanonical(statement),
  );
}

export function proofChallengeScalar(
  purpose: ProofDomainPurpose,
  context: ProofContext,
  statement: CborValue,
): RistrettoScalar {
  return reduceWideRistrettoScalar(sha512(proofChallengeInput(purpose, context, statement)));
}

export function framedDomainInput(
  purpose: DomainPurpose,
  ...values: readonly CborValue[]
): Uint8Array {
  return concatBytes(domainSeparator(purpose), ...values.map((value) => encodeCanonical(value)));
}

function requireUnsignedSafeInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${label} must be an unsigned safe integer`);
  }
}

function requireSeat(value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 7) {
    throw new RangeError("seat must be an integer from 0 through 7");
  }
}

function requireNonEmptyText(value: string, label: string): void {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${label} must be a non-empty text string`);
  }
}
