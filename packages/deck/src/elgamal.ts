import {
  RISTRETTO_SCALAR_ZERO,
  RistrettoPoint,
  type RistrettoScalar,
} from "@p2pcards/crypto";

export interface MaskedCard {
  readonly A: RistrettoPoint;
  readonly B: RistrettoPoint;
}

export function initialMaskedCard(message: RistrettoPoint): MaskedCard {
  return Object.freeze({ A: RistrettoPoint.identity(), B: message });
}

export function maskCard(
  message: RistrettoPoint,
  randomness: RistrettoScalar,
  aggregateKey: RistrettoPoint,
): MaskedCard {
  requireMaskingInputs(randomness, aggregateKey);
  return Object.freeze({
    A: RistrettoPoint.base().multiply(randomness),
    B: message.add(aggregateKey.multiply(randomness)),
  });
}

export function remaskCard(
  card: MaskedCard,
  randomness: RistrettoScalar,
  aggregateKey: RistrettoPoint,
): MaskedCard {
  requireMaskingInputs(randomness, aggregateKey);
  return Object.freeze({
    A: card.A.add(RistrettoPoint.base().multiply(randomness)),
    B: card.B.add(aggregateKey.multiply(randomness)),
  });
}

export function aggregatePublicKeys(keys: readonly RistrettoPoint[]): RistrettoPoint {
  if (keys.length === 0) {
    throw new RangeError("At least one public key is required");
  }

  let aggregate = RistrettoPoint.identity();
  for (const key of keys) {
    if (key.isIdentity()) {
      throw new TypeError("Individual public keys must not be the identity point");
    }
    aggregate = aggregate.add(key);
  }
  if (aggregate.isIdentity()) {
    throw new TypeError("Aggregate public key must not be the identity point");
  }
  return aggregate;
}

export function decryptionShare(
  secretKey: RistrettoScalar,
  cardA: RistrettoPoint,
): RistrettoPoint {
  if (secretKey === RISTRETTO_SCALAR_ZERO) {
    throw new TypeError("Decryption secret must be non-zero");
  }
  return cardA.multiply(secretKey);
}

export function removeDecryptionShares(
  card: MaskedCard,
  shares: readonly RistrettoPoint[],
): RistrettoPoint {
  let message = card.B;
  for (const share of shares) {
    message = message.subtract(share);
  }
  return message;
}

function requireMaskingInputs(
  randomness: RistrettoScalar,
  aggregateKey: RistrettoPoint,
): void {
  if (randomness === RISTRETTO_SCALAR_ZERO) {
    throw new TypeError("Fresh masking randomness must be non-zero");
  }
  if (aggregateKey.isIdentity()) {
    throw new TypeError("Aggregate public key must not be the identity point");
  }
}
