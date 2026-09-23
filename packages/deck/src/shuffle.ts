import {
  randomNonZeroRistrettoScalar,
  randomPermutation,
  RistrettoPoint,
  type RandomSource,
  type RistrettoScalar,
} from "@p2pcards/crypto";

import { MAX_DECK_SIZE, MIN_DECK_SIZE } from "./card-points";
import { remaskCard, type MaskedCard } from "./elgamal";

/** Private prover input. Never broadcast, log, or include this witness in a transcript. */
export interface DeckShuffleWitness {
  /** Output position j takes its input card from permutation[j]. */
  readonly permutation: readonly number[];
  /** Fresh remasking scalars, indexed by output position, not input position. */
  readonly randomizers: readonly RistrettoScalar[];
}

/** Local preparation only: this contains secrets and is not a verified shuffle. */
export interface UnprovenDeckShuffle {
  readonly aggregateKey: RistrettoPoint;
  readonly inputDeck: readonly MaskedCard[];
  readonly outputDeck: readonly MaskedCard[];
  readonly witness: DeckShuffleWitness;
}

/**
 * Apply the specification's permutation/remasking relation using fresh private
 * randomness. A separately profiled prover/verifier must establish this relation
 * before a peer can accept the output deck. The public beacon is not an RNG here.
 */
export function createUnprovenDeckShuffle(
  deck: readonly MaskedCard[],
  aggregateKey: RistrettoPoint,
  source?: RandomSource,
): UnprovenDeckShuffle {
  if (!Array.isArray(deck)) {
    throw new TypeError("Shuffle input deck must be an array");
  }
  const size = deck.length;
  if (size < MIN_DECK_SIZE || size > MAX_DECK_SIZE) {
    throw new RangeError(`Shuffle input deck must contain ${MIN_DECK_SIZE} to ${MAX_DECK_SIZE} cards`);
  }
  const key = copyPoint(aggregateKey);
  if (key.isIdentity()) {
    throw new TypeError("Shuffle aggregate key must not be the identity point");
  }

  // Validate and detach the complete statement before invoking the RNG callback.
  const input: MaskedCard[] = [];
  for (let position = 0; position < size; position += 1) {
    const card = deck[position];
    if (typeof card !== "object" || card === null) {
      throw new TypeError(`Shuffle input card ${position} must contain Ristretto points`);
    }
    input.push(Object.freeze({ A: copyPoint(card.A), B: copyPoint(card.B) }));
  }
  const inputDeck = Object.freeze(input);
  const permutation = randomPermutation(size, source);
  const randomizers = Object.freeze(
    Array.from({ length: size }, () => randomNonZeroRistrettoScalar(source)),
  );
  const outputDeck = Object.freeze(
    permutation.map((inputPosition, outputPosition) =>
      remaskCard(inputDeck[inputPosition]!, randomizers[outputPosition]!, key),
    ),
  );

  return Object.freeze({
    aggregateKey: key,
    inputDeck,
    outputDeck,
    witness: Object.freeze({ permutation, randomizers }),
  });
}

function copyPoint(value: RistrettoPoint): RistrettoPoint {
  if (!(value instanceof RistrettoPoint)) {
    throw new TypeError("Shuffle inputs must contain Ristretto points");
  }
  return RistrettoPoint.fromBytes(value.toBytes());
}
