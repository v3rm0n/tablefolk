import { concatBytes, encodeRistrettoScalar, RistrettoPoint } from "@p2pcards/crypto";
import { encodeCanonical } from "@p2pcards/encoding";
import { parseGameId, parseHash256, type GameId, type Hash256 } from "@p2pcards/protocol";
import type { MaskedCard } from "./elgamal";
import type { DeckShuffleWitness } from "./shuffle";
import { MAX_SHUFFLE_CARDS, shuffleCardCount, type ShuffleDimensions } from "./shuffle-dimensions";

export const CANDIDATE_SHUFFLE_STATEMENT_PROFILE = "bg-ristretto255-statement-candidate-v2";
const HEADER = new Uint8Array([0x8a, ...encodeCanonical(CANDIDATE_SHUFFLE_STATEMENT_PROFILE)]);
const FIXED_BYTES = HEADER.length + 17 + 1 + 34 + 34 + 2 * 3;
const MIN_BYTES = FIXED_BYTES + 2 + 1 + 2 * 4 * 64;
const MAX_BYTES = FIXED_BYTES + 3 + 9 + 2 * MAX_SHUFFLE_CARDS * 64;

export interface CandidateShuffleStatement extends ShuffleDimensions {
  readonly gameId: GameId;
  readonly round: number;
  readonly seat: number;
  readonly rosterHash: Hash256;
  readonly aggregateKey: RistrettoPoint;
  readonly inputDeck: readonly MaskedCard[];
  readonly outputDeck: readonly MaskedCard[];
}

/** Public statement encoding only; caller must establish roster/deck provenance. */
export function encodeCandidateShuffleStatement(value: CandidateShuffleStatement): Uint8Array {
  const { rows, columns } = value;
  const cardCount = shuffleCardCount({ rows, columns });
  const game = parseGameId(value.gameId), roster = parseHash256(value.rosterHash);
  const round = value.round, seat = value.seat;
  if (!Number.isSafeInteger(round) || round < 0 || Object.is(round, -0) ||
    !Number.isInteger(seat) || seat < 0 || seat > 3 || Object.is(seat, -0)) {
    throw new RangeError("Invalid shuffle round or seat");
  }
  const key = pointBytes(value.aggregateKey);
  if (value.aggregateKey.isIdentity()) { throw new Error("Identity shuffle key"); }
  return encodeCanonical([CANDIDATE_SHUFFLE_STATEMENT_PROFILE, rows, columns, game, round, seat,
    roster, key, packShuffleDeck(value.inputDeck, cardCount), packShuffleDeck(value.outputDeck, cardCount)]);
}

/** Fixed CBOR grammar: no untrusted lengths reach a general-purpose decoder. */
export function decodeCandidateShuffleStatement(bytes: Uint8Array): CandidateShuffleStatement {
  if (!(bytes instanceof Uint8Array) || bytes.constructor !== Uint8Array ||
    bytes.length < MIN_BYTES || bytes.length > MAX_BYTES) {
    throw new Error("Invalid shuffle statement byte length");
  }
  let offset = 0;
  function exact(expected: Uint8Array): void {
    for (const byte of expected) { if (bytes[offset++] !== byte) throw new Error("Invalid shuffle statement header"); }
  }
  function fixed(size: number): Uint8Array {
    exact(size < 24 ? new Uint8Array([0x40 + size]) : size < 256
      ? new Uint8Array([0x58, size]) : new Uint8Array([0x59, size >> 8, size & 255]));
    const result = bytes.slice(offset, offset + size); offset += size;
    if (result.length !== size) throw new Error("Truncated shuffle statement");
    return result;
  }
  exact(HEADER);
  function unsigned(): number {
    const tag = bytes[offset++]!;
    if (tag < 24) return tag;
    const count = tag === 24 ? 1 : tag === 25 ? 2 : tag === 26 ? 4 : tag === 27 ? 8 : 0;
    if (!count) throw new Error("Invalid shuffle integer encoding");
    let wide = 0n;
    for (let i = 0; i < count; i++) wide = wide * 256n + BigInt(bytes[offset++]!);
    const min = count === 1 ? 24n : count === 2 ? 256n : count === 4 ? 65536n : 4294967296n;
    if (wide < min || wide > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("Noncanonical shuffle integer");
    return Number(wide);
  }
  const rows = unsigned(), columns = unsigned();
  const cardCount = shuffleCardCount({ rows, columns });
  const gameId = parseGameId(fixed(16));
  const round = unsigned();
  if (bytes.length - offset !== 1 + 34 + 34 + 2 * (3 + cardCount * 64)) {
    throw new Error("Invalid shuffle statement byte length");
  }
  const seat = bytes[offset++]!;
  if (seat > 3) throw new Error("Invalid shuffle seat");
  const rosterHash = parseHash256(fixed(32));
  const aggregateKey = RistrettoPoint.fromBytes(fixed(32));
  if (aggregateKey.isIdentity()) throw new Error("Identity shuffle key");
  const inputDeck = unpackShuffleDeck(fixed(cardCount * 64), cardCount);
  const outputDeck = unpackShuffleDeck(fixed(cardCount * 64), cardCount);
  if (offset !== bytes.length) throw new Error("Trailing shuffle statement bytes");
  return Object.freeze({ rows, columns, gameId, round, seat, rosterHash, aggregateKey, inputDeck, outputDeck });
}

/** PRIVATE local worker input. Never include these bytes in messages or logs. */
export function encodeCandidateShuffleWitness(witness: DeckShuffleWitness, dimensions: ShuffleDimensions): {
  readonly permutation: Uint8Array; readonly randomizers: Uint8Array;
} {
  const cardCount = shuffleCardCount(dimensions);
  if (!Array.isArray(witness.permutation) || witness.permutation.length !== cardCount ||
    !Array.isArray(witness.randomizers) || witness.randomizers.length !== cardCount) throw new Error("Invalid witness lengths");
  const permutation = new Uint8Array(cardCount), seen = new Set<number>();
  const scalars: Uint8Array[] = [];
  for (let i = 0; i < cardCount; i++) {
    const p = witness.permutation[i]!;
    if (!Number.isInteger(p) || p < 0 || p >= cardCount || Object.is(p, -0) || seen.has(p)) throw new Error("Invalid permutation");
    seen.add(p); permutation[i] = p;
    const scalar = witness.randomizers[i]!;
    if (scalar === 0n) throw new Error("Zero shuffle randomizer");
    scalars.push(encodeRistrettoScalar(scalar));
  }
  return Object.freeze({ permutation, randomizers: concatBytes(...scalars) });
}

function pointBytes(point: RistrettoPoint): Uint8Array {
  if (!(point instanceof RistrettoPoint)) throw new TypeError("Expected Ristretto point");
  return point.toBytes();
}
/** Pack ordered ciphertexts as contiguous canonical A/B point pairs. */
export function packShuffleDeck(deck: readonly MaskedCard[], cardCount: number): Uint8Array {
  assertCardCount(cardCount);
  if (!Array.isArray(deck) || deck.length !== cardCount) throw new Error("Unexpected shuffle deck size");
  return concatBytes(...Array.from(deck, (card) => concatBytes(pointBytes(card.A), pointBytes(card.B))));
}
export function unpackShuffleDeck(bytes: Uint8Array, cardCount: number): readonly MaskedCard[] {
  assertCardCount(cardCount);
  if (!(bytes instanceof Uint8Array) || bytes.constructor !== Uint8Array || bytes.length !== cardCount * 64) {
    throw new Error("Invalid packed shuffle deck byte length");
  }
  return Object.freeze(Array.from({ length: cardCount }, (_, i) => Object.freeze({
    A: RistrettoPoint.fromBytes(bytes.slice(i * 64, i * 64 + 32)),
    B: RistrettoPoint.fromBytes(bytes.slice(i * 64 + 32, i * 64 + 64)),
  })));
}

function assertCardCount(cardCount: number): void {
  if (!Number.isInteger(cardCount) || cardCount < 4 || cardCount > MAX_SHUFFLE_CARDS) {
    throw new RangeError("Invalid shuffle card count");
  }
}
