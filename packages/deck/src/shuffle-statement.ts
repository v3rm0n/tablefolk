import { concatBytes, encodeRistrettoScalar, RistrettoPoint } from "@p2pcards/crypto";
import { encodeCanonical } from "@p2pcards/encoding";
import { parseGameId, parseHash256, type GameId, type Hash256 } from "@p2pcards/protocol";
import type { MaskedCard } from "./elgamal";
import type { DeckShuffleWitness } from "./shuffle";

export const CANDIDATE_SHUFFLE_STATEMENT_PROFILE = "bg-ristretto255-36-4x9-statement-candidate-v1";
const HEADER = new Uint8Array([0x88, ...encodeCanonical(CANDIDATE_SHUFFLE_STATEMENT_PROFILE)]);
export const MIN_CANDIDATE_SHUFFLE_STATEMENT_BYTES = HEADER.length + 17 + 1 + 1 + 34 + 34 + 2 * 2307;
export const MAX_CANDIDATE_SHUFFLE_STATEMENT_BYTES = MIN_CANDIDATE_SHUFFLE_STATEMENT_BYTES + 8;

export interface CandidateShuffleStatement36 {
  readonly gameId: GameId;
  readonly round: number;
  readonly seat: number;
  readonly rosterHash: Hash256;
  readonly aggregateKey: RistrettoPoint;
  readonly inputDeck: readonly MaskedCard[];
  readonly outputDeck: readonly MaskedCard[];
}

/** Public statement encoding only; caller must establish roster/deck provenance. */
export function encodeCandidateShuffleStatement36(value: CandidateShuffleStatement36): Uint8Array {
  const game = parseGameId(value.gameId), roster = parseHash256(value.rosterHash);
  const round = value.round, seat = value.seat;
  if (!Number.isSafeInteger(round) || round < 0 || Object.is(round, -0) ||
    !Number.isInteger(seat) || seat < 0 || seat > 3 || Object.is(seat, -0)) {
    throw new RangeError("Invalid shuffle round or seat");
  }
  const key = pointBytes(value.aggregateKey);
  if (RistrettoPoint.fromBytes(key).isIdentity()) { throw new Error("Identity shuffle key"); }
  return encodeCanonical([CANDIDATE_SHUFFLE_STATEMENT_PROFILE, game, round, seat,
    roster, key, packDeck(value.inputDeck), packDeck(value.outputDeck)]);
}

/** Fixed CBOR grammar: no untrusted lengths reach a general-purpose decoder. */
export function decodeCandidateShuffleStatement36(bytes: Uint8Array): CandidateShuffleStatement36 {
  if (!(bytes instanceof Uint8Array) || bytes.constructor !== Uint8Array ||
    bytes.length < MIN_CANDIDATE_SHUFFLE_STATEMENT_BYTES || bytes.length > MAX_CANDIDATE_SHUFFLE_STATEMENT_BYTES) {
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
  const gameId = parseGameId(fixed(16));
  const tag = bytes[offset++]!;
  let round: number;
  if (tag < 24) round = tag;
  else {
    const count = tag === 24 ? 1 : tag === 25 ? 2 : tag === 26 ? 4 : tag === 27 ? 8 : 0;
    if (!count) throw new Error("Invalid shuffle round encoding");
    let wide = 0n;
    for (let i = 0; i < count; i++) wide = wide * 256n + BigInt(bytes[offset++]!);
    const min = count === 1 ? 24n : count === 2 ? 256n : count === 4 ? 65536n : 4294967296n;
    if (wide < min || wide > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("Noncanonical shuffle round");
    round = Number(wide);
  }
  const seat = bytes[offset++]!;
  if (seat > 3) throw new Error("Invalid shuffle seat");
  const rosterHash = parseHash256(fixed(32));
  const aggregateKey = RistrettoPoint.fromBytes(fixed(32));
  if (aggregateKey.isIdentity()) throw new Error("Identity shuffle key");
  const inputDeck = unpackDeck(fixed(2304)), outputDeck = unpackDeck(fixed(2304));
  if (offset !== bytes.length) throw new Error("Trailing shuffle statement bytes");
  return Object.freeze({ gameId, round, seat, rosterHash, aggregateKey, inputDeck, outputDeck });
}

/** PRIVATE local worker input. Never include these bytes in messages or logs. */
export function encodeCandidateShuffleWitness36(witness: DeckShuffleWitness): {
  readonly permutation: Uint8Array; readonly randomizers: Uint8Array;
} {
  if (!Array.isArray(witness.permutation) || witness.permutation.length !== 36 ||
    !Array.isArray(witness.randomizers) || witness.randomizers.length !== 36) throw new Error("Invalid witness lengths");
  const permutation = new Uint8Array(36), seen = new Set<number>();
  const scalars: Uint8Array[] = [];
  for (let i = 0; i < 36; i++) {
    const p = witness.permutation[i]!;
    if (!Number.isInteger(p) || p < 0 || p >= 36 || Object.is(p, -0) || seen.has(p)) throw new Error("Invalid permutation");
    seen.add(p); permutation[i] = p;
    const scalar = witness.randomizers[i]!;
    if (scalar === 0n) throw new Error("Zero shuffle randomizer");
    scalars.push(encodeRistrettoScalar(scalar));
  }
  return Object.freeze({ permutation, randomizers: concatBytes(...scalars) });
}

function pointBytes(point: RistrettoPoint): Uint8Array {
  if (!(point instanceof RistrettoPoint)) throw new TypeError("Expected Ristretto point");
  const bytes = point.toBytes(); RistrettoPoint.fromBytes(bytes); return bytes;
}
function packDeck(deck: readonly MaskedCard[]): Uint8Array {
  if (!Array.isArray(deck) || deck.length !== 36) throw new Error("Expected 36 ciphertexts");
  return concatBytes(...Array.from(deck, (card) => concatBytes(pointBytes(card.A), pointBytes(card.B))));
}
function unpackDeck(bytes: Uint8Array): readonly MaskedCard[] {
  return Object.freeze(Array.from({ length: 36 }, (_, i) => Object.freeze({
    A: RistrettoPoint.fromBytes(bytes.slice(i * 64, i * 64 + 32)),
    B: RistrettoPoint.fromBytes(bytes.slice(i * 64 + 32, i * 64 + 64)),
  })));
}
