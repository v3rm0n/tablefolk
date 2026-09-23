import { decodeRistrettoScalar, RistrettoPoint } from "@p2pcards/crypto";
import { encodeCanonical } from "@p2pcards/encoding";

/** Encoding candidate only; successful decoding does not verify a shuffle. */
export const CANDIDATE_SHUFFLE_PROOF_36_PROFILE = "bg-ristretto255-36-4x9-proof-candidate-v1";

// Pinned upstream field order; ciphertexts contribute A then B as two points.
const SECTIONS = [
  ["point", 4], ["point", 4], ["point", 1], ["point", 4],
  ["point", 2], ["point", 9], ["scalar", 9], ["scalar", 9], ["scalar", 3],
  ["point", 3], ["scalar", 9], ["scalar", 9], ["scalar", 2],
  ["point", 1], ["point", 8], ["point", 16], ["scalar", 4], ["scalar", 9],
] as const;
const KINDS = SECTIONS.flatMap(([kind, count]) => Array.from({ length: count }, () => kind));
const HEADER = new Uint8Array([0x82, ...encodeCanonical(CANDIDATE_SHUFFLE_PROOF_36_PROFILE), 0x98, 106]);
export const CANDIDATE_SHUFFLE_PROOF_36_BYTES = HEADER.length + 106 * 34;

/** Fixed grammar: [profile text, 106 canonical 32-byte strings]. */
export function decodeCandidateShuffleProof36(bytes: Uint8Array): readonly Uint8Array[] {
  assertBytes(bytes);
  if (bytes.length !== CANDIDATE_SHUFFLE_PROOF_36_BYTES) {
    throw new Error("Candidate shuffle proof has an incorrect byte length");
  }
  for (let i = 0; i < HEADER.length; i++) {
    if (bytes[i] !== HEADER[i]) { throw new Error("Incorrect candidate shuffle proof header"); }
  }
  // No generic CBOR decoder sees untrusted lengths or nesting.
  const elements: Uint8Array[] = [];
  for (let i = 0; i < 106; i++) {
    const offset = HEADER.length + i * 34;
    if (bytes[offset] !== 0x58 || bytes[offset + 1] !== 32) {
      throw new Error("Candidate shuffle proof elements must be canonical 32-byte strings");
    }
    const element = bytes.slice(offset + 2, offset + 34);
    validateElement(element, i);
    elements.push(element);
  }
  return Object.freeze(elements);
}

export function encodeCandidateShuffleProof36(elements: readonly Uint8Array[]): Uint8Array {
  if (!Array.isArray(elements) || elements.length !== 106) {
    throw new Error("Candidate shuffle proof must contain exactly 106 elements");
  }
  const bytes = new Uint8Array(CANDIDATE_SHUFFLE_PROOF_36_BYTES);
  bytes.set(HEADER);
  for (let i = 0; i < 106; i++) {
    const element = elements[i]!;
    assertBytes(element);
    validateElement(element, i);
    const offset = HEADER.length + i * 34;
    bytes.set([0x58, 32], offset);
    bytes.set(element, offset + 2);
  }
  return bytes;
}

function validateElement(bytes: Uint8Array, index: number): void {
  if (KINDS[index] === "point") { RistrettoPoint.fromBytes(bytes); }
  else { decodeRistrettoScalar(bytes); }
}

function assertBytes(value: unknown): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array) || value.constructor !== Uint8Array) {
    throw new TypeError("Candidate proof bytes must be a plain Uint8Array");
  }
}
