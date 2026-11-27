import { decodeRistrettoScalar, RistrettoPoint } from "@p2pcards/crypto";
import { encodeCanonical } from "@p2pcards/encoding";
import { shuffleCardCount, type ShuffleDimensions } from "./shuffle-dimensions";

/** Encoding candidate only; successful decoding does not verify a shuffle. */
export const CANDIDATE_SHUFFLE_PROOF_PROFILE = "bg-ristretto255-proof-candidate-v2";

// Pinned upstream field order; ciphertexts contribute A then B as two points.
function grammar({ rows: m, columns: n }: ShuffleDimensions) {
  shuffleCardCount({ rows: m, columns: n });
  const sections = [
    ["point", m], ["point", m], ["point", 1], ["point", m],
    ["point", 2], ["point", 2 * m + 1], ["scalar", n], ["scalar", n], ["scalar", 3],
    ["point", 3], ["scalar", n], ["scalar", n], ["scalar", 2],
    ["point", 1], ["point", 2 * m], ["point", 4 * m], ["scalar", 4], ["scalar", n],
  ] as const;
  const kinds = sections.flatMap(([kind, count]) => Array.from({ length: count }, () => kind));
  const count = kinds.length;
  const arrayHeader = count < 256 ? [0x98, count] : [0x99, count >> 8, count & 255];
  const header = new Uint8Array([0x84, ...encodeCanonical(CANDIDATE_SHUFFLE_PROOF_PROFILE),
    ...encodeCanonical(m), ...encodeCanonical(n), ...arrayHeader]);
  return { kinds, header, size: header.length + count * 34 };
}

/** Fixed grammar: [profile, rows, columns, canonical 32-byte strings]. */
export function decodeCandidateShuffleProof(bytes: Uint8Array, dimensions: ShuffleDimensions): readonly Uint8Array[] {
  const { kinds, header, size } = grammar(dimensions);
  assertBytes(bytes);
  if (bytes.length !== size) {
    throw new Error("Candidate shuffle proof has an incorrect byte length");
  }
  for (let i = 0; i < header.length; i++) {
    if (bytes[i] !== header[i]) { throw new Error("Incorrect candidate shuffle proof header"); }
  }
  // No generic CBOR decoder sees untrusted lengths or nesting.
  const elements: Uint8Array[] = [];
  for (let i = 0; i < kinds.length; i++) {
    const offset = header.length + i * 34;
    if (bytes[offset] !== 0x58 || bytes[offset + 1] !== 32) {
      throw new Error("Candidate shuffle proof elements must be canonical 32-byte strings");
    }
    const element = bytes.slice(offset + 2, offset + 34);
    validateElement(element, kinds[i]!);
    elements.push(element);
  }
  return Object.freeze(elements);
}

export function encodeCandidateShuffleProof(elements: readonly Uint8Array[], dimensions: ShuffleDimensions): Uint8Array {
  const { kinds, header, size } = grammar(dimensions);
  if (!Array.isArray(elements) || elements.length !== kinds.length) {
    throw new Error("Incorrect candidate shuffle proof element count");
  }
  const bytes = new Uint8Array(size);
  bytes.set(header);
  for (let i = 0; i < kinds.length; i++) {
    const element = elements[i]!;
    assertBytes(element);
    validateElement(element, kinds[i]!);
    const offset = header.length + i * 34;
    bytes.set([0x58, 32], offset);
    bytes.set(element, offset + 2);
  }
  return bytes;
}

function validateElement(bytes: Uint8Array, kind: "point" | "scalar"): void {
  if (kind === "point") { RistrettoPoint.fromBytes(bytes); }
  else { decodeRistrettoScalar(bytes); }
}

function assertBytes(value: unknown): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array) || value.constructor !== Uint8Array) {
    throw new TypeError("Candidate proof bytes must be a plain Uint8Array");
  }
}
