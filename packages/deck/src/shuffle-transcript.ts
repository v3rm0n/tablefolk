import { asciiToBytes, encodeRistrettoScalar, reduceWideRistrettoScalar, sha512, type RistrettoScalar } from "@p2pcards/crypto";
import { encodeCanonical, type CborValue } from "@p2pcards/encoding";
import { proofChallengeInput, parseGameId, type ProofContext } from "@p2pcards/protocol";

export const CANDIDATE_SHUFFLE_TRANSCRIPT_PROFILE = "bg-ristretto255-36-4x9-fs-candidate-v1";

export interface CandidateShuffleChallenge {
  readonly input: Uint8Array;
  readonly digest: Uint8Array;
  readonly scalar: RistrettoScalar;
}

/** Experimental transcript framing, not a statement validator or proof verifier. */
export class CandidateShuffleTranscript {
  readonly #root: Uint8Array;
  readonly #context: ProofContext;
  readonly #events: CborValue[] = [];
  #eventBytes = 0;

  constructor(root: Uint8Array, context: ProofContext) {
    this.#root = capture(root, 1, 1024);
    const gameId = parseGameId(capture(context.gameId, 16, 16));
    const round = context.round, phase = context.phase;
    if (!Number.isSafeInteger(round) || round < 0 || Object.is(round, -0) ||
      typeof phase !== "string" || !/^[\x00-\x7f]{1,64}$/.test(phase)) {
      throw new RangeError("Candidate transcript context bound");
    }
    this.#context = { gameId, round, phase };
  }

  label(label: Uint8Array): void {
    this.#push([0, capture(label, 1, 64)]);
  }

  /** The pinned backend's compressed public serialization, explicitly framed. */
  appendPublicBytes(bytes: Uint8Array): void {
    this.#push([1, capture(bytes, 0, 8192)]);
  }

  challenge(label: Uint8Array): { read(): CandidateShuffleChallenge } {
    const capturedLabel = capture(label, 1, 64);
    let index = 0;
    let expectedLength = this.#events.length;
    return Object.freeze({ read: (): CandidateShuffleChallenge => {
      if (expectedLength !== this.#events.length) { throw new Error("Stale challenge reader"); }
      if (index >= 16) { throw new Error("Candidate challenge count bound"); }
      const input = proofChallengeInput("shuffle", this.#context, [
        asciiToBytes(CANDIDATE_SHUFFLE_TRANSCRIPT_PROFILE), this.#root, this.#events,
        [2, capturedLabel, index],
      ]);
      const digest = sha512(input);
      const scalar = reduceWideRistrettoScalar(digest);
      this.#push([2, capturedLabel, index, encodeRistrettoScalar(scalar)]);
      index++;
      expectedLength++;
      return Object.freeze({ input, digest, scalar });
    } });
  }

  #push(event: CborValue): void {
    const size = encodeCanonical(event).length;
    if (this.#events.length >= 128 || this.#eventBytes + size > 32768) {
      throw new Error("Candidate transcript event bound");
    }
    this.#events.push(event);
    this.#eventBytes += size;
  }
}

function capture(bytes: Uint8Array, min: number, max: number): Uint8Array {
  if (!(bytes instanceof Uint8Array) || bytes.constructor !== Uint8Array) {
    throw new TypeError("Transcript inputs must be plain Uint8Array values");
  }
  if (bytes.length < min || bytes.length > max) { throw new RangeError("Candidate transcript field bound"); }
  return bytes.slice();
}
