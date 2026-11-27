import { bytesEqual, decodeRistrettoScalar, encodeRistrettoScalar, RistrettoPoint, type RistrettoScalar } from "@p2pcards/crypto";
import {
  decodeCandidateShuffleProof, decodeCandidateShuffleStatement, unpackShuffleDeck,
  type DecryptionShareBatchBackend, type DecryptionShareCard, type ProvenDecryptionShare,
} from "@p2pcards/deck";
import { proofChallengeInput, type ProofContext } from "@p2pcards/protocol";

export interface CandidateShuffleResult { readonly outputDeck: Uint8Array; readonly proof: Uint8Array }
export type CryptoWorkerRequest =
  | { readonly operation: "prove"; readonly statement: Uint8Array; readonly outputDeckBytes: number }
  | { readonly operation: "verify"; readonly statement: Uint8Array; readonly proof: Uint8Array }
  | { readonly operation: "createDleq"; readonly context: Uint8Array; readonly cards: Uint8Array; readonly secret: Uint8Array }
  | { readonly operation: "verifyDleq"; readonly context: Uint8Array; readonly cards: Uint8Array; readonly key: Uint8Array; readonly shares: Uint8Array };

const CARD_BYTES = 33;
const SHARE_BYTES = 128;

export class CandidateShuffleClient implements DecryptionShareBatchBackend {
  #cancel: (() => void) | null = null;
  #worker: Worker | null = null;
  #closed = false;
  constructor(private readonly makeWorker: () => Worker = () => new Worker(new URL("./candidate-shuffle-worker.ts", import.meta.url), { type: "module" }),
    private readonly timeoutMs = 30_000) {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) throw new Error("Invalid shuffle timeout");
  }

  close(): void {
    this.#closed = true;
    this.cancel();
    this.#worker?.terminate();
    this.#worker = null;
  }

  cancel(): void { this.#cancel?.(); }

  async verify(statement: Uint8Array, proof: Uint8Array, signal?: AbortSignal): Promise<boolean> {
    const dimensions = decodeCandidateShuffleStatement(statement);
    decodeCandidateShuffleProof(proof, dimensions);
    return this.#run({ operation: "verify", statement: statement.slice(), proof: proof.slice() }, readValidity, signal);
  }

  async prove(template: Uint8Array, signal?: AbortSignal): Promise<CandidateShuffleResult> {
    const expected = decodeCandidateShuffleStatement(template);
    const statement = template.slice();
    const deckBytes = expected.inputDeck.length * 64;
    const outputStart = statement.length - deckBytes;
    if (!bytesEqual(statement.subarray(outputStart - deckBytes - 3, outputStart - 3), statement.subarray(outputStart))) {
      throw new Error("Invalid shuffle preparation template");
    }
    return this.#run({ operation: "prove", statement, outputDeckBytes: deckBytes }, data => {
      const outputDeck = data["outputDeck"], proof = data["proof"];
      if (!(outputDeck instanceof Uint8Array) || !(proof instanceof Uint8Array)) throw malformed();
      unpackShuffleDeck(outputDeck, expected.inputDeck.length);
      decodeCandidateShuffleProof(proof, expected);
      return Object.freeze({ outputDeck: outputDeck.slice(), proof: proof.slice() });
    }, signal);
  }

  async createDleqBatch(context: ProofContext, secretKey: RistrettoScalar, cards: readonly DecryptionShareCard[]): Promise<readonly ProvenDecryptionShare[]> {
    const prefix = challengePrefix(context), packed = packCards(cards);
    const count = packed.length / CARD_BYTES;
    const secret = encodeRistrettoScalar(secretKey);
    try {
      return this.#run({ operation: "createDleq", context: prefix, cards: packed, secret }, data => {
        const shares = data["shares"];
        if (!(shares instanceof Uint8Array) || shares.length !== count * SHARE_BYTES) throw malformed();
        return Object.freeze(Array.from({ length: count }, (_, index) => {
          const offset = index * SHARE_BYTES;
          return Object.freeze({
            S: RistrettoPoint.fromBytes(shares.subarray(offset, offset + 32)),
            proof: Object.freeze({
              R1: RistrettoPoint.fromBytes(shares.subarray(offset + 32, offset + 64)),
              R2: RistrettoPoint.fromBytes(shares.subarray(offset + 64, offset + 96)),
              z: decodeRistrettoScalar(shares.subarray(offset + 96, offset + SHARE_BYTES)),
            }),
          });
        }));
      });
    } finally {
      // postMessage synchronously clones the request. Wipe the caller-side copy immediately.
      secret.fill(0);
    }
  }

  async verifyDleqBatch(context: ProofContext, key: RistrettoPoint, cards: readonly DecryptionShareCard[], shares: readonly ProvenDecryptionShare[]): Promise<boolean> {
    if (cards.length !== shares.length) throw new RangeError("DLEQ batch lengths must match");
    const packed = new Uint8Array(shares.length * SHARE_BYTES);
    shares.forEach(({ S, proof }, index) => {
      const offset = index * SHARE_BYTES;
      packed.set(S.toBytes(), offset);
      packed.set(proof.R1.toBytes(), offset + 32);
      packed.set(proof.R2.toBytes(), offset + 64);
      packed.set(encodeRistrettoScalar(proof.z), offset + 96);
    });
    return this.#run({ operation: "verifyDleq", context: challengePrefix(context), cards: packCards(cards),
      key: key.toBytes(), shares: packed }, readValidity);
  }

  #run<T>(request: CryptoWorkerRequest, read: (data: Record<string, unknown>) => T, signal?: AbortSignal): Promise<T> {
    if (this.#closed || this.#cancel !== null || signal?.aborted) return Promise.reject(new Error("Shuffle worker closed, busy, or cancelled"));
    return new Promise((resolve, reject) => {
      const worker = this.#worker ?? this.makeWorker();
      this.#worker = worker;
      let settled = false;
      const finish = (error?: unknown, result?: T) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener("abort", cancel);
        worker.onmessage = null;
        worker.onerror = null;
        worker.onmessageerror = null;
        this.#cancel = null;
        if (error !== undefined) {
          worker.terminate();
          this.#worker = null;
          reject(error);
        } else {
          resolve(result!);
        }
      };
      const cancel = () => finish(new Error("Shuffle operation cancelled"));
      const timer = setTimeout(() => finish(new Error("Shuffle worker timed out")), this.timeoutMs);
      this.#cancel = cancel;
      signal?.addEventListener("abort", cancel, { once: true });
      worker.onmessage = ({ data }) => {
        if (settled) return;
        try {
          if (!data || typeof data !== "object" || data.error) throw new Error("Shuffle worker failed");
          finish(undefined, read(data));
        } catch (error) {
          finish(error);
        }
      };
      worker.onerror = () => finish(new Error("Shuffle worker failed"));
      worker.onmessageerror = () => finish(new Error("Shuffle worker response failed"));
      if (signal?.aborted) { cancel(); return; }
      try { worker.postMessage(request); } catch { finish(new Error("Shuffle worker dispatch failed")); }
    });
  }
}

function challengePrefix(context: ProofContext): Uint8Array {
  // Drop the one-byte CBOR null placeholder. WASM appends the canonical proof statement.
  return proofChallengeInput("decryptionShare", context, null).subarray(0, -1);
}

function packCards(cards: readonly DecryptionShareCard[]): Uint8Array {
  if (cards.length < 1 || cards.length > 128) throw new RangeError("Invalid DLEQ batch length");
  const packed = new Uint8Array(cards.length * CARD_BYTES);
  cards.forEach(({ pos, A }, index) => {
    if (!Number.isInteger(pos) || pos < 0 || pos > 127) throw new RangeError("Invalid DLEQ card position");
    const offset = index * CARD_BYTES;
    packed[offset] = pos;
    packed.set(A.toBytes(), offset + 1);
  });
  return packed;
}

function malformed(): Error { return new Error("Malformed shuffle worker response"); }

function readValidity(data: Record<string, unknown>): boolean {
  if (typeof data["valid"] !== "boolean") throw malformed();
  return data["valid"];
}
