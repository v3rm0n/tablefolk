import { bytesEqual } from "@p2pcards/crypto";
import { decodeCandidateShuffleStatement36, encodeCandidateShuffleStatement36, decodeCandidateShuffleProof36 } from "@p2pcards/deck";

export interface CandidateShuffleResult { readonly statement: Uint8Array; readonly proof: Uint8Array }
/** Experimental adapter. One disposable worker, one operation; no private witness crosses this boundary. */
export class CandidateShuffleClient {
  #cancel: (() => void) | null = null;
  #closed = false;
  constructor(private readonly makeWorker: () => Worker = () => new Worker(new URL("./candidate-shuffle-worker.ts", import.meta.url), { type: "module" }),
    private readonly timeoutMs = 30_000) {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) throw new Error("Invalid shuffle timeout");
  }
  close(): void { this.#closed = true; this.cancel(); }
  cancel(): void { this.#cancel?.(); }
  async verify(statement: Uint8Array, proof: Uint8Array, signal?: AbortSignal): Promise<boolean> {
    decodeCandidateShuffleStatement36(statement); decodeCandidateShuffleProof36(proof);
    const result = await this.#run({ operation: "verify", statement: statement.slice(), proof: proof.slice() }, signal);
    if (typeof result["valid"] !== "boolean") throw new Error("Malformed shuffle worker response");
    return result["valid"];
  }
  async prove(template: Uint8Array, signal?: AbortSignal): Promise<CandidateShuffleResult> {
    const expected = decodeCandidateShuffleStatement36(template);
    if (!bytesEqual(template, encodeCandidateShuffleStatement36({ ...expected, outputDeck: expected.inputDeck }))) throw new Error("Invalid shuffle preparation template");
    const result = await this.#run({ operation: "prove", statement: template.slice() }, signal);
    const statement = result["statement"], proof = result["proof"];
    if (!(statement instanceof Uint8Array) || !(proof instanceof Uint8Array)) throw new Error("Malformed shuffle worker response");
    const actual = decodeCandidateShuffleStatement36(statement);
    decodeCandidateShuffleProof36(proof);
    if (!bytesEqual(encodeCandidateShuffleStatement36({ ...actual, outputDeck: expected.outputDeck }),
      encodeCandidateShuffleStatement36(expected))) throw new Error("Worker changed shuffle scope or input deck");
    return Object.freeze({ statement: statement.slice(), proof: proof.slice() });
  }
  #run(request: unknown, signal?: AbortSignal): Promise<Record<string, unknown>> {
    if (this.#closed || this.#cancel !== null || signal?.aborted) return Promise.reject(new Error("Shuffle worker closed, busy, or cancelled"));
    return new Promise((resolve, reject) => {
      const worker = this.makeWorker();
      let settled = false;
      const finish = (error?: Error, result?: Record<string, unknown>) => {
        if (settled) return;
        settled = true; clearTimeout(timer); signal?.removeEventListener("abort", cancel);
        worker.onmessage = null; worker.onerror = null; worker.onmessageerror = null;
        worker.terminate(); this.#cancel = null;
        if (error) reject(error); else resolve(result!);
      };
      const cancel = () => finish(new Error("Shuffle operation cancelled"));
      const timer = setTimeout(() => finish(new Error("Shuffle worker timed out")), this.timeoutMs);
      this.#cancel = cancel;
      signal?.addEventListener("abort", cancel, { once: true });
      worker.onmessage = ({ data }) => {
        if (!data || typeof data !== "object" || data.error) finish(new Error("Shuffle worker failed")); else finish(undefined, data);
      };
      worker.onerror = () => finish(new Error("Shuffle worker failed"));
      worker.onmessageerror = () => finish(new Error("Shuffle worker response failed"));
      if (signal?.aborted) { cancel(); return; }
      try { worker.postMessage(request); } catch { finish(new Error("Shuffle worker dispatch failed")); }
    });
  }
}
