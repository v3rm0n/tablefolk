import { afterEach, describe, expect, it, vi } from "vitest";
import { RistrettoPoint } from "@p2pcards/crypto";
import { encodeCandidateShuffleStatement36, encodeCandidateShuffleProof36 } from "@p2pcards/deck";
import { parseGameId, parseHash256 } from "@p2pcards/protocol";
import { CandidateShuffleClient } from "./candidate-shuffle-client";
const deck = Array.from({ length: 36 }, () => ({ A: RistrettoPoint.identity(), B: RistrettoPoint.base() }));
const statement = encodeCandidateShuffleStatement36({ gameId: parseGameId(new Uint8Array(16)), round: 0, seat: 0,
  rosterHash: parseHash256(new Uint8Array(32)), aggregateKey: RistrettoPoint.base(), inputDeck: deck, outputDeck: deck });
const proof = encodeCandidateShuffleProof36(Array.from({ length: 106 }, () => new Uint8Array(32)));
function fixture() {
  const workers: Array<{ onmessage: ((event: { data: unknown }) => void) | null; onerror: (() => void) | null; onmessageerror: (() => void) | null; postMessage: ReturnType<typeof vi.fn>; terminate: ReturnType<typeof vi.fn> }> = [];
  const make = vi.fn(() => {
    const worker = { onmessage: null, onerror: null, onmessageerror: null, postMessage: vi.fn(), terminate: vi.fn() };
    workers.push(worker); return worker as unknown as Worker;
  });
  return { workers, make, client: new CandidateShuffleClient(make, 100) };
}
afterEach(() => vi.useRealTimers());
describe("candidate shuffle worker lifecycle", () => {
  it("reuses one verifier worker and terminates it on close", async () => {
    const f = fixture();
    for (const valid of [true, false]) {
      const pending = f.client.verify(statement, proof), w = f.workers.at(-1)!;
      w.onmessage!({ data: { valid } }); expect(await pending).toBe(valid);
      expect(w.terminate).not.toHaveBeenCalled(); expect(w.onmessage).toBeNull();
    }
    expect(f.make).toHaveBeenCalledOnce();
    f.client.close();
    expect(f.workers[0]!.terminate).toHaveBeenCalledOnce();
  });
  it("rejects busy calls, aborts, and ignores a queued late result", async () => {
    const f = fixture(), abort = new AbortController();
    const pending = f.client.verify(statement, proof, abort.signal), w = f.workers[0]!, late = w.onmessage!;
    await expect(f.client.verify(statement, proof)).rejects.toThrow(/busy/);
    abort.abort(); late({ data: { valid: true } });
    await expect(pending).rejects.toThrow(/cancelled/); expect(w.terminate).toHaveBeenCalledOnce();
    await expect(f.client.verify(statement, proof, abort.signal)).rejects.toThrow(); expect(f.make).toHaveBeenCalledOnce();
  });
  it("times out and closes without retaining a worker", async () => {
    vi.useFakeTimers(); const f = fixture();
    const pending = f.client.verify(statement, proof); const rejection = expect(pending).rejects.toThrow(/timed out/);
    await vi.advanceTimersByTimeAsync(100); await rejection;
    const next = f.client.verify(statement, proof); f.client.close();
    await expect(next).rejects.toThrow(/cancelled/);
    await expect(f.client.verify(statement, proof)).rejects.toThrow(/closed/);
    expect(f.workers.every(w => w.terminate.mock.calls.length === 1)).toBe(true);
  });
  it("handles worker errors, malformed responses and dispatch failures", async () => {
    const f = fixture();
    for (const action of ["onerror", "onmessageerror"] as const) {
      const pending = f.client.verify(statement, proof); f.workers.at(-1)![action]!(); await expect(pending).rejects.toThrow();
    }
    const pending = f.client.verify(statement, proof); f.workers.at(-1)!.onmessage!({ data: { valid: 1 } }); await expect(pending).rejects.toThrow(/Malformed/);
    const client = new CandidateShuffleClient(() => ({ postMessage() { throw new Error("dispatch"); }, terminate() {} }) as unknown as Worker);
    await expect(client.verify(statement, proof)).rejects.toThrow(/dispatch/);
  });
  it("admits buffers before worker creation and sends no private witness", async () => {
    const f = fixture(); await expect(f.client.verify(statement.slice(1), proof)).rejects.toThrow(); expect(f.make).not.toHaveBeenCalled();
    const captured = statement.slice(), pending = f.client.prove(captured), w = f.workers[0]!;
    captured.fill(0);
    expect(w.postMessage.mock.calls[0]![0]).toEqual({ operation: "prove", statement });
    w.onmessage!({ data: { statement, proof } }); expect(await pending).toEqual({ statement, proof });
  });
});
