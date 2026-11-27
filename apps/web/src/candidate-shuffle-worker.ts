import { createUnprovenDeckShuffle, decodeCandidateShuffleStatement, encodeCandidateShuffleStatement,
  encodeCandidateShuffleWitness, decodeCandidateShuffleProof, packShuffleDeck } from "@p2pcards/deck";
import { bytesEqual } from "@p2pcards/crypto";

interface Backend {
  default(): Promise<unknown>;
  prove_candidate_shuffle(statement: Uint8Array, permutation: Uint8Array, randomizers: Uint8Array): Uint8Array;
  verify_candidate_shuffle(statement: Uint8Array, proof: Uint8Array): boolean;
}
const scope = globalThis as unknown as { onmessage: ((event: MessageEvent) => void) | null; postMessage(value: unknown): void };
let busy = false;
let proved = false;
let backendPromise: Promise<Backend> | null = null;
scope.onmessage = async ({ data }) => {
  if (busy || proved) { scope.postMessage({ error: "Candidate shuffle worker is busy or spent" }); return; }
  busy = true;
  try {
    const statement = decodeCandidateShuffleStatement(data.statement);
    if (data.operation !== "prove" && data.operation !== "verify") throw new Error("Invalid operation");
    if (data.operation === "verify") decodeCandidateShuffleProof(data.proof, statement);
    // Only local, explicitly staged candidate artifacts. No caller-supplied module URL.
    // Absolute URL avoids Vite's import-query rewrite for public files. Built
    // workers live in assets/; ../ preserves the app's relative deployment base.
    const moduleUrl = import.meta.env.DEV
      ? new URL(`${import.meta.env.BASE_URL}shuffle-candidate/shuffle_wasm.js`, globalThis.location.origin + "/").href
      : new URL(/* @vite-ignore */ "../shuffle-candidate/shuffle_wasm.js", import.meta.url).href;
    backendPromise ??= (async () => {
      const loaded = await import(/* @vite-ignore */ moduleUrl) as Backend;
      await loaded.default();
      return loaded;
    })();
    const backend = await backendPromise;
    if (data.operation === "verify") {
      scope.postMessage({ valid: backend.verify_candidate_shuffle(data.statement, data.proof) });
    } else {
      proved = true; // A proof worker is never reused after handling a private witness.
      if (!bytesEqual(encodeCandidateShuffleStatement(statement), encodeCandidateShuffleStatement({ ...statement, outputDeck: statement.inputDeck }))) throw new Error("Invalid preparation template");
      const shuffled = createUnprovenDeckShuffle(statement.inputDeck, statement.aggregateKey);
      const publicStatement = encodeCandidateShuffleStatement({ ...statement, outputDeck: shuffled.outputDeck });
      const witness = encodeCandidateShuffleWitness(shuffled.witness, statement);
      try {
        const proof = backend.prove_candidate_shuffle(publicStatement, witness.permutation, witness.randomizers);
        decodeCandidateShuffleProof(proof, statement);
        scope.postMessage({ outputDeck: packShuffleDeck(shuffled.outputDeck, statement.inputDeck.length), proof });
      } finally { witness.permutation.fill(0); witness.randomizers.fill(0); }
    }
  } catch { scope.postMessage({ error: "Candidate shuffle operation failed" }); }
  finally { busy = false; }
};
