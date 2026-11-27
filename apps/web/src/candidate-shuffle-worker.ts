import type { CryptoWorkerRequest } from "./candidate-shuffle-client";

interface Backend {
  default(): Promise<unknown>;
  prepare_and_prove_candidate_shuffle36(template: Uint8Array): Uint8Array;
  verify_candidate_shuffle36(statement: Uint8Array, proof: Uint8Array): boolean;
  create_dleq_batch(context: Uint8Array, secret: Uint8Array, cards: Uint8Array): Uint8Array;
  verify_dleq_batch(context: Uint8Array, key: Uint8Array, cards: Uint8Array, shares: Uint8Array): boolean;
}
const scope = globalThis as unknown as {
  onmessage: ((event: MessageEvent<CryptoWorkerRequest>) => void) | null;
  postMessage(value: unknown): void;
};
let busy = false;
let backendPromise: Promise<Backend> | null = null;

async function loadBackend(): Promise<Backend> {
  // Built workers live in assets/. This path preserves the app's deployment base.
  const moduleUrl = import.meta.env.DEV
    ? new URL(`${import.meta.env.BASE_URL}shuffle-candidate/shuffle_backend_evaluation.js`, globalThis.location.origin + "/").href
    : new URL(/* @vite-ignore */ "../shuffle-candidate/shuffle_backend_evaluation.js", import.meta.url).href;
  const loaded = await import(/* @vite-ignore */ moduleUrl) as Backend;
  await loaded.default();
  return loaded;
}

scope.onmessage = async ({ data }) => {
  const secret = data?.operation === "createDleq" ? data.secret : undefined;
  if (busy) {
    secret?.fill(0);
    scope.postMessage({ error: "Crypto worker is busy" });
    return;
  }
  busy = true;
  let result: unknown;
  try {
    const backend = await (backendPromise ??= loadBackend());
    switch (data.operation) {
      case "prove": {
        const prepared = backend.prepare_and_prove_candidate_shuffle36(data.statement);
        result = { statement: prepared.slice(0, data.statement.length), proof: prepared.slice(data.statement.length) };
        break;
      }
      case "verify":
        result = { valid: backend.verify_candidate_shuffle36(data.statement, data.proof) };
        break;
      case "createDleq":
        result = { shares: backend.create_dleq_batch(data.context, data.secret, data.cards) };
        break;
      case "verifyDleq":
        result = { valid: backend.verify_dleq_batch(data.context, data.key, data.cards, data.shares) };
        break;
      default:
        throw new Error("Invalid crypto operation");
    }
  } catch {
    result = { error: "Crypto operation failed" };
  } finally {
    secret?.fill(0);
    busy = false;
  }
  scope.postMessage(result);
};
