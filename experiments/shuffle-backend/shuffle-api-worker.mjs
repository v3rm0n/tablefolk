import init, * as wasm from "./pkg-transcript/shuffle_backend_evaluation.js";
self.onmessage = async ({ data: d }) => {
  try {
    await init();
    const s = new Uint8Array(d.statement);
    if (d.proof) self.postMessage({ valid: wasm.verify_candidate_shuffle36(s, new Uint8Array(d.proof)) });
    else if (d.permutation) self.postMessage({ proof: Array.from(wasm.prove_candidate_shuffle36(s, new Uint8Array(d.permutation), new Uint8Array(d.randomizers))) });
    else { wasm.validate_candidate_shuffle_statement36(s); self.postMessage({ accepted: true }); }
  } catch { self.postMessage({ error: true }); }
};
