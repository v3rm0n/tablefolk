// Stage the shuffle WASM module used by the web worker.
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
const source = new URL("./pkg/", import.meta.url);
const target = new URL("../../apps/web/public/shuffle-candidate/", import.meta.url);
const js = await readFile(new URL("shuffle_wasm.js", source));
for (const name of ["prove_candidate_shuffle", "verify_candidate_shuffle", "validate_candidate_shuffle_statement",
  "prepare_and_prove_candidate_shuffle", "create_dleq_batch", "verify_dleq_batch"]) {
  if (!js.toString().includes(`export function ${name}(`)) throw new Error("Build shuffle-wasm artifacts before staging");
}
const wasm = await readFile(new URL("shuffle_wasm_bg.wasm", source));
await mkdir(target, { recursive: true });
await writeFile(new URL("shuffle_wasm.js", target), js);
await writeFile(new URL("shuffle_wasm_bg.wasm", target), wasm);
const manifest = { profile: "bg-ristretto255-proof-candidate-v2", files: Object.fromEntries([["shuffle_wasm.js", js], ["shuffle_wasm_bg.wasm", wasm]].map(([name, bytes]) => [name, { bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") }])) };
await writeFile(new URL("manifest.json", target), JSON.stringify(manifest, null, 2) + "\n");
console.log(JSON.stringify(manifest));
