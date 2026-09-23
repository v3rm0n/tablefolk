// Stage the explicitly selected experimental backend for the first-round browser profile.
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
const source = new URL("./pkg-transcript/", import.meta.url);
const target = new URL("../../apps/web/public/shuffle-candidate/", import.meta.url);
const js = await readFile(new URL("shuffle_backend_evaluation.js", source));
for (const name of ["prove_candidate_shuffle36", "verify_candidate_shuffle36", "validate_candidate_shuffle_statement36"]) {
  if (!js.toString().includes(`export function ${name}(`)) throw new Error("Build candidate-transcript artifacts before staging");
}
const wasm = await readFile(new URL("shuffle_backend_evaluation_bg.wasm", source));
await mkdir(target, { recursive: true });
await writeFile(new URL("shuffle_backend_evaluation.js", target), js);
await writeFile(new URL("shuffle_backend_evaluation_bg.wasm", target), wasm);
const manifest = { candidate: true, files: Object.fromEntries([["shuffle_backend_evaluation.js", js], ["shuffle_backend_evaluation_bg.wasm", wasm]].map(([name, bytes]) => [name, { bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") }])) };
await writeFile(new URL("manifest.json", target), JSON.stringify(manifest, null, 2) + "\n");
console.log(JSON.stringify(manifest));
