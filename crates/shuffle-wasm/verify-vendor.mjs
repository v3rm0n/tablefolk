import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

const root = fileURLToPath(new URL("vendor/cards-proofs/", import.meta.url));
const manifest = JSON.parse(await readFile(resolve(root, "source-manifest.json"), "utf8"));
const actual = [];
async function walk(path) {
  for (const entry of await readdir(resolve(root, path), { withFileTypes: true })) {
    const relative = `${path}/${entry.name}`;
    if (entry.isDirectory()) await walk(relative);
    else actual.push(relative);
  }
}
await walk("src");
assert.deepEqual(actual.sort(), Object.keys(manifest.files).sort());
for (const [path, entry] of Object.entries(manifest.files)) {
  const hash = createHash("sha256").update(await readFile(resolve(root, path))).digest("hex");
  assert.equal(hash, entry.local, `Vendor source changed: ${path}`);
}
console.log(`Verified ${actual.length} source files against the attributed adaptation manifest.`);
