import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createServer } from "vite";

export async function buildProofCodecChecks(rows, includeRejections = true) {
  const vite = await createServer({
    root: fileURLToPath(new URL("../../", import.meta.url)), configFile: false,
    appType: "custom", server: { middlewareMode: true, hmr: false, watch: null },
    ssr: { noExternal: [/^@p2pcards\//] },
  });
  try {
    const deck = await vite.ssrLoadModule("/packages/deck/src/index.ts");
    const cases = [];
    function add(name, input, accepted) {
      let actual;
      try {
        actual = { accepted: true, bytes: Array.from(deck.encodeCandidateShuffleProof36(
          deck.decodeCandidateShuffleProof36(new Uint8Array(input)),
        )) };
      } catch { actual = { accepted: false, bytes: null }; }
      const expected = { accepted, bytes: accepted ? Array.from(input) : null };
      assert.deepEqual(actual, expected, `TypeScript codec: ${name}`);
      cases.push({ name, input: Array.from(input), expected });
    }
    rows.forEach((row, i) => add(`genuine-proof-${i}`, row.proof_wire, true));
    if (!includeRejections) return cases;
    const wire = rows[0].proof_wire;
    const header = wire.length - 106 * 34;
    const zeros = deck.encodeCandidateShuffleProof36(Array.from({ length: 106 }, () => new Uint8Array(32)));
    add("zero-elements-structural-only", zeros, true);
    for (const length of [0, header - 1, header, wire.length - 1]) {
      add(`truncated-${length}`, wire.slice(0, length), false);
    }
    add("suffix", [...wire, 0], false);
    add("nonminimal-array", [0x98, 2, ...wire.slice(1)], false);
    for (let i = 0; i < header; i++) {
      const bytes = wire.slice(); bytes[i] ^= 1;
      add(`header-${i}`, bytes, false);
    }
    for (let i = 0; i < 106; i++) {
      const offset = header + i * 34;
      const invalid = wire.slice(); invalid.fill(255, offset + 2, offset + 34);
      add(`noncanonical-field-${i}`, invalid, false);
      const type = wire.slice(); type[offset] = 0x98;
      add(`nested-array-${i}`, type, false);
      const length = wire.slice(); length[offset + 1] = 31;
      add(`wrong-byte-length-${i}`, length, false);
    }
    return cases;
  } finally { await vite.close(); }
}

export function assertProofCodecChecks(cases, results, runtime) {
  assert.equal(results.length, cases.length, `${runtime} codec case count`);
  cases.forEach((test, i) => assert.deepEqual(results[i], test.expected, `${runtime} codec: ${test.name}`));
}
