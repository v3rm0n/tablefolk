import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

const [upstream, adapted] = process.argv.slice(2);
assert.ok(upstream && adapted, "Usage: node compare-transcripts.mjs UPSTREAM_BINARY ADAPTED_BINARY");
const run = (binary, command, input) => JSON.parse(execFileSync(binary, [command], {
  encoding: "utf8", input: input && JSON.stringify(input), timeout: 120_000, maxBuffer: 8 * 1024 * 1024,
}));
const original = run(upstream, "generate"), candidate = run(adapted, "generate");
assert.equal(original.length, 2); assert.equal(candidate.length, 2);
for (const row of [...original, ...candidate]) {
  assert.equal(row.passed, true);
  assert.equal(row.report.crs_profile, "bg-ristretto255-36-4x9-crs-candidate-v1");
}
original.forEach((row) => assert.equal(row.report.transcript_profile, "upstream-ark-transcript"));
candidate.forEach((row) => assert.equal(row.report.transcript_profile, "bg-ristretto255-36-4x9-fs-candidate-v1"));
for (const [binary, rows] of [[upstream, candidate], [adapted, original]]) {
  const reports = run(binary, "verify", rows.map((row) => row.fixture));
  assert.equal(reports.length, 2);
  for (const report of reports) assert.equal(report.checks.find((check) => check.name === "valid").accepted, false);
}
console.log("Four genuine proofs accepted by their own profile and rejected by the other transcript profile.");
