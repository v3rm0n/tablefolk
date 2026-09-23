import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, writeFile, mkdir, stat } from "node:fs/promises";
import { createServer } from "node:http";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "@playwright/test";
import { buildAdapterChecks, assertAdapterChecks } from "./adapter-checks.mjs";
import { buildProofCodecChecks, assertProofCodecChecks } from "./proof-codec-checks.mjs";
import { checkTranscriptReports } from "./transcript-checks.mjs";

const root = dirname(fileURLToPath(import.meta.url));
const target = resolve(root, process.env.CARGO_TARGET_DIR ?? "target");
const nativeBinary = resolve(target, "release/shuffle-backend-evaluation");
const output = resolve(root, process.env.SHUFFLE_EVAL_OUTPUT_DIR ?? "results");
const curve = process.env.SHUFFLE_EVAL_CURVE ?? "secp256k1";
const crsProfile = process.env.SHUFFLE_EVAL_CRS ?? "random-evaluation";
const candidateCrs = crsProfile === "bg-ristretto255-36-4x9-crs-candidate-v1";
const transcriptProfile = process.env.SHUFFLE_EVAL_TRANSCRIPT ?? "upstream-ark-transcript";
const candidateTranscript = transcriptProfile === "bg-ristretto255-36-4x9-fs-candidate-v1";
assert.ok(candidateTranscript || transcriptProfile === "upstream-ark-transcript", "Unknown transcript profile");
assert.ok(!candidateTranscript || candidateCrs, "Candidate transcript requires the fixed CRS");
assert.ok(candidateCrs || crsProfile === "random-evaluation", "Unknown CRS profile");
assert.ok(!candidateCrs || curve === "ristretto255", "Candidate CRS requires Ristretto");
const fixtureCount = candidateCrs ? 2 : 4;
assert.ok(["secp256k1", "ristretto255"].includes(curve), "Unknown evaluation curve");
const revision = "ac4fb67b612aa89f37f6be72ea74a3c13eff66ca";
const basename = "shuffle_backend_evaluation";
const pkg = resolve(root, process.env.SHUFFLE_EVAL_PKG_DIR ?? "pkg");
const wasmPath = resolve(pkg, `${basename}_bg.wasm`);
const routes = new Map([
  ["/worker.mjs", [resolve(root, "worker.mjs"), "text/javascript"]],
  [`/pkg/${basename}.js`, [resolve(pkg, `${basename}.js`), "text/javascript"]],
  [`/pkg/${basename}_bg.wasm`, [wasmPath, "application/wasm"]],
]);

const adapterCases = curve === "ristretto255" ? await buildAdapterChecks() : [];
const nativeAdapterResults = adapterCases.length === 0 ? [] : JSON.parse(execFileSync(nativeBinary, ["adapters"], {
  encoding: "utf8", input: JSON.stringify(adapterCases.map((test) => test.input)),
  timeout: 120_000, maxBuffer: 4 * 1024 * 1024,
}));
assertAdapterChecks(adapterCases, nativeAdapterResults, "native");
const native = JSON.parse(execFileSync(nativeBinary, ["generate"], {
  encoding: "utf8", timeout: 120_000, maxBuffer: 4 * 1024 * 1024,
}));
for (const row of native) {
  assert.equal(row.report.crs_profile, crsProfile, "Native binary has the wrong CRS profile");
  assert.equal(row.report.transcript_profile, transcriptProfile, "Native binary has the wrong transcript");
  assert.equal(row.report.curve, curve, "Native binary has the wrong curve");
}
const expectedCrs = candidateCrs ? JSON.parse(await readFile(
  resolve(root, "../../packages/deck/test-vectors/shuffle-crs-36.json"), "utf8",
)) : null;
const nativeCrs = candidateCrs ? JSON.parse(execFileSync(nativeBinary, ["crs"], {
  encoding: "utf8", timeout: 120_000, maxBuffer: 1024 * 1024,
})) : null;
assert.deepEqual(nativeCrs, expectedCrs, "Native CRS differs from TypeScript fixtures");
const proofCodecCases = candidateCrs ? await buildProofCodecChecks(native) : [];
const nativeCodecResults = candidateCrs ? JSON.parse(execFileSync(nativeBinary, ["codec"], {
  encoding: "utf8", input: JSON.stringify(proofCodecCases.map((test) => test.input)),
  timeout: 120_000, maxBuffer: 4 * 1024 * 1024,
})) : [];
assertProofCodecChecks(proofCodecCases, nativeCodecResults, "native");
const transcriptVectors = candidateTranscript ? JSON.parse(await readFile(
  resolve(root, "../../packages/deck/test-vectors/shuffle-transcript.json"), "utf8",
)).challenges : null;
const nativeTranscriptVectors = candidateTranscript ? JSON.parse(execFileSync(nativeBinary, ["transcript"], {
  encoding: "utf8", timeout: 120_000, maxBuffer: 4 * 1024 * 1024,
})) : null;
assert.deepEqual(nativeTranscriptVectors, transcriptVectors);
const server = createServer(async (request, response) => {
  try {
    const path = new URL(request.url, "http://127.0.0.1").pathname;
    if (path === "/") {
      response.writeHead(200, { "Content-Type": "text/html" });
      response.end("<!doctype html><title>Isolated shuffle evaluation</title>");
    } else if (routes.has(path)) {
      const [file, type] = routes.get(path);
      response.writeHead(200, { "Content-Type": type });
      response.end(await readFile(file));
    } else {
      response.writeHead(404).end();
    }
  } catch {
    response.writeHead(500).end();
  }
});
await new Promise((resolve, reject) => {
  server.once("error", reject);
  server.listen(0, "127.0.0.1", resolve);
});

let browser;
try {
  const launch = { headless: true };
  if (process.env.PLAYWRIGHT_EXECUTABLE_PATH) launch.executablePath = process.env.PLAYWRIGHT_EXECUTABLE_PATH;
  browser = await chromium.launch(launch);
  const page = await browser.newPage();
  const errors = [];
  page.on("pageerror", (error) => errors.push(String(error)));
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  const browserResult = await page.evaluate((fixtures) => new Promise((resolve, reject) => {
    const worker = new Worker("/worker.mjs", { type: "module" });
    const timer = setTimeout(() => {
      worker.terminate();
      reject(new Error("Shuffle evaluation worker timed out"));
    }, 120_000);
    const finish = (fn, result) => {
      clearTimeout(timer);
      worker.terminate();
      fn(result);
    };
    worker.onerror = (event) => finish(reject, new Error(event.message));
    worker.onmessage = ({ data }) => data.error
      ? finish(reject, new Error(`${data.error}\n${data.stack ?? ""}`))
      : finish(resolve, data);
    worker.postMessage(fixtures);
  }), { nativeFixtures: native, candidateCrs,
    candidateTranscript,
    proofCodecInputs: proofCodecCases.map((test) => test.input),
    adapterInputs: adapterCases.length === 0 ? null : adapterCases.map((test) => test.input) });
  assert.deepEqual(browserResult.crsVectors, expectedCrs, "WASM CRS differs from TypeScript fixtures");
  assert.deepEqual(browserResult.transcriptVectors, transcriptVectors, "WASM transcript differs from Python vectors");
  assertProofCodecChecks(proofCodecCases, browserResult.proofCodecResults, "browser");
  if (candidateCrs) {
    await buildProofCodecChecks(browserResult.results, false);
    browserResult.results.forEach((row, i) => assert.deepEqual(row.native_proof_wire, native[i].proof_wire));
  }
  assertAdapterChecks(adapterCases, browserResult.adapterResults ?? [], "browser");
  const browserFixtures = browserResult.results.map((row) => row.fixture);
  const browserToNative = JSON.parse(execFileSync(nativeBinary, ["verify"], {
    encoding: "utf8", input: JSON.stringify(browserFixtures),
    timeout: 120_000, maxBuffer: 4 * 1024 * 1024,
  }));
  const allReports = [
    ...native.map((row) => row.report),
    ...browserResult.results.flatMap((row) => [row.native_report, row.report]),
    ...browserToNative,
  ];
  const failed = allReports.flatMap((report, index) => report.checks
    .filter((check) => check.accepted !== check.expected)
    .map((check) => ({ report: index, ...check })));
  const transcriptChallenges = candidateTranscript ? await checkTranscriptReports(allReports) : 0;
  const wasmBytes = await readFile(wasmPath);
  await mkdir(output, { recursive: true });
  const saveFixtures = async (rows, prefix) => Promise.all(rows.map(async ({ fixture, ...row }, index) => {
    const bytes = new Uint8Array(fixture);
    const file = `${prefix}-${index}.bin`;
    await writeFile(resolve(output, file), bytes);
    return {
      ...row,
      fixture_file: file,
      fixture_sha256: createHash("sha256").update(bytes).digest("hex"),
    };
  }));
  const report = {
    revision,
    rust_toolchain: "1.90.0",
    wasm_bindgen: "0.2.100",
    curve,
    crs_profile: crsProfile,
    transcript_profile: transcriptProfile,
    transcript_reference_comparisons: candidateTranscript ? 16 : 0,
    transcript_challenge_comparisons: transcriptChallenges,
    crs_vector_comparisons: candidateCrs ? expectedCrs.length * 2 : 0,
    proof_codec_cases: proofCodecCases.length,
    proof_codec_comparisons: proofCodecCases.length * 3,
    browser: browser.version(),
    user_agent: browserResult.userAgent,
    native_platform: `${process.platform}/${process.arch}`,
    wasm_bytes: (await stat(wasmPath)).size,
    wasm_sha256: createHash("sha256").update(wasmBytes).digest("hex"),
    lock_sha256: createHash("sha256").update(await readFile(resolve(root, "Cargo.lock"))).digest("hex"),
    checks: allReports.reduce((sum, report) => sum + report.checks.length, 0),
    failed,
    adapter_cases: adapterCases.length,
    adapter_comparisons: adapterCases.length * 2,
    native: await saveFixtures(native, "native"),
    browser_results: await saveFixtures(browserResult.results, "browser"),
    browser_to_native: browserToNative,
    page_errors: errors,
  };
  await writeFile(resolve(output, "report.json"), `${JSON.stringify(report, null, 2)}\n`);
  if (adapterCases.length > 0) {
    await writeFile(resolve(output, "adapter-vectors.json"), `${JSON.stringify({
      cases: adapterCases, native: nativeAdapterResults, browser: browserResult.adapterResults,
    }, null, 2)}\n`);
  }
  if (candidateCrs) {
    await writeFile(resolve(output, "proof-codec-vectors.json"), `${JSON.stringify({
      cases: proofCodecCases, native: nativeCodecResults, browser: browserResult.proofCodecResults,
    }, null, 2)}\n`);
    await writeFile(resolve(output, "crs-vectors.json"), `${JSON.stringify({
      expected: expectedCrs, native: nativeCrs, browser: browserResult.crsVectors,
    }, null, 2)}\n`);
  }
  assert.equal(native.length, fixtureCount);
  assert.equal(browserResult.results.length, fixtureCount);
  assert.equal(browserToNative.length, fixtureCount);
  assert.deepEqual(errors, []);
  assert.deepEqual(failed, [], "Unexpected acceptance/rejection results; see report.json");
  for (const result of allReports) {
    assert.equal(result.revision, revision);
    assert.equal(result.curve, curve);
    assert.equal(result.crs_profile, crsProfile);
    assert.equal(result.transcript_profile, transcriptProfile);
    assert.equal(result.proof_codec, candidateCrs ? "bg-ristretto255-36-4x9-proof-candidate-v1" : null);
    assert.equal(result.checks.length, 16);
  }
  for (let index = 0; index < fixtureCount; index += 1) {
    assert.deepEqual(native[index].report, browserResult.results[index].native_report);
    assert.deepEqual(browserResult.results[index].report, browserToNative[index]);
  }
  const summary = {
    revision, curve, checks: report.checks, failed: failed.length,
    crs_profile: crsProfile, crs_vector_comparisons: report.crs_vector_comparisons,
    transcript_profile: transcriptProfile, transcript_challenge_comparisons: transcriptChallenges,
    proof_codec_cases: report.proof_codec_cases, proof_codec_comparisons: report.proof_codec_comparisons,
    adapter_cases: report.adapter_cases, adapter_comparisons: report.adapter_comparisons,
    browser: report.browser, wasm_bytes: report.wasm_bytes,
    timings: native.map((row, index) => ({
      matrix: `${row.report.rows}x${row.report.cols}`,
      initial_identity_a: row.report.initial_identity_a,
      proof_bytes: row.report.proof_bytes,
      native_prepare_and_prove_ms: row.prepare_and_prove_ms,
      browser_prepare_and_prove_ms: browserResult.results[index].prepare_and_prove_ms,
      native_assess_ms: row.assess_ms,
      browser_assess_ms: browserResult.results[index].assess_ms,
    })),
    report: resolve(output, "report.json"),
  };
  await writeFile(resolve(output, "summary.json"), `${JSON.stringify(summary, null, 2)}\n`);
  console.log(JSON.stringify(summary, null, 2));
} finally {
  await browser?.close();
  await new Promise((resolve) => server.close(resolve));
}
