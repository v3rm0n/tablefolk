// Local interoperability test. Private requests stay in memory, never artifacts.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "vite";
import { chromium } from "@playwright/test";
const root = fileURLToPath(new URL("../../", import.meta.url));
const binary = resolve(process.env.CARGO_TARGET_DIR ?? resolve(root, "crates/shuffle-wasm/target"), "release/examples/shuffle-api");
const server = await createServer({ root, configFile: false, appType: "custom", server: { host: "127.0.0.1", port: 0, hmr: false, watch: null }, ssr: { noExternal: [/^@p2pcards\//] } });
let browser, admissions = 0, verifications = 0;
try {
  await server.listen();
  const d = await server.ssrLoadModule("/packages/deck/src/index.ts");
  const c = await server.ssrLoadModule("/packages/crypto/src/index.ts");
  const p = await server.ssrLoadModule("/packages/protocol/src/index.ts");
  const enc = await server.ssrLoadModule("/packages/encoding/src/index.ts");
  const native = request => JSON.parse(execFileSync(binary, [], { input: JSON.stringify(request), encoding: "utf8", timeout: 120000, maxBuffer: 128 * 1024 }));
  browser = await chromium.launch({ executablePath: process.env.PLAYWRIGHT_EXECUTABLE_PATH, headless: true });
  const page = await browser.newPage();
  await page.goto(`${server.resolvedUrls.local[0]}crates/shuffle-wasm/shuffle-api-worker.mjs`);
  await page.evaluate(() => { globalThis.apiWorker = new Worker("/crates/shuffle-wasm/shuffle-api-worker.mjs", { type: "module" }); });
  const wasm = request => page.evaluate(request => new Promise((resolve, reject) => {
    globalThis.apiWorker.onmessage = e => resolve(e.data);
    globalThis.apiWorker.onerror = () => reject(new Error("API worker failure"));
    globalThis.apiWorker.postMessage(request);
  }), request);
  const point = n => c.RistrettoPoint.base().multiply(c.scalarFromBigInt(BigInt(n)));
  const timings = [];
  for (const [rows, columns] of [[4, 9], [4, 13]]) {
    const cardCount = rows * columns;
    let inputDeck = Array.from({ length: cardCount }, (_, i) => ({ A: c.RistrettoPoint.identity(), B: point(i + 1) }));
    const aggregateKey = point(7);
    for (let seat = 0; seat < 4; seat++) {
      const shuffled = d.createUnprovenDeckShuffle(inputDeck, aggregateKey);
      const statement = { rows, columns, gameId: p.parseGameId(new Uint8Array(16).fill(42)), round: 7, seat,
        rosterHash: p.parseHash256(new Uint8Array(32).fill(11)), aggregateKey, inputDeck, outputDeck: shuffled.outputDeck };
      const wire = d.encodeCandidateShuffleStatement(statement);
      const privateInput = d.encodeCandidateShuffleWitness(shuffled.witness, statement);
      const request = { statement: Array.from(wire), permutation: Array.from(privateInput.permutation), randomizers: Array.from(privateInput.randomizers) };
      const started = performance.now();
      const nativeProof = native(request);
      const nativeProveMs = performance.now() - started;
      const wasmStarted = performance.now();
      const wasmProof = await wasm(request);
      const wasmProveMs = performance.now() - wasmStarted;
      const proofBytes = columns === 9 ? 3645 : 4325;
      for (const proof of [nativeProof.proof, wasmProof.proof]) {
        assert.equal(proof?.length, proofBytes);
        const bytes = new Uint8Array(proof);
        assert.deepEqual(d.encodeCandidateShuffleProof(d.decodeCandidateShuffleProof(bytes, statement), statement), bytes);
      }
      const nativeVerifyStarted = performance.now();
      assert.deepEqual(native({ statement: request.statement, proof: wasmProof.proof }), { valid: true });
      const nativeVerifyMs = performance.now() - nativeVerifyStarted;
      const wasmVerifyStarted = performance.now();
      assert.deepEqual(await wasm({ statement: request.statement, proof: nativeProof.proof }), { valid: true });
      const wasmVerifyMs = performance.now() - wasmVerifyStarted;
      timings.push({ cardCount, seat, proofBytes, nativeProveMs, wasmProveMs, nativeVerifyMs, wasmVerifyMs });
      verifications += 2;
      for (const proof of [nativeProof.proof, wasmProof.proof]) for (const api of [native, wasm]) {
        assert.deepEqual(await api({ statement: request.statement, proof }), { valid: true }); verifications++;
        for (const changed of [{ ...statement, gameId: p.parseGameId(new Uint8Array(16)) }, { ...statement, round: 8 },
          { ...statement, seat: (seat + 1) % 4 }, { ...statement, rosterHash: p.parseHash256(new Uint8Array(32)) },
          { ...statement, aggregateKey: point(8) }, { ...statement, inputDeck: [...inputDeck].reverse() },
          { ...statement, outputDeck: [...shuffled.outputDeck].reverse() }]) {
          assert.deepEqual(await api({ statement: Array.from(d.encodeCandidateShuffleStatement(changed)), proof }), { valid: false }); verifications++;
        }
        assert.deepEqual(await api({ statement: request.statement, proof: proof.slice(1) }), { error: true }); verifications++;
      }
      for (const api of [native, wasm]) {
        assert.deepEqual(await api({ ...request, randomizers: new Array(cardCount * 32).fill(0) }), { error: true });
        assert.deepEqual(await api({ ...request, permutation: new Array(cardCount).fill(0) }), { error: true });
      }
      if (seat === 0) {
        const offset = enc.encodeCanonical(d.CANDIDATE_SHUFFLE_STATEMENT_PROFILE).length + 20;
        const cases = [];
        for (const round of [0, 23, 24, 255, 256, 65535, 65536, 4294967295, 4294967296, Number.MAX_SAFE_INTEGER]) cases.push([d.encodeCandidateShuffleStatement({ ...statement, round }), true]);
        for (const length of [0, 1, wire.length - 8, wire.length - 1]) cases.push([wire.slice(0, length), false]);
        cases.push([new Uint8Array([...wire, 0]), false]);
        for (const replacement of [[24, 7], [25, 0, 7], [27, 0, 32, 0, 0, 0, 0, 0, 0], [32], [255]]) cases.push([new Uint8Array([...wire.slice(0, offset), ...replacement, ...wire.slice(offset + 1)]), false]);
        for (const index of [0, 1, offset + 1, offset + 2, offset + 36, offset + 70, offset + 73, offset + 73 + 3 + cardCount * 64]) {
          const bad = wire.slice(); bad[index] = 255; cases.push([bad, false]);
        }
        for (const [bytes, accepted] of cases) {
          let ts; try { d.decodeCandidateShuffleStatement(bytes); ts = true; } catch { ts = false; }
          assert.equal(ts, accepted); admissions++;
          for (const api of [native, wasm]) { assert.deepEqual(await api({ statement: Array.from(bytes) }), accepted ? { accepted: true } : { error: true }); admissions++; }
        }
      }
      inputDeck = shuffled.outputDeck;
    }
  }
  console.log(JSON.stringify({ sequentialShuffles: 8, proofs: 16, publicAdmissionComparisons: admissions, verificationChecks: verifications, privateRejections: 32, timings }));
} finally { await browser?.close(); await server.close(); }
