// Compare the old and new arithmetic paths on identical 36-card shuffle and 27-card deal inputs.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { createServer } from "vite";
import * as wasm from "./pkg-transcript/shuffle_backend_evaluation.js";

const root = fileURLToPath(new URL("../../", import.meta.url));
const server = await createServer({ root, configFile: false, appType: "custom",
  server: { middlewareMode: true, ws: false, watch: null }, ssr: { noExternal: [/^@p2pcards\//] } });

try {
  await wasm.default({ module_or_path: await readFile(new URL("./pkg-transcript/shuffle_backend_evaluation_bg.wasm", import.meta.url)) });
  const c = await server.ssrLoadModule("/packages/crypto/src/index.ts");
  const d = await server.ssrLoadModule("/packages/deck/src/index.ts");
  const p = await server.ssrLoadModule("/packages/protocol/src/index.ts");
  const point = n => c.RistrettoPoint.base().multiply(c.scalarFromBigInt(BigInt(n)));
  const secret = c.scalarFromBigInt(7n), key = point(7);
  const gameId = p.parseGameId(Uint8Array.from({ length: 16 }, (_, i) => i));
  const context = { gameId, round: 256, phase: "round.256.deal.0" };
  const prefix = p.proofChallengeInput("decryptionShare", context, null).subarray(0, -1);
  const deck = Array.from({ length: 36 }, (_, i) => ({ A: i ? point(i + 101) : c.RistrettoPoint.identity(), B: point(i + 1) }));
  const cards = deck.slice(0, 27).map(({ A }, pos) => ({ pos, A }));
  const packedCards = c.concatBytes(...cards.map(({ pos, A }) => c.concatBytes(Uint8Array.of(pos), A.toBytes())));
  const template = { gameId, round: context.round, seat: 0, rosterHash: p.parseHash256(new Uint8Array(32)),
    aggregateKey: key, inputDeck: deck, outputDeck: deck };
  const encoded = d.encodeCandidateShuffleStatement36(template);

  const jsCreate = () => cards.map(({ pos, A }) => d.createProvenDecryptionShare(context, pos, secret, A));
  const jsVerify = shares => cards.every(({ pos, A }, i) => d.verifyProvenDecryptionShare(context, pos, key, A, shares[i]));
  const wasmCreate = () => {
    const bytes = c.encodeRistrettoScalar(secret);
    const packed = wasm.create_dleq_batch(prefix, bytes, packedCards);
    assert.ok(bytes.every(byte => byte === 0));
    return packed;
  };
  const wasmVerify = packed => wasm.verify_dleq_batch(prefix, key.toBytes(), packedCards, packed);
  const unpack = bytes => cards.map((_, i) => {
    const offset = i * 128, at = n => bytes.subarray(offset + n, offset + n + 32);
    return { S: c.RistrettoPoint.fromBytes(at(0)), proof: {
      R1: c.RistrettoPoint.fromBytes(at(32)), R2: c.RistrettoPoint.fromBytes(at(64)), z: c.decodeRistrettoScalar(at(96)),
    } };
  });
  const pack = shares => c.concatBytes(...shares.map(({ S, proof }) =>
    c.concatBytes(S.toBytes(), proof.R1.toBytes(), proof.R2.toBytes(), c.encodeRistrettoScalar(proof.z))));

  const jsShares = jsCreate(), packedJsShares = pack(jsShares), wasmShares = wasmCreate();
  assert.ok(jsVerify(unpack(wasmShares)));
  assert.ok(wasmVerify(packedJsShares));
  assert.ok(wasmVerify(wasmShares));
  const changed = unpack(wasmShares);
  const one = c.scalarFromBigInt(1n);
  changed[1].proof.z = c.addRistrettoScalars(changed[1].proof.z, one);
  changed[2].proof.z = c.subtractRistrettoScalars(changed[2].proof.z, one);
  assert.equal(wasmVerify(pack(changed)), false);
  assert.equal(wasm.verify_dleq_batch(prefix, new Uint8Array(32), packedCards, wasmShares), false);
  const wrongScope = p.proofChallengeInput("decryptionShare", { ...context, phase: "round.256.deal.1" }, null).subarray(0, -1);
  assert.equal(wasm.verify_dleq_batch(wrongScope, key.toBytes(), packedCards, wasmShares), false);
  const invalid = wasmShares.slice();
  invalid.fill(255, 96, 128);
  assert.throws(() => wasmVerify(invalid));
  const rejectedSecret = c.encodeRistrettoScalar(secret);
  assert.throws(() => wasm.create_dleq_batch(prefix, rejectedSecret, new Uint8Array()));
  assert.ok(rejectedSecret.every(byte => byte === 0));

  const oldProve = () => {
    const { outputDeck, witness } = d.createUnprovenDeckShuffle(deck, key);
    const statement = d.encodeCandidateShuffleStatement36({ ...template, outputDeck });
    const { permutation, randomizers } = d.encodeCandidateShuffleWitness36(witness);
    try {
      return wasm.prove_candidate_shuffle36(statement, permutation, randomizers);
    } finally {
      permutation.fill(0);
      randomizers.fill(0);
    }
  };
  const newProve = () => wasm.prepare_and_prove_candidate_shuffle36(encoded);
  const prepared = newProve();
  assert.ok(wasm.verify_candidate_shuffle36(prepared.subarray(0, encoded.length), prepared.subarray(encoded.length)));
  const sample = task => {
    task();
    const timings = Array.from({ length: 7 }, () => {
      const start = performance.now();
      task();
      return performance.now() - start;
    }).sort((a, b) => a - b);
    return Number(timings[3].toFixed(2));
  };
  console.table([
    { operation: "36-card remask and prove", previousMs: sample(oldProve), wasmMs: sample(newProve) },
    { operation: "27 DLEQ shares", previousMs: sample(jsCreate), wasmMs: sample(wasmCreate) },
    { operation: "27 DLEQ verifications", previousMs: sample(() => jsVerify(jsShares)), wasmMs: sample(() => wasmVerify(packedJsShares)) },
  ]);
} finally {
  await server.close();
}
