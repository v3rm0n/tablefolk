import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createServer } from "vite";

// Re-encode every event and recompute every challenge using actual TypeScript
// code, including cumulative response absorption. Do not merely rehash Rust bytes.
export async function checkTranscriptReports(reports) {
  const vite = await createServer({ root: fileURLToPath(new URL("../../", import.meta.url)),
    configFile: false, appType: "custom", server: { middlewareMode: true, hmr: false, watch: null },
    ssr: { noExternal: [/^@p2pcards\//] } });
  try {
    const deck = await vite.ssrLoadModule("/packages/deck/src/index.ts");
    const crypto = await vite.ssrLoadModule("/packages/crypto/src/index.ts");
    const cbor = await vite.ssrLoadModule("/packages/encoding/src/index.ts");
    const domain = crypto.asciiToBytes("p2pcards/v1/shuffle");
    const context = { gameId: crypto.sha256(crypto.asciiToBytes("game-a")).slice(0, 16), round: 0, phase: "shuffle-0" };
    const prefix = crypto.concatBytes(domain, context.gameId, cbor.encodeCanonical(context.round), cbor.encodeCanonical(context.phase));
    const schedule = [["x", 0], ["yz", 0], ["yz", 1], ["xy", 0], ["xy", 1], ["x", 0], ["x", 0], ["x_powers", 0]];
    let count = 0;
    for (const report of reports) {
      assert.equal(report.challenges.length, 8);
      let transcript, root, reader;
      const expectedEvents = [];
      for (const [i, record] of report.challenges.entries()) {
        const input = crypto.hexToBytes(record.input);
        assert.deepEqual(input.slice(0, prefix.length), prefix);
        const value = cbor.decodeCanonical(input.slice(prefix.length));
        assert.equal(value.length, 4);
        assert.deepEqual(value[0], crypto.asciiToBytes(deck.CANDIDATE_SHUFFLE_TRANSCRIPT_PROFILE));
        if (!transcript) { root = value[1]; transcript = new deck.CandidateShuffleTranscript(root, context); }
        assert.deepEqual(value[1], root);
        const events = value[2], request = value[3];
        assert.deepEqual(request, [2, crypto.asciiToBytes(schedule[i][0]), schedule[i][1]]);
        assert.deepEqual(events.slice(0, expectedEvents.length), expectedEvents);
        for (const event of events.slice(expectedEvents.length)) {
          assert.equal(event.length, 2);
          if (event[0] === 0) transcript.label(event[1]);
          else { assert.equal(event[0], 1); transcript.appendPublicBytes(event[1]); }
          expectedEvents.push(event);
        }
        if (request[2] === 0) reader = transcript.challenge(request[1]);
        const result = reader.read();
        assert.equal(crypto.bytesToHex(result.input), record.input);
        assert.equal(crypto.bytesToHex(result.digest), record.digest);
        assert.equal(crypto.bytesToHex(crypto.encodeRistrettoScalar(result.scalar)), record.scalar);
        expectedEvents.push([2, request[1], request[2], crypto.encodeRistrettoScalar(result.scalar)]);
        count++;
      }
    }
    return count;
  } finally { await vite.close(); }
}
