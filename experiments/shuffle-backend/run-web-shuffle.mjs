import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createServer as httpServer } from "node:http";
import { createServer, build } from "vite";
import { chromium } from "@playwright/test";
const root = fileURLToPath(new URL("../../", import.meta.url));
const config = { root, publicDir: `${root}apps/web/public`, configFile: false, appType: "mpa", worker: { format: "es" } };
const server = await createServer({ ...config, server: { host: "127.0.0.1", port: 0, hmr: false, watch: null } });
const outDir = await mkdtemp(join(tmpdir(), "cards2-shuffle-web-"));
let browser, builtServer;
try {
  await server.listen();
  browser = await chromium.launch({ executablePath: process.env.PLAYWRIGHT_EXECUTABLE_PATH, headless: true });
  const page = await browser.newPage();
  const check = async url => {
    await page.goto(url);
    const result = await page.evaluate(() => globalThis.runWebShuffleChecks());
    assert.deepEqual(result, { cancelled: true, invalidRejected: true, accepted: ["accepted", "accepted", "accepted", "accepted"], complete: true, deckSize: 36, durable: { recoveredSeats: [1, 2, 3, null], complete: true, deckSize: 36, authoredSequence: 3, hand: { privateHandSizes: [9, 9, 9, 9], plays: 36, audit: "valid", recovered: true }, coordinated: { reverseHistoryEnvelopes: 57, audit: "valid", pending: 0, sync: "range_received" } } });
    return result;
  };
  const development = await check(`${server.resolvedUrls.local[0]}experiments/shuffle-backend/web-shuffle-harness.html`);
  // The dev server sets NODE_ENV; explicitly build the second harness as production.
  const previousNodeEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = "production";
  await build({ ...config, base: "./", logLevel: "error", build: { outDir, emptyOutDir: true,
    rolldownOptions: { input: resolve(root, "experiments/shuffle-backend/web-shuffle-harness.html") } } });
  if (previousNodeEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = previousNodeEnv;
  builtServer = httpServer(async (request, response) => {
    try {
      const path = new URL(request.url, "http://localhost").pathname;
      if (path === "/favicon.ico") { response.writeHead(204); response.end(); return; }
      if (!path.startsWith("/nested/")) throw new Error("Invalid path");
      const file = resolve(outDir, path.slice(8));
      if (!file.startsWith(outDir + "/")) throw new Error("Invalid path");
      response.setHeader("Content-Type", file.endsWith(".wasm") ? "application/wasm" : file.endsWith(".js") ? "text/javascript" : "text/html");
      response.end(await readFile(file));
    } catch { console.error(`Missing harness asset: ${request.url}`); response.writeHead(404); response.end(); }
  });
  await new Promise(resolve => builtServer.listen(0, "127.0.0.1", resolve));
  const production = await check(`http://127.0.0.1:${builtServer.address().port}/nested/experiments/shuffle-backend/web-shuffle-harness.html`);
  console.log(JSON.stringify({ development, production }));
} finally {
  await browser?.close(); await server.close();
  if (builtServer) await new Promise(resolve => builtServer.close(resolve));
  await rm(outDir, { recursive: true, force: true });
}
