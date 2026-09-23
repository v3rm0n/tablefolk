import { expect, test, type Page } from "@playwright/test";
import { writeFile } from "node:fs/promises";
import { WebSocketServer, WebSocket } from "ws";

test("four isolated browser identities play and recover the first Sasku round over real WebRTC", async ({ browser, baseURL }, testInfo) => {
  test.setTimeout(300_000);
  const server = new WebSocketServer({ host: "127.0.0.1", port: 0 });
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const address = server.address();
  if (typeof address === "string" || address === null) { throw new Error("Relay did not open"); }
  const relayUrl = `ws://127.0.0.1:${address.port}/`;
  const subscriptions = new Map<WebSocket, { id: string; topic: string; kinds: number[] }>();
  server.on("connection", (socket) => {
    socket.on("message", (data) => {
      const [type, id, payload] = JSON.parse(data.toString());
      if (type === "REQ") {
        subscriptions.set(socket, { id, topic: payload["#x"][0], kinds: payload.kinds });
        socket.send(JSON.stringify(["EOSE", id]));
      } else if (type === "EVENT") {
        const event = id;
        socket.send(JSON.stringify(["OK", event.id, true, "accepted"]));
        const topic = event.tags.find((tag: string[]) => tag[0] === "x")?.[1];
        for (const [target, subscription] of subscriptions) {
          if (target.readyState === WebSocket.OPEN && subscription.topic === topic && subscription.kinds.includes(event.kind)) {
            target.send(JSON.stringify(["EVENT", subscription.id, event]));
          }
        }
      }
    });
    socket.on("close", () => subscriptions.delete(socket));
  });
  const contexts = await Promise.all(Array.from({ length: 4 }, () => browser.newContext({ viewport: { width: 1440, height: 1100 } })));
  for (const context of contexts) {
    await context.addInitScript(() => {
      const Native = window.RTCPeerConnection;
      const logs: Array<Record<string, unknown>[]> = [];
      Object.defineProperty(window, "__rtcDiagnostics", { value: logs });
      const description = (value: RTCSessionDescriptionInit | null) => {
        const sdp = value?.sdp ?? "";
        const origin = /^o=\S+ (\S+) (\S+)/m.exec(sdp);
        return {
          type: value?.type, origin: origin?.[1], version: origin?.[2],
          ufrag: /^a=ice-ufrag:([^\r\n]+)/m.exec(sdp)?.[1],
          fingerprint: /^a=fingerprint:([^\r\n]+)/m.exec(sdp)?.[1],
          candidates: (sdp.match(/^a=candidate:/gm) ?? []).length,
          media: [...sdp.matchAll(/^m=(\S+) (\d+) (.+)\r?$/gm)].map((match) => ({
            kind: match[1], rejected: match[2] === "0", protocol: match[3]?.trim(),
          })),
          bundle: /^a=group:BUNDLE ([^\r\n]+)/m.exec(sdp)?.[1],
          endOfCandidates: /^a=end-of-candidates/m.test(sdp),
        };
      };
      class ObservedPeer extends Native {
        readonly trace: Array<Record<string, unknown>>;
        constructor(configuration?: RTCConfiguration) {
          super(configuration);
          this.trace = [];
          logs.push(this.trace);
          for (const name of ["connectionstatechange", "iceconnectionstatechange", "icegatheringstatechange", "signalingstatechange", "negotiationneeded"]) {
            this.addEventListener(name, () => this.record(name));
          }
          this.addEventListener("icecandidate", (event) => this.record("local-candidate", {
            ufrag: event.candidate?.usernameFragment, candidateType: event.candidate?.type,
          }));
        }
        record(event: string, data?: unknown): void {
          if (this.trace.length >= 300) { return; }
          this.trace.push({ time: Date.now(), event, data, signaling: this.signalingState, ice: this.iceConnectionState,
            gathering: this.iceGatheringState, sctp: this.sctp?.state,
            connection: this.connectionState, local: description(this.localDescription), remote: description(this.remoteDescription) });
        }
        override setLocalDescription(value?: RTCLocalSessionDescriptionInit): Promise<void> {
          this.record("set-local", value?.type);
          const result = value === undefined ? super.setLocalDescription() : super.setLocalDescription(value);
          void result.then(() => this.record("set-local-ok"), (error: Error) => this.record("set-local-error", error.message));
          return result;
        }
        override setRemoteDescription(value: RTCSessionDescriptionInit): Promise<void> {
          this.record("set-remote", description(value));
          const result = super.setRemoteDescription(value);
          void result.then(() => this.record("set-remote-ok"), (error: Error) => this.record("set-remote-error", error.message));
          return result;
        }
        override addIceCandidate(value?: RTCIceCandidateInit | null): Promise<void> {
          this.record("add-candidate", { ufrag: value?.usernameFragment, mid: value?.sdpMid });
          const result = super.addIceCandidate(value);
          void result.then(() => this.record("add-candidate-ok"), (error: Error) => this.record("add-candidate-error", error.message));
          return result;
        }
        override close(): void {
          this.record("close");
          super.close();
        }
      }
      window.RTCPeerConnection = ObservedPeer;
    });
  }
  const pages = await Promise.all(contexts.map((context) => context.newPage()));
  const errors: string[] = [];
  pages.forEach((page, index) => page.on("pageerror", (error) => errors.push(`${index}: ${error.message}`)));
  try {
    for (const page of pages) { await page.goto(baseURL!); await expect(page.getByRole("button", { name: "Open a table" })).toBeEnabled(); }
    await configureRelay(pages[0]!, relayUrl);
    await pages[0]!.screenshot({ path: testInfo.outputPath("welcome-desktop.png"), fullPage: true });
    await pages[0]!.getByRole("button", { name: "Open a table" }).click();
    await expect(pages[0]!.getByLabel("Share this invitation")).toBeVisible();
    const invitation = await pages[0]!.getByLabel("Share this invitation").inputValue();
    const duplicateTab = await contexts[0]!.newPage();
    await duplicateTab.goto(invitation);
    await expect(duplicateTab.getByRole("button", { name: "Join this table" })).toBeEnabled();
    await duplicateTab.getByRole("button", { name: "Join this table" }).click();
    await expect(duplicateTab.getByRole("alert")).toContainText("already open in another tab");
    await duplicateTab.close();
    for (const page of pages.slice(1)) {
      await configureRelay(page, relayUrl);
      await page.getByLabel("Invitation link", { exact: true }).fill(invitation);
      await page.getByRole("button", { name: "Join this table" }).click();
      await expect(page.getByLabel("Share this invitation")).toBeVisible();
    }
    for (const page of pages) {
      await expect(page.getByText("4 / 4 seated", { exact: true })).toBeVisible();
      await expect(page.getByRole("button", { name: "Mark ready", exact: true })).toBeEnabled();
    }
    const ownFingerprint = (page: Page) => page.locator(".seat").filter({ has: page.getByRole("heading", { name: /^You/ }) }).locator(".seat__fingerprint").textContent();
    const identities = await Promise.all(pages.map(ownFingerprint));
    expect(new Set(identities).size).toBe(4);
    await pages[2]!.reload();
    await expect(pages[2]!.getByRole("button", { name: "Join this table" })).toBeEnabled();
    await configureRelay(pages[2]!, relayUrl);
    await pages[2]!.getByRole("button", { name: "Join this table" }).click();
    for (const page of pages) { await expect(page.getByRole("button", { name: "Mark ready", exact: true })).toBeEnabled(); }
    expect(await ownFingerprint(pages[2]!)).toBe(identities[2]);
    await pages[0]!.screenshot({ path: testInfo.outputPath("lobby-desktop.png"), fullPage: true });
    await pages[3]!.setViewportSize({ width: 390, height: 844 });
    await expect.poll(() => pages[3]!.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await pages[3]!.screenshot({ path: testInfo.outputPath("lobby-mobile.png"), fullPage: true });
    for (const page of pages) { await page.getByRole("button", { name: "Mark ready", exact: true }).click(); }
    for (const page of pages) { await expect(page.getByRole("heading", { name: "A lobby, agreed." })).toBeVisible(); }
    const transcripts = await Promise.all(pages.map((page) => page.evaluate(async () => {
      const database = await new Promise<IDBDatabase>((resolve, reject) => {
        const request = indexedDB.open("p2pcards"); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
      });
      const rows = await new Promise<Array<{ bytes: Uint8Array }>>((resolve, reject) => {
        const request = database.transaction("transcripts", "readonly").objectStore("transcripts").getAll();
        request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
      });
      database.close();
      return rows.map(({ bytes }) => Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("")).sort();
    })));
    expect(transcripts[0]).toHaveLength(11);
    for (const transcript of transcripts.slice(1)) { expect(transcript).toEqual(transcripts[0]); }
    expect(errors).toEqual([]);
    // Model a locally authored roster committed before its derived snapshot was written.
    await pages[0]!.evaluate(async () => {
      const database = await new Promise<IDBDatabase>((resolve, reject) => {
        const request = indexedDB.open("p2pcards"); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
      });
      await new Promise<void>((resolve, reject) => {
        const transaction = database.transaction("games", "readwrite");
        transaction.oncomplete = () => resolve(); transaction.onabort = () => reject(transaction.error);
        const store = transaction.objectStore("games");
        const request = store.getAll();
        request.onsuccess = () => {
          for (const record of request.result) { delete record.lobbyRoster; store.put(record); }
        };
      });
      database.close();
    });
    await pages[0]!.reload();
    await expect(pages[0]!.getByRole("button", { name: "Join this table" })).toBeEnabled();
    await configureRelay(pages[0]!, relayUrl);
    await pages[0]!.getByRole("button", { name: "Join this table" }).click();
    await expect(pages[0]!.getByRole("heading", { name: "A lobby, agreed." })).toBeVisible();
    await expect(pages[0]!.locator(".diagnostics > summary")).toContainText("3 verified links");
    for (const page of pages) await page.getByRole("button", { name: "Play first round", exact: true }).click();
    for (const page of pages) await expect(page.getByLabel("Live Sasku round")).toHaveAttribute("data-phase", "bidding", { timeout: 120_000 });
    for (const page of pages) await expect(page.getByLabel("Your private hand").getByRole("button")).toHaveCount(9);
    for (const page of pages) {
      await expect(page.getByRole("heading", { name: "A lobby, agreed." })).not.toBeVisible();
      await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    }
    await pages[0]!.screenshot({ path: testInfo.outputPath("live-table-desktop.png"), fullPage: true });
    await pages[3]!.screenshot({ path: testInfo.outputPath("live-table-mobile.png"), fullPage: true });

    // Restore a private hand from persisted signed history and its existing local secret.
    const beforeHand = await pages[2]!.getByLabel("Your private hand").getByRole("button").evaluateAll(buttons => buttons.map(b => b.getAttribute("aria-label")));
    await pages[2]!.reload();
    await expect(pages[2]!.getByRole("button", { name: "Join this table" })).toBeEnabled();
    await configureRelay(pages[2]!, relayUrl);
    await pages[2]!.getByRole("button", { name: "Join this table" }).click();
    await expect(pages[2]!.getByLabel("Live Sasku round")).toHaveAttribute("data-phase", "bidding", { timeout: 120_000 });
    await expect.poll(() => pages[2]!.getByLabel("Your private hand").getByRole("button").evaluateAll(buttons => buttons.map(b => b.getAttribute("aria-label")))).toEqual(beforeHand);
    await pages[0]!.getByLabel("Live Sasku round").getByRole("button", { name: /^Bid / }).click();
    for (const page of pages.slice(1)) await page.getByLabel("Live Sasku round").getByRole("button", { name: "Pass", exact: true }).click();
    await pages[0]!.getByLabel("Live Sasku round").getByRole("button", { name: /^Choose clubs/ }).click();
    for (let play = 0; play < 36; play++) {
      let turn = -1;
      await expect.poll(async () => {
        const choices = await Promise.all(pages.map(p => p.getByLabel("Your private hand").locator("button:enabled").count()));
        turn = choices.findIndex(count => count > 0); return turn;
      }).toBeGreaterThanOrEqual(0);
      await pages[turn]!.getByLabel("Your private hand").locator("button:enabled").first().click();
      await expect.poll(async () => {
        const counts = await Promise.all(pages.map(p => p.getByLabel("Your private hand").getByRole("button").count()));
        return counts.reduce((sum, count) => sum + count, 0);
      }).toBe(35 - play);
      if (play === 3) {
        for (const page of pages) await expect(page.getByLabel("Last completed trick")).toBeVisible();
        await pages[0]!.screenshot({ path: testInfo.outputPath("live-trick-desktop.png"), fullPage: true });
        await pages[3]!.screenshot({ path: testInfo.outputPath("live-trick-mobile.png"), fullPage: true });
      }
    }
    for (const page of pages) {
      await expect(page.getByLabel("Live Sasku round")).toHaveAttribute("data-phase", "complete", { timeout: 60_000 });
      await expect(page.getByText("Round verified by this browser:", { exact: false })).toBeVisible();
      await expect(page.getByLabel("Your private hand").getByRole("button")).toHaveCount(0);
    }
    expect(errors).toEqual([]);

  } finally {
    for (const [index, page] of pages.entries()) {
      if (!page.isClosed()) {
        const path = testInfo.outputPath(`page-${index}.txt`);
        await writeFile(path, await page.locator("body").innerText());
        await testInfo.attach(`page-${index}`, { path, contentType: "text/plain" });
        const rtcPath = testInfo.outputPath(`rtc-${index}.json`);
        const rtc = await page.evaluate(() => (window as unknown as { __rtcDiagnostics: unknown }).__rtcDiagnostics);
        await writeFile(rtcPath, JSON.stringify(rtc, null, 2));
        await testInfo.attach(`rtc-${index}`, { path: rtcPath, contentType: "application/json" });
      }
    }
    await Promise.all(contexts.map((context) => context.close()));
    for (const socket of server.clients) { socket.terminate(); }
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test("invalid invitations fail without relay traffic and mobile welcome stays usable", async ({ page }, testInfo) => {
  const relaySockets: string[] = [];
  page.on("websocket", (socket) => { if (!socket.url().includes(":4317")) { relaySockets.push(socket.url()); } });
  await page.setViewportSize({ width: 320, height: 800 });
  await page.goto("/");
  await expect(page.getByRole("button", { name: "Open a table" })).toBeEnabled();
  await page.getByLabel("Invitation link", { exact: true }).fill("https://example.test/#g=invalid");
  await page.getByRole("button", { name: "Join this table" }).click();
  await expect(page.getByRole("alert")).toContainText("Invitation");
  expect(relaySockets).toEqual([]);
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath("welcome-mobile-error.png"), fullPage: true });
});

async function configureRelay(page: Page, relayUrl: string): Promise<void> {
  await page.getByText("Connection settings", { exact: true }).click();
  await page.getByLabel("Custom Nostr relays").fill(relayUrl);
}
