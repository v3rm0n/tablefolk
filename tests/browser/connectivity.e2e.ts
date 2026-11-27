import { expect, test } from "@playwright/test";
import { WebSocketServer } from "ws";

test("persists relay settings and surfaces relay outages and TURN credential fallback", async ({ page }) => {
  const working = new WebSocketServer({ host: "127.0.0.1", port: 0 });
  const rejecting = new WebSocketServer({ host: "127.0.0.1", port: 0 });
  const relayUrls = await Promise.all([rejecting, working].map(async server => {
    await new Promise<void>(resolve => server.once("listening", resolve));
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("Local relay did not listen");
    return `ws://127.0.0.1:${address.port}/`;
  }));
  let relayAvailable = true;
  for (const server of [working, rejecting]) {
    server.on("connection", socket => {
      socket.on("message", data => {
        const [type, id] = JSON.parse(data.toString());
        if (type !== "REQ") return;
        const result = server === working && relayAvailable
          ? ["EOSE", id]
          : ["CLOSED", id, "blocked: private upstream detail"];
        socket.send(JSON.stringify(result));
      });
    });
  }

  const relayText = relayUrls.join("\n");
  const credential = "test-only-turn-password";
  let credentialServiceAvailable = true;
  let requests = 0;
  try {
    await page.route("**/turn-credentials", route => {
      requests += 1;
      return credentialServiceAvailable
        ? route.fulfill({ json: { ttlSeconds: 3600, iceServers: [
          { urls: "turn:127.0.0.1:3478", username: "test-user", credential },
        ] } })
        : route.fulfill({ status: 503, json: { error: credential } });
    });
    await page.addInitScript(() => {
      Object.assign(globalThis, { TABLEFOLK_ICE_CONFIG: { credentialEndpoint: "/turn-credentials" } });
    });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto("/");
    await page.getByText("Connection settings", { exact: true }).click();
    const settings = page.getByLabel("Custom Nostr relays");
    const save = page.getByRole("button", { name: "Save relay settings" });
    await settings.fill("wss://user:secret@example.test/");
    await save.click();
    await expect(page.getByText(/without credentials/)).toBeVisible();
    await settings.fill(relayText);
    await save.click();
    await expect(page.getByText("Relay settings saved on this browser.")).toBeVisible();
    await page.reload();
    await page.getByText("Connection settings", { exact: true }).click();
    await expect(settings).toHaveValue(relayText);
    await page.getByRole("button", { name: "Start a game" }).click();

    await expect(page.getByLabel("Share this invitation")).toBeVisible();
    await page.getByText("Network diagnostics", { exact: false }).first().click();
    const relayList = page.locator(".relay-list");
    const workingRelay = relayList.locator("li").filter({ hasText: relayUrls[1]! });
    await expect(relayList.getByText("Nostr relay closed subscription (blocked)")).toBeVisible();
    await expect(workingRelay.getByText("connected", { exact: true })).toBeVisible();
    await expect(page.locator("body")).not.toContainText("private upstream detail");
    expect(requests).toBe(1);
    const fallback = page.getByText(/TURN credential service is unavailable/);
    await expect(fallback).toHaveCount(0);

    relayAvailable = false;
    for (const socket of working.clients) socket.close(1011);
    const outage = page.getByText(/No Nostr relay is available/);
    await expect(outage).toBeVisible();
    relayAvailable = true;
    await expect(workingRelay.getByText("connected", { exact: true })).toBeVisible();
    await expect(outage).toHaveCount(0);

    credentialServiceAvailable = false;
    await page.getByRole("button", { name: "Leave table" }).click();
    await page.getByRole("button", { name: "Start a game" }).click();
    await expect(fallback).toBeVisible();
    expect(requests).toBe(2);
    await expect(page.locator("body")).not.toContainText(credential);
  } finally {
    await page.close();
    await Promise.all([working, rejecting].map(server => {
      for (const socket of server.clients) socket.terminate();
      return new Promise<void>(resolve => server.close(() => resolve()));
    }));
  }
});
