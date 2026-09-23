import { expect, test } from "@playwright/test";

test("public hand practice runs bidding, all nine tricks, scoring, and dealer rotation", async ({ page }, testInfo) => {
  const sockets: string[] = [];
  page.on("websocket", (socket) => { if (!socket.url().includes(":4317")) { sockets.push(socket.url()); } });
  await page.setViewportSize({ width: 1440, height: 1100 });
  await page.goto("/");
  await expect(page.getByRole("button", { name: "Open a table" })).toBeEnabled();
  const location = page.url();
  const practice = page.locator(".hand-practice");
  await practice.locator(":scope > summary").click();
  await expect(practice.getByRole("heading", { name: "Seat 1 to bid" })).toBeVisible();
  await practice.getByLabel("Public practice deal").selectOption("1");
  await practice.getByRole("button", { name: "Pass", exact: true }).click();
  await practice.getByRole("button", { name: "Bid 5", exact: true }).click();
  await expect(practice.getByRole("button", { name: "Bid 4", exact: true })).toBeDisabled();
  await practice.getByRole("button", { name: "Pass", exact: true }).click();
  await practice.getByRole("button", { name: "Pass", exact: true }).click();
  await practice.getByRole("button", { name: "Bid 8", exact: true }).click();
  for (let pass = 0; pass < 3; pass += 1) { await practice.getByRole("button", { name: "Pass", exact: true }).click(); }
  await expect(practice.getByRole("heading", { name: "Seat 1 chooses trump" })).toBeVisible();
  await practice.getByLabel("Public practice deal").selectOption("0");
  await practice.getByRole("button", { name: "Bid 6", exact: true }).click();
  await expect(practice.getByRole("heading", { name: "Seat 2 to bid" })).toBeVisible();
  await expect(practice.getByRole("button", { name: "Bid 6", exact: true })).toBeDisabled();
  for (let pass = 0; pass < 3; pass += 1) { await practice.getByRole("button", { name: "Pass", exact: true }).click(); }
  await expect(practice.getByRole("heading", { name: "Seat 1 chooses trump" })).toBeVisible();
  await practice.getByRole("button", { name: /^Choose hearts/ }).click();
  await expect(practice.getByRole("heading", { name: "Seat 1 to play" })).toBeVisible();
  await practice.screenshot({ path: testInfo.outputPath("hand-desktop.png") });
  for (let play = 0; play < 36; play += 1) {
    const available = practice.locator(".full-hand-cards button:not(:disabled)");
    await expect(available.first()).toBeVisible();
    await available.first().click();
    await expect(practice.locator(".hand-ledger")).toContainText(`${35 - play} cards remain in the hands.`);
    if (play === 3) {
      await page.setViewportSize({ width: 320, height: 800 });
      await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      await practice.screenshot({ path: testInfo.outputPath("hand-mobile.png") });
    }
  }
  await expect(practice.getByRole("heading", { name: "Practice hand complete" })).toBeVisible();
  await expect(practice.locator(".hand-ledger h3")).toHaveText("9 of 9 tricks");
  await expect(practice.getByRole("status")).toContainText("All 36 cards and 120 card points are accounted for");
  await expect(practice.getByRole("status")).toContainText("Next dealer: seat 1");
  await practice.getByRole("button", { name: "Next practice hand" }).click();
  await expect(practice.getByRole("heading", { name: "Seat 2 to bid" })).toBeVisible();
  for (let pass = 0; pass < 4; pass += 1) { await practice.getByRole("button", { name: "Pass", exact: true }).click(); }
  await expect(practice.getByRole("heading", { name: "Seat 2 to play" })).toBeVisible();
  await expect(practice.locator(".hand-contract")).toContainText("pass-round");
  await practice.getByRole("button", { name: "Restart example hand" }).click();
  await practice.getByRole("button", { name: "Name diamonds now" }).click();
  await expect(practice.getByRole("heading", { name: "Seat 2 to play" })).toBeVisible();
  await expect(practice.locator(".hand-contract")).toContainText("declared by seat 2");
  expect(sockets).toEqual([]);
  expect(page.url()).toBe(location);
  await expect(page.getByRole("button", { name: "Open a table" })).toBeEnabled();
});
