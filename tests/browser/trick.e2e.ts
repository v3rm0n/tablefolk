import { expect, test } from "@playwright/test";

test("trick practice enforces effective suits and free discard without touching the lobby", async ({ page }, testInfo) => {
  const sockets: string[] = [];
  page.on("websocket", (socket) => { if (!socket.url().includes(":4317")) { sockets.push(socket.url()); } });
  await page.setViewportSize({ width: 1440, height: 1100 });
  await page.goto("/");
  await expect(page.getByRole("button", { name: "Open a table" })).toBeEnabled();
  const location = page.url();
  await page.locator(".trick-reference > summary").click();
  const trick = page.getByRole("region", { name: "Example trick", exact: true });
  await expect(page.getByRole("button", { name: "Play queen of hearts", exact: true })).toBeEnabled();
  await expect(page.getByRole("button", { name: "Play ten of clubs", exact: true })).toBeEnabled();
  await page.getByRole("button", { name: "Play queen of hearts", exact: true }).click();
  await expect(trick.getByRole("heading", { name: "Seat 4 takes the trick" })).toBeVisible();
  await expect(trick.getByRole("status")).toContainText("24 card points");
  await page.getByRole("button", { name: "Try another card" }).click();
  await page.getByRole("button", { name: "Play ten of clubs", exact: true }).click();
  await expect(trick.getByRole("heading", { name: "Seat 2 takes the trick" })).toBeVisible();

  await page.getByLabel("Practice situation").selectOption("1");
  await expect(page.getByRole("button", { name: "Play ace of hearts", exact: true })).toBeEnabled();
  await expect(page.getByRole("button", { name: "Play queen of hearts", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Play ace of diamonds", exact: true })).toBeDisabled();
  await page.getByRole("button", { name: "Play ace of hearts", exact: true }).click();
  await expect(trick.getByRole("heading", { name: "Seat 4 takes the trick" })).toBeVisible();

  await page.getByLabel("Practice situation").selectOption("2");
  await expect(page.getByRole("button", { name: "Play ace of hearts", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Play king of diamonds", exact: true })).toBeEnabled();
  await expect(page.getByRole("button", { name: "Play nine of diamonds", exact: true })).toBeEnabled();
  await page.getByRole("button", { name: "Play ace of diamonds", exact: true }).click();
  await expect(trick.getByRole("heading", { name: "Seat 1 takes the trick" })).toBeVisible();
  await expect(trick.getByRole("status")).toContainText("13 card points");
  await page.locator(".trick-reference").screenshot({ path: testInfo.outputPath("trick-desktop.png") });
  await page.setViewportSize({ width: 320, height: 800 });
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.locator(".trick-reference").screenshot({ path: testInfo.outputPath("trick-mobile.png") });
  expect(sockets).toEqual([]);
  expect(page.url()).toBe(location);
  await expect(page.getByRole("button", { name: "Open a table" })).toBeEnabled();
});
