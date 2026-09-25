import { expect, test } from "@playwright/test";

test("one tab runs four local Sasku players with switchable private views", async ({ page, baseURL }, testInfo) => {
  test.setTimeout(180_000);
  const errors: string[] = [];
  const sockets: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  page.on("websocket", socket => sockets.push(socket.url()));
  await page.goto(`${baseURL}/demo.html`);

  await expect(page.getByRole("tab", { name: /Player 1/ })).toBeVisible();
  await expect(page.getByRole("button", { name: "Play first round" })).toBeEnabled({ timeout: 90_000 });
  await expect(page.getByText("4 / 4 seated", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Share this invitation")).toHaveCount(0);
  await page.screenshot({ path: testInfo.outputPath("demo-lobby.png"), fullPage: true });

  await page.getByRole("button", { name: "Play first round" }).click();
  await expect(page.getByLabel("Live Sasku round")).toHaveAttribute("data-phase", "bidding", { timeout: 120_000 });
  await expect(page.getByLabel("Your private hand").getByRole("button")).toHaveCount(9);
  const firstHand = await page.getByLabel("Your private hand").getByRole("button").evaluateAll(cards => cards.map(card => card.getAttribute("aria-label")));
  await page.getByRole("tab", { name: /Player 2/ }).click();
  await expect(page.getByRole("tab", { name: /Player 2/ })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByLabel("Your private hand").getByRole("button")).toHaveCount(9);
  const secondHand = await page.getByLabel("Your private hand").getByRole("button").evaluateAll(cards => cards.map(card => card.getAttribute("aria-label")));
  expect(secondHand).not.toEqual(firstHand);
  await page.getByRole("button", { name: "Go to player 1" }).click();
  await page.getByLabel("Live Sasku round").getByRole("button", { name: /^Bid / }).first().click();
  await expect(page.getByRole("tab", { name: /Player 2/ })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("heading", { name: "Your turn to bid" })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("demo-bidding.png"), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.getByRole("button", { name: "New demo table" }).click();
  await expect(page.getByRole("button", { name: "Play first round" })).toBeEnabled({ timeout: 90_000 });
  expect(sockets).toEqual([]);
  expect(errors).toEqual([]);
});
