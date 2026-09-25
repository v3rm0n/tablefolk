import { expect, test } from "@playwright/test";

test("one tab runs four local Sasku players with switchable private views", async ({ page, baseURL }, testInfo) => {
  test.setTimeout(180_000);
  const errors: string[] = [];
  const sockets: string[] = [];
  await page.addInitScript(() => {
    Object.defineProperty(window, "RTCPeerConnection", { value: class { constructor() { throw new Error("The local demo must not open WebRTC"); } } });
  });
  page.on("pageerror", error => errors.push(error.message));
  page.on("websocket", socket => { if (!socket.url().includes(":4317")) sockets.push(socket.url()); });
  await page.goto(`${baseURL}/demo.html`);

  await expect(page.getByRole("tab", { name: /Player 1/ })).toBeVisible();
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
  for (let pass = 0; pass < 3; pass++) await page.getByLabel("Live Sasku round").getByRole("button", { name: "Pass", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Choose your trump" })).toBeVisible();
  await expect(page.locator(".live-felt")).not.toContainText(/Trump choice|[♠♣♥♦]/);
  for (const width of [1280, 320]) {
    await page.setViewportSize({ width, height: 900 });
    const choices = await page.getByRole("group", { name: "Choose trump" }).boundingBox();
    const first = (await page.getByRole("button", { name: "Choose clubs" }).boundingBox())!;
    const last = (await page.getByRole("button", { name: "Choose diamonds" }).boundingBox())!;
    expect(Math.abs((first.x + last.x + last.width) / 2 - (choices!.x + choices!.width / 2))).toBeLessThan(2);
    expect(first.y).toBe(last.y);
    await page.screenshot({ path: testInfo.outputPath(`trump-choice-${width}.png`), fullPage: true });
  }
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.getByRole("button", { name: "Choose diamonds" }).click();
  await expect(page.locator(".live-contract .trump-symbol")).toHaveText("♦");
  await expect(page.locator(".live-contract .trump-symbol")).toHaveCSS("color", "rgb(181, 31, 50)");
  await expect(page.locator(".live-felt")).not.toContainText("♦");
  for (let play = 0; play < 4; play++) await page.getByLabel("Your private hand").locator("button.is-playable").first().click();
  await expect(page.locator(".live-history > summary")).toContainText("1 / 9");
  await page.screenshot({ path: testInfo.outputPath("demo-first-trick.png"), fullPage: true });
  for (const width of [1280, 620, 390, 320]) {
    await page.setViewportSize({ width, height: 900 });
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    const cards = await page.locator(".live-played-card").evaluateAll(elements => elements.map(element => {
      const { x, y, width, height } = element.getBoundingClientRect();
      return { x, y, width, height };
    }));
    expect(cards).toHaveLength(4);
    for (const [index, card] of cards.entries()) {
      expect(card.width).toBeGreaterThanOrEqual(width > 620 ? 100 : 74);
      for (const other of cards.slice(index + 1)) {
        expect(card.x + card.width <= other.x || other.x + other.width <= card.x || card.y + card.height <= other.y || other.y + other.height <= card.y).toBe(true);
      }
    }
    await page.screenshot({ path: testInfo.outputPath(`played-cards-${width}.png`), fullPage: true });
  }
  await page.getByRole("button", { name: "New demo table" }).click();
  await expect(page.getByLabel("Live Sasku round")).toHaveAttribute("data-phase", "bidding", { timeout: 120_000 });
  expect(sockets).toEqual([]);
  expect(errors).toEqual([]);
});

test("the local four-player table finishes a match to twelve points", async ({ page, baseURL }) => {
  test.setTimeout(600_000);
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.goto(`${baseURL}/demo.html`);
  await expect(page.getByLabel("Live Sasku round")).toHaveAttribute("data-phase", "bidding", { timeout: 120_000 });
  for (let round = 1; round <= 10; round += 1) {
    if (await page.getByLabel("Live Sasku round").getAttribute("data-phase") === "match_complete") break;
    await expect(page.getByText(`Sasku · Round ${round}`)).toBeVisible({ timeout: 120_000 });
    await expect(page.getByLabel("Live Sasku round")).toHaveAttribute("data-phase", "bidding", { timeout: 120_000 });
    await page.getByRole("button", { name: "Call diamonds" }).click();
    await expect(page.getByLabel("Live Sasku round")).toHaveAttribute("data-actions", "1");
    for (let play = 0; play < 36; play += 1) {
      await playDemoCard(page, play + 2);
    }
    await expect(page.getByLabel("Match scoreboard")).toContainText(`${round} ${round === 1 ? "round" : "rounds"} verified`, { timeout: 90_000 });
  }
  await expect(page.getByLabel("Live Sasku round")).toHaveAttribute("data-phase", "match_complete");
  await expect(page.getByRole("heading", { name: /won the game/ })).toBeVisible();
  expect(errors).toEqual([]);
});

async function playDemoCard(page: import("@playwright/test").Page, expectedActions: number): Promise<void> {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    await page.getByLabel("Your private hand").locator("button.is-playable:enabled").first().click();
    try {
      await expect(page.getByLabel("Live Sasku round")).toHaveAttribute("data-actions", String(expectedActions), { timeout: 5000 });
      return;
    } catch {
      if (await page.locator("[role='alert']").count()) throw new Error((await page.locator("[role='alert']").allInnerTexts()).join("; "));
    }
  }
  throw new Error(`Card play did not advance to action ${expectedActions}`);
}
