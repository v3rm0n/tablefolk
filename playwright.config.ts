import { defineConfig } from "@playwright/test";

const browser = process.env["PLAYWRIGHT_BROWSER"] ?? "chromium";
if (browser !== "chromium" && browser !== "firefox" && browser !== "webkit") {
  throw new Error("PLAYWRIGHT_BROWSER must be chromium, firefox, or webkit");
}

const port = process.env["PLAYWRIGHT_PORT"] ?? "4317";
if (!/^\d{1,5}$/.test(port) || Number(port) < 1 || Number(port) > 65535) {
  throw new Error("PLAYWRIGHT_PORT must be a valid TCP port");
}
const baseURL = `http://127.0.0.1:${port}`;

export default defineConfig({
  testDir: "./tests/browser",
  testMatch: "**/*.e2e.ts",
  workers: 1,
  timeout: 90_000,
  expect: { timeout: 30_000 },
  outputDir: process.env["PLAYWRIGHT_OUTPUT_DIR"] ?? "test-results/browser",
  reporter: "list",
  use: {
    baseURL,
    headless: true,
    browserName: browser,
    launchOptions: {
      ...(process.env["PLAYWRIGHT_EXECUTABLE_PATH"] === undefined ? {} : { executablePath: process.env["PLAYWRIGHT_EXECUTABLE_PATH"] }),
      ...(browser === "chromium" ? { args: ["--disable-features=WebRtcHideLocalIpsWithMdns"] } : {}),
    },
  },
  webServer: {
    command: process.env["PLAYWRIGHT_PRODUCTION"] === "1"
      ? `npm run preview --workspace @p2pcards/web -- --host 127.0.0.1 --port ${port} --strictPort`
      : `npm run dev --workspace @p2pcards/web -- --host 127.0.0.1 --port ${port} --strictPort`,
    url: baseURL,
    reuseExistingServer: !process.env["CI"] && process.env["PLAYWRIGHT_PRODUCTION"] !== "1",
  },
});
