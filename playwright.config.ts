import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/browser",
  testMatch: "**/*.e2e.ts",
  workers: 1,
  timeout: 90_000,
  expect: { timeout: 30_000 },
  outputDir: process.env["PLAYWRIGHT_OUTPUT_DIR"] ?? "test-results/browser",
  reporter: "list",
  use: {
    baseURL: "http://127.0.0.1:4317",
    headless: true,
    launchOptions: {
      ...(process.env["PLAYWRIGHT_EXECUTABLE_PATH"] === undefined ? {} : { executablePath: process.env["PLAYWRIGHT_EXECUTABLE_PATH"] }),
      args: ["--disable-features=WebRtcHideLocalIpsWithMdns"],
    },
  },
  webServer: {
    command: process.env["PLAYWRIGHT_PRODUCTION"] === "1"
      ? "npm run preview --workspace @p2pcards/web -- --host 127.0.0.1 --port 4317 --strictPort"
      : "npm run dev --workspace @p2pcards/web -- --host 127.0.0.1 --port 4317 --strictPort",
    url: "http://127.0.0.1:4317",
    reuseExistingServer: !process.env["CI"] && process.env["PLAYWRIGHT_PRODUCTION"] !== "1",
  },
});
