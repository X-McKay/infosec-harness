import { defineConfig, devices } from "@playwright/test";

const PORT = 4173;
const baseURL = `http://127.0.0.1:${PORT}`;
const CI = !!process.env.CI;

/**
 * End-to-end tests against the production bundle served by `vite preview`. The default suite
 * answers every `/api/*` request from e2e/fixtures/ (see e2e/support/); only
 * e2e/live-smoke.spec.ts, gated by E2E_LIVE_API_URL, reaches a real API, and only with GETs.
 */
export default defineConfig({
  testDir: "./e2e",
  outputDir: "./test-results",
  fullyParallel: true,
  forbidOnly: CI,
  retries: CI ? 1 : 0,
  workers: CI ? 2 : undefined,
  timeout: 30_000,
  expect: { timeout: 5_000 },
  reporter: [
    [CI ? "github" : "list"],
    ["html", { outputFolder: "playwright-report", open: "never" }],
  ],
  use: {
    baseURL,
    trace: "on-first-retry",
    locale: "en-US",
    timezoneId: "UTC",
  },
  projects: [
    {
      name: "desktop",
      use: { ...devices["Desktop Chrome"], viewport: { width: 1280, height: 800 } },
    },
    {
      name: "dark",
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 1280, height: 800 },
        colorScheme: "dark",
      },
    },
    { name: "mobile", use: { ...devices["Pixel 7"] } },
  ],
  webServer: {
    command: `npm run build && npm run preview -- --host 127.0.0.1 --port ${PORT} --strictPort`,
    url: baseURL,
    // Reuse only on request: another checkout's preview on this port would test the wrong build.
    reuseExistingServer: !!process.env.E2E_REUSE_SERVER,
    timeout: 180_000,
    stdout: "ignore",
    stderr: "pipe",
  },
});
