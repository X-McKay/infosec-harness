/**
 * The mocked test fixture. Every test gets:
 *  - `api`: the synthetic /api served from e2e/fixtures/ (installed before the test runs);
 *  - a frozen clock, so relative times and elapsed durations are deterministic;
 *  - a guard that fails the test on any console error, uncaught page error or request that
 *    leaves the preview origin. A browser "Failed to load resource" line for an /api response
 *    the mock deliberately answered with an error status is expected and ignored.
 */
import { test as base, expect, type Page } from "@playwright/test";
import { MockApi } from "./mock-api";

/** 2026-10-05 12:00 UTC: after every completed fixture, five minutes into the running one. */
export const FIXED_NOW = new Date("2026-10-05T12:00:00Z");

type Fixtures = {
  api: MockApi;
  /** Console error texts the test expects; matched against the message text. */
  allowedConsoleErrors: RegExp[];
  guard: void;
};

const API_STATUS_LINE =
  /^Failed to load resource: the server responded with a status of \d{3}/;

export const test = base.extend<Fixtures>({
  allowedConsoleErrors: [[], { option: true }],
  // Automatic, so no mocked test can reach the preview server's /api proxy.
  api: [
    async ({ page }, use) => {
      const api = new MockApi(page);
      await api.install();
      await page.clock.setFixedTime(FIXED_NOW);
      await use(api);
    },
    { auto: true },
  ],
  guard: [
    async ({ page, allowedConsoleErrors, baseURL }, use) => {
      const problems: string[] = [];
      const origin = new URL(baseURL ?? "http://127.0.0.1:4173").origin;
      page.on("console", (message) => {
        if (message.type() !== "error") return;
        const text = message.text();
        const location = message.location().url ?? "";
        if (API_STATUS_LINE.test(text) && location.includes("/api/")) return;
        if (allowedConsoleErrors.some((pattern) => pattern.test(text))) return;
        problems.push(`console error: ${text} (${location})`);
      });
      page.on("pageerror", (error) =>
        problems.push(`page error: ${error.message}`),
      );
      page.on("request", (request) => {
        const url = request.url();
        if (url.startsWith("data:") || url.startsWith("blob:")) return;
        if (new URL(url).origin !== origin)
          problems.push(`request left the preview origin: ${url}`);
      });
      await use();
      expect(
        problems,
        "console errors, page errors or foreign requests",
      ).toEqual([]);
    },
    { auto: true },
  ],
});

export { expect };

/** True when the document is wider than the viewport (horizontal page scroll). */
export async function horizontalOverflow(page: Page) {
  return page.evaluate(() => {
    const root = document.documentElement;
    return { scrollWidth: root.scrollWidth, clientWidth: root.clientWidth };
  });
}

/** Set by fixture text if any markup in recorded content ever executed. */
export async function pwned(page: Page) {
  return page.evaluate(
    () => (window as unknown as { __e2ePwned?: unknown }).__e2ePwned ?? null,
  );
}
