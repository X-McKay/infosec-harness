/**
 * Opt-in smoke test against a real API: set E2E_LIVE_API_URL (for example
 * http://127.0.0.1:8000) and run `npm run e2e -- --project=desktop live-smoke`.
 *
 * The UI still loads from the local preview; its same-origin /api requests are forwarded to
 * E2E_LIVE_API_URL. Only GET is forwarded: any other method is aborted and fails the test, so
 * this never submits or cancels an investigation. Skipped when the variable is unset.
 */
import { expect, test } from "@playwright/test";

const LIVE = process.env.E2E_LIVE_API_URL?.replace(/\/+$/, "");

test.describe("live API smoke (GET only)", () => {
  test.skip(!LIVE, "E2E_LIVE_API_URL is not set");

  test("lists runs, opens one, lists reports and reads health without errors", async ({
    page,
  }) => {
    test.skip(
      test.info().project.name !== "desktop",
      "live smoke runs once, on the desktop project",
    );
    const problems: string[] = [];
    const refused: string[] = [];
    page.on("console", (message) => {
      if (message.type() === "error") problems.push(message.text());
    });
    page.on("pageerror", (error) => problems.push(error.message));
    await page.route("**/api/**", async (route) => {
      const request = route.request();
      if (request.method() !== "GET") {
        refused.push(`${request.method()} ${request.url()}`);
        return route.abort("blockedbyclient");
      }
      const url = new URL(request.url());
      try {
        const response = await route.fetch({
          url: `${LIVE}${url.pathname}${url.search}`,
        });
        await route.fulfill({ response });
      } catch {
        // A poll still in flight when the test ends finds its page closed. During the test an
        // aborted request surfaces as a console error, which fails it below.
        await route.abort("failed").catch(() => {});
      }
    });

    const listed = page.waitForResponse(
      (response) => new URL(response.url()).pathname === "/api/runs",
    );
    await page.goto("/");
    await expect(
      page.getByRole("heading", { level: 1, name: "Investigations" }),
    ).toBeVisible();
    const runs = (await (await listed).json()) as { items: { id: string }[] };

    if (runs.items.length) {
      await page.goto(`/runs/${encodeURIComponent(runs.items[0].id)}`);
      await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
      await expect(page.getByRole("heading", { level: 1 })).not.toHaveText(
        "Investigation not found",
      );
    }

    await page.goto("/reports");
    await expect(
      page.getByRole("heading", { level: 1, name: "Reports" }),
    ).toBeVisible();
    await expect(page.getByText("Loading current data…")).toHaveCount(0, {
      timeout: 15_000,
    });

    await page.goto("/runtime");
    await expect(page.getByRole("heading", { name: "API health" })).toBeVisible(
      {
        timeout: 15_000,
      },
    );

    expect(refused, "non-GET requests").toEqual([]);
    expect(problems, "console or page errors").toEqual([]);
  });
});
