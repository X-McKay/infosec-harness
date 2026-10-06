import type { Page } from "@playwright/test";
import { expect, test } from "./support/test";

/**
 * The phone header shows only the runtime summary line; the rest of the health summary sits
 * behind its disclosure button. The sidebar (768px and wider) always shows every line.
 */
async function openRuntimeDetails(page: Page) {
  const toggle = page.getByRole("button", { name: "Runtime details" });
  if (await toggle.isVisible()) {
    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-expanded", "true");
  }
}

test.describe("runtime", () => {
  test("shows what the health endpoint reports and keeps the runtime not checked", async ({
    page,
  }) => {
    await page.goto("/runtime");
    await expect(
      page.getByRole("heading", { level: 1, name: "Runtime" }),
    ).toBeVisible();
    const health = page.locator("div.rounded-lg", {
      has: page.getByRole("heading", { name: "API health" }),
    });
    const field = (label: string) =>
      health
        .locator("dt", { hasText: new RegExp(`^${label}$`) })
        .locator("xpath=following-sibling::dd");
    await expect(field("Status")).toHaveText("control plane ready");
    await expect(field("Generation")).toHaveText("v11");
    await expect(field("Task queue")).toHaveText("investigate-v11");
    await expect(field("Native OpenShell runtime")).toHaveText("not checked");
    await expect(
      page.getByText("generation v11", { exact: true }),
    ).toBeVisible();
    await expect(page.getByText("http://127.0.0.1:4173/api")).toBeVisible();
    await expect(health).toContainText(
      "It does not establish model availability, provider credentials or sandbox isolation",
    );
    // Sidebar summary
    const sidebar = page
      .getByRole("status")
      .filter({ hasText: "Native runtime" });
    await expect(sidebar).toContainText("control plane ready");
    await expect(sidebar).toContainText("Native runtime: not checked");
  });

  test("shows the Temporal connectivity the API reports", async ({ page }) => {
    await page.goto("/runtime");
    const health = page.locator("div.rounded-lg", {
      has: page.getByRole("heading", { name: "API health" }),
    });
    await expect(
      health
        .locator("dt", { hasText: /^Temporal$/ })
        .locator("xpath=following-sibling::dd"),
    ).toHaveText("reachable");
    await openRuntimeDetails(page);
    await expect(page.getByText("Temporal: reachable")).toBeVisible();
  });

  test("an unreachable Temporal is reported as such, never as ready", async ({
    page,
    api,
  }) => {
    // The API answers 503 with the Health body when Temporal is unreachable.
    api.on("GET", /^\/api\/health$/, {
      status: 503,
      body: {
        status: "temporal_unavailable",
        temporal: false,
        runtime: "not_checked",
        generation: "v11",
        task_queue: "investigate-v11",
      },
    });
    await page.goto("/runtime");
    const health = page.locator("div.rounded-lg", {
      has: page.getByRole("heading", { name: "API health" }),
    });
    const field = (label: string) =>
      health
        .locator("dt", { hasText: new RegExp(`^${label}$`) })
        .locator("xpath=following-sibling::dd");
    await expect(field("Status")).toHaveText("temporal unavailable");
    await expect(field("Temporal")).toHaveText("unreachable");
    await openRuntimeDetails(page);
    await expect(page.getByText("Temporal: unreachable")).toBeVisible();
    await expect(page.getByText("control plane ready")).toHaveCount(0);
  });

  test("an unhealthy API is reported, not inferred", async ({ page, api }) => {
    api.on("GET", /^\/api\/health$/, {
      status: 503,
      body: { detail: "Workflow service unavailable" },
    });
    await page.goto("/runtime");
    await expect(page.getByText("API unavailable")).toBeVisible({
      timeout: 10_000,
    });
    await expect(page.getByRole("alert")).toContainText("503");
  });
});

test.describe("appearance", () => {
  const isDark = (page: import("@playwright/test").Page) =>
    page.evaluate(() => document.documentElement.classList.contains("dark"));

  test("follows the system preference by default", async ({ page }, info) => {
    await page.goto("/");
    await expect(
      page.getByRole("combobox", { name: "Appearance" }),
    ).toHaveValue("system");
    expect(await isDark(page)).toBe(info.project.name === "dark");
  });

  test("a chosen appearance persists across reloads", async ({ page }) => {
    await page.goto("/");
    const select = page.getByRole("combobox", { name: "Appearance" });
    await select.selectOption("dark");
    await expect.poll(() => isDark(page)).toBe(true);
    await page.reload();
    await expect(select).toHaveValue("dark");
    expect(await isDark(page)).toBe(true);
    expect(
      await page.evaluate(() => localStorage.getItem("harness-theme")),
    ).toBe("dark");

    await select.selectOption("light");
    await expect.poll(() => isDark(page)).toBe(false);
    await page.goto("/runtime");
    await expect(
      page.getByRole("combobox", { name: "Appearance" }).first(),
    ).toHaveValue("light");
    expect(await isDark(page)).toBe(false);
  });
});
