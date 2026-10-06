import type { Page } from "@playwright/test";
import { expect, test } from "./support/test";

const section = (page: Page, title: string) =>
  page.locator("div.rounded-lg", {
    has: page.getByRole("heading", { name: title, exact: true }),
  });

test.describe("metrics", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/metrics");
    await expect(
      page.getByRole("heading", { level: 1, name: "Metrics" }),
    ).toBeVisible();
  });

  test("plots one row per full-corpus cohort, oldest first, marking unfinished ones", async ({
    page,
  }) => {
    const chart = section(page, "Task success rate");
    await chart.getByText("View data table").click();
    const data = chart.getByRole("table", { name: "Task success rate data" });
    const rows = data.getByRole("row").filter({ has: page.getByRole("cell") });
    await expect(rows).toHaveCount(3);
    await expect(rows.nth(0)).toContainText("model-20261004T090000Z.json");
    await expect(rows.nth(0)).toContainText("92%");
    await expect(rows.nth(1)).toContainText("model-20261005T090000Z.json");
    await expect(rows.nth(1)).toContainText("67%");
    await expect(rows.nth(2)).toContainText(
      "model-20261006T080000Z.json (not finished, partial)",
    );
    // Diagnostic subsets never enter the cohort series.
    await expect(data).not.toContainText("diagnostic");

    const completion = section(page, "Completed of planned");
    await completion.getByText("View data table").click();
    const completed = completion.getByRole("table", {
      name: "Completed of planned data",
    });
    await expect(completed.getByRole("row").nth(2)).toContainText("28 / 36");

    for (const title of ["Unsafe negatives", "Median case duration"])
      await expect(section(page, title).getByRole("img")).toHaveAttribute(
        "aria-label",
        `${title} for 3 reports, oldest first`,
      );
  });

  test("the latest complete cohort shows its gate states", async ({ page }) => {
    const latest = section(page, "Latest complete cohort");
    await expect(
      latest.getByRole("link", { name: "model-20261004T090000Z.json" }),
    ).toBeVisible();
    const gates = latest.getByRole("table", {
      name: "Latest complete cohort gate states",
    });
    await expect(gates.getByText("passed", { exact: true })).toHaveCount(3);
    await expect(latest).toContainText("33 / 36 correct");
  });
});

test.describe("qualification", () => {
  test("shows the latest native qualification and earlier runs", async ({
    page,
  }) => {
    await page.goto("/qualification");
    await expect(
      page.getByRole("heading", { level: 1, name: "Qualification" }),
    ).toBeVisible();
    await expect(
      page.getByRole("link", { name: "openshell-20261005T100000Z.json" }),
    ).toBeVisible();
    const profiles = page.getByRole("table", {
      name: "Qualification checks by sandbox profile",
    });
    await expect(profiles.getByRole("rowheader")).toHaveText([
      "workspace",
      "probe",
    ]);
    await expect(profiles.getByText("not checked")).toHaveCount(0);
    const summary = section(page, "Native boundary qualification");
    await expect(
      summary
        .locator("dt", { hasText: "Model quality" })
        .locator("xpath=following-sibling::dd"),
    ).toHaveText("not checked");

    const earlier = section(page, "Earlier qualification runs");
    await expect(earlier.getByRole("listitem")).toHaveCount(1);
    await expect(earlier).toContainText("openshell-20261001T100000Z.json");
    await expect(earlier).toContainText("failed");
    await earlier
      .getByRole("link", { name: "openshell-20261001T100000Z.json" })
      .click();
    const older = page.getByRole("table", {
      name: "Qualification checks by sandbox profile",
    });
    await expect(older.getByRole("row", { name: /workspace/ })).toContainText(
      "failed",
    );
    await expect(older.getByText("not checked")).toHaveCount(3);
  });

  test("with no qualification recorded, native boundaries are not checked", async ({
    page,
    api,
  }) => {
    api.on("GET", /^\/api\/reports$/, {
      body: { items: [], truncated: false },
    });
    await page.goto("/qualification");
    await expect(
      page.getByRole("heading", { name: "No qualification recorded" }),
    ).toBeVisible();
    await expect(
      page.getByText("Native boundaries: not checked."),
    ).toBeVisible();
  });
});
