/**
 * WCAG AA text contrast (4.5:1, 3:1 for large text) on every route, in the light (desktop)
 * and dark projects, including badges, callouts and chart labels. See support/contrast.ts.
 */
import { contrastProblems } from "./support/contrast";
import { expect, test } from "./support/test";

const ROUTES = [
  "/",
  "/runs/investigate-v11-exploitable-0001",
  "/runs/investigate-v11-fixed-0002",
  "/runs/investigate-v11-running-0003",
  "/runs/investigate-v11-failed-0004",
  "/reports",
  "/reports/model-20261005T090000Z.json",
  "/reports/model-20261006T080000Z.json",
  "/reports/diagnostic-20261005T150000Z.json",
  "/reports/openshell-20261005T100000Z.json",
  "/reports/replay-20261005T110000Z.json",
  "/metrics",
  "/qualification",
  "/runtime",
];

test.describe("text contrast", () => {
  test.beforeEach(({}, info) => {
    test.skip(info.project.name === "mobile", "colours match the desktop run");
  });

  for (const path of ROUTES)
    test(`${path} meets WCAG AA text contrast`, async ({ page }) => {
      await page.goto(path);
      await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
      await page.waitForLoadState("networkidle");
      // Open every collapsed section so its contents are measured too.
      await page.evaluate(() => {
        for (const details of document.querySelectorAll("details"))
          details.open = true;
      });
      await page.waitForTimeout(200);
      expect(await contrastProblems(page)).toEqual([]);
    });
});
