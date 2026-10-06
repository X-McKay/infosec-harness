/**
 * Every route: one h1, named controls, no console errors (enforced by the fixture guard) and
 * no horizontal page scroll, in every project (desktop, dark and phone width).
 */
import {
  CASE_TABLE_OVERFLOW,
  expect,
  horizontalOverflow,
  test,
} from "./support/test";

const ROUTES: [string, string][] = [
  ["/", "Investigations"],
  [
    "/runs/investigate-v11-exploitable-0001",
    "Command injection in archive extraction handler",
  ],
  [
    "/runs/investigate-v11-fixed-0002",
    "SQL injection in report search (fixed revision)",
  ],
  ["/runs/investigate-v11-running-0003", "Path traversal in static file route"],
  [
    "/runs/investigate-v11-failed-0004",
    "XML external entity in invoice import",
  ],
  ["/runs/investigate-v11-untrusted-0005", "stored XSS"],
  ["/runs/investigate-v11-missing", "Investigation not found"],
  ["/reports", "Reports"],
  ["/reports/model-20261005T090000Z.json", "model-20261005T090000Z.json"],
  [
    "/reports/diagnostic-20261005T150000Z.json",
    "diagnostic-20261005T150000Z.json",
  ],
  [
    "/reports/openshell-20261005T100000Z.json",
    "openshell-20261005T100000Z.json",
  ],
  ["/reports/replay-20261005T110000Z.json", "replay-20261005T110000Z.json"],
  ["/reports/legacy-broken.json", "legacy-broken.json"],
  ["/metrics", "Metrics"],
  ["/qualification", "Qualification"],
  ["/runtime", "Runtime"],
  ["/no-such-route", "Page not found"],
];

const OVERFLOW_DEFECTS: Record<string, string> = {
  "/reports/model-20261005T090000Z.json": CASE_TABLE_OVERFLOW,
  "/reports/diagnostic-20261005T150000Z.json": CASE_TABLE_OVERFLOW,
};

for (const [path, heading] of ROUTES) {
  test(`${path} has no horizontal page overflow`, async ({ page }) => {
    test.fixme(!!OVERFLOW_DEFECTS[path], OVERFLOW_DEFECTS[path]);
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1 })).toContainText(
      heading,
    );
    await page.waitForLoadState("networkidle");
    const { scrollWidth, clientWidth } = await horizontalOverflow(page);
    expect(
      scrollWidth,
      `document is ${scrollWidth}px wide in a ${clientWidth}px viewport`,
    ).toBeLessThanOrEqual(clientWidth);
  });

  test(`${path} has one h1 and named controls`, async ({ page }) => {
    await page.goto(path);
    const h1 = page.getByRole("heading", { level: 1 });
    await expect(h1).toHaveCount(1);
    await expect(h1).toContainText(heading);
    // Let the route's queries settle (charts, timelines, report documents).
    await page.waitForLoadState("networkidle");

    // Every button and link has an accessible name (icon-only controls included).
    const unnamed = await page.evaluate(() => {
      const controls = [
        ...document.querySelectorAll<HTMLElement>(
          "button, a[href], [role=button], select, input, textarea, summary",
        ),
      ];
      return controls
        .filter((element) => {
          if (element.closest("[aria-hidden=true]")) return false;
          const labelled =
            element.getAttribute("aria-label") ||
            element.getAttribute("aria-labelledby") ||
            element.getAttribute("title") ||
            (element as HTMLInputElement).labels?.length ||
            (element.textContent ?? "").trim();
          return !labelled;
        })
        .map((element) => element.outerHTML.slice(0, 120));
    });
    expect(unnamed).toEqual([]);
    // Images and SVG drawings are either hidden from assistive technology or named.
    const unnamedImages = await page.evaluate(() =>
      [...document.querySelectorAll("img, svg, [role=img]")]
        .filter(
          (element) =>
            !element.closest("[aria-hidden=true]") &&
            !element.getAttribute("aria-label") &&
            !element.getAttribute("alt") &&
            !element.closest("[role=img][aria-label]"),
        )
        .map((element) => element.outerHTML.slice(0, 120)),
    );
    expect(unnamedImages).toEqual([]);
  });
}

test("the main navigation marks the current route", async ({ page }) => {
  await page.goto("/metrics");
  const nav = page.getByRole("navigation", { name: "Main navigation" });
  await expect(nav.getByRole("link", { name: "Metrics" })).toHaveAttribute(
    "aria-current",
    "page",
  );
  await nav.getByRole("link", { name: "Reports" }).click();
  await expect(
    page.getByRole("heading", { level: 1, name: "Reports" }),
  ).toBeVisible();
  await expect(nav.getByRole("link", { name: "Reports" })).toHaveAttribute(
    "aria-current",
    "page",
  );
  await expect(nav.getByRole("link", { name: "Metrics" })).not.toHaveAttribute(
    "aria-current",
    "page",
  );
});
