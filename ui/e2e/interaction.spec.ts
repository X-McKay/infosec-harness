/**
 * Interaction polish: keyboard navigation through the list and detail, copy buttons for
 * identifiers and hashes, filters kept in the URL, and the live-refresh indicator.
 */
import type { Page } from "@playwright/test";
import { expect, test } from "./support/test";

const table = (page: Page) =>
  page.getByRole("table", { name: /Investigations on this page/ });
const rowLink = (page: Page, title: string) =>
  table(page).getByRole("link", { name: title });

test.describe("keyboard", () => {
  test.beforeEach(({}, info) => {
    test.skip(info.project.name === "mobile", "keyboard shortcuts are desktop");
  });

  test("j and k move between rows and Enter opens one", async ({ page }) => {
    await page.goto("/");
    await expect(
      rowLink(page, "Path traversal in static file route"),
    ).toBeVisible();
    await page.getByRole("heading", { level: 1 }).click();
    await page.keyboard.press("j");
    await expect(
      rowLink(page, "Path traversal in static file route"),
    ).toBeFocused();
    await page.keyboard.press("j");
    await expect(rowLink(page, "stored XSS")).toBeFocused();
    await page.keyboard.press("ArrowDown");
    await expect(
      rowLink(page, "XML external entity in invoice import"),
    ).toBeFocused();
    await page.keyboard.press("k");
    await expect(rowLink(page, "stored XSS")).toBeFocused();
    await page.keyboard.press("End");
    await expect(
      rowLink(page, "Server-side request forgery in webhook preview"),
    ).toBeFocused();
    await page.keyboard.press("Home");
    await expect(
      rowLink(page, "Path traversal in static file route"),
    ).toBeFocused();
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/\/runs\/investigate-v11-fixed-0002/);
    await expect(
      page.getByRole("heading", {
        level: 1,
        name: "SQL injection in report search (fixed revision)",
      }),
    ).toBeVisible();
  });

  test("the focused row is highlighted", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("heading", { level: 1 }).click();
    await page.keyboard.press("j");
    const row = table(page).getByRole("row").nth(1);
    await expect
      .poll(() =>
        row.evaluate((element) => getComputedStyle(element).backgroundColor),
      )
      .not.toBe("rgba(0, 0, 0, 0)");
  });

  test("arrow keys leave the page alone until a row has focus, and ArrowDown leaves the search box", async ({
    page,
  }) => {
    await page.goto("/");
    await page.getByRole("heading", { level: 1 }).click();
    await page.keyboard.press("ArrowDown");
    await expect(
      rowLink(page, "Path traversal in static file route"),
    ).not.toBeFocused();
    await page.keyboard.press("/");
    const search = page.getByRole("searchbox", {
      name: "Search investigations",
    });
    await expect(search).toBeFocused();
    // Shortcuts never fire while typing: j and k are text in the box.
    await page.keyboard.type("jk");
    await expect(search).toHaveValue("jk");
    await search.fill("");
    await page.keyboard.press("ArrowDown");
    await expect(
      rowLink(page, "Path traversal in static file route"),
    ).toBeFocused();
  });

  test("on a detail opened from the list, j and k step to its neighbours", async ({
    page,
  }) => {
    await page.goto("/");
    await rowLink(
      page,
      "SQL injection in report search (fixed revision)",
    ).click();
    const nav = page.getByRole("navigation", {
      name: "Investigation navigation",
    });
    await expect(nav).toContainText("Investigation 4 of 6 on this list page");
    await page.keyboard.press("j");
    await expect(page).toHaveURL(/\/runs\/investigate-v11-exploitable-0001/);
    await expect(nav).toContainText("Investigation 5 of 6 on this list page");
    await page.keyboard.press("k");
    await page.keyboard.press("k");
    await expect(page).toHaveURL(/\/runs\/investigate-v11-failed-0004/);
    await expect(nav.getByRole("link", { name: "Next" })).toHaveAttribute(
      "aria-keyshortcuts",
      "j",
    );
  });
});

test.describe("copy buttons", () => {
  test.beforeEach(async ({ context, browserName }) => {
    test.skip(
      browserName !== "chromium",
      "clipboard permissions are Chromium's",
    );
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  });

  const clipboard = (page: Page) =>
    page.evaluate(() => navigator.clipboard.readText());

  test("the run ID copies exactly and says so", async ({ page }) => {
    await page.goto("/runs/investigate-v11-exploitable-0001");
    const button = page.getByRole("button", { name: "Copy run ID" });
    await button.click();
    expect(await clipboard(page)).toBe("investigate-v11-exploitable-0001");
    await expect(
      page.getByRole("status").filter({ hasText: "Copied" }),
    ).toHaveCount(1);
    // The confirmation clears itself.
    await expect(
      page.getByRole("status").filter({ hasText: "Copied" }),
    ).toHaveCount(0, { timeout: 4000 });
  });

  test("evidence, digest and worker identity values copy in full", async ({
    page,
  }) => {
    await page.goto("/runs/investigate-v11-exploitable-0001");
    const probe = page
      .locator("[id^=evidence-]")
      .filter({ has: page.locator("code", { hasText: "probe-cmdi-1" }) });
    await probe.getByRole("button", { name: "Copy evidence ID" }).click();
    expect(await clipboard(page)).toBe("probe-cmdi-1");
    const identity = page.locator("div.rounded-lg", {
      has: page.getByRole("heading", { name: "Model and worker identity" }),
    });
    await identity
      .getByRole("button", { name: "Copy worker fingerprint" })
      .click();
    expect(await clipboard(page)).toContain("wkr-5d6e7f80");
  });

  test("a shortened commit hash copies the full recorded value", async ({
    page,
  }) => {
    await page.goto("/reports/model-20261005T090000Z.json");
    const provenance = page.locator("div.rounded-lg", {
      has: page.getByRole("heading", { name: "Provenance" }),
    });
    await expect(provenance).not.toContainText(
      "741eb852fc9630da741eb852fc9630da741eb852",
    );
    await provenance.getByRole("button", { name: "Copy commit" }).click();
    expect(await clipboard(page)).toBe(
      "741eb852fc9630da741eb852fc9630da741eb852",
    );
  });

  test("copy buttons are named and never carry the copied value", async ({
    page,
  }) => {
    await page.goto("/runs/investigate-v11-untrusted-0005");
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    const labels = await page
      .getByRole("button", { name: /^Copy / })
      .evaluateAll((buttons) =>
        buttons.map((button) => button.getAttribute("aria-label")),
      );
    expect(labels.length).toBeGreaterThan(0);
    for (const label of labels) expect(label).toMatch(/^Copy [A-Za-z0-9 -]+$/);
  });
});

test.describe("filters in the URL", () => {
  test("a multi-word search keeps its spaces while typing", async ({
    page,
  }) => {
    await page.goto("/");
    const search = page.getByRole("searchbox", {
      name: "Search investigations",
    });
    await search.pressSequentially("SQL injection");
    await expect(search).toHaveValue("SQL injection");
    await expect(page).toHaveURL(/[?&]q=SQL(\+|%20)injection/);
    await expect(
      table(page)
        .getByRole("row")
        .filter({ has: page.getByRole("cell") }),
    ).toHaveCount(1);
  });

  test("the report-kind filter is kept in the URL", async ({ page }) => {
    await page.goto("/reports");
    const filters = page.getByRole("group", { name: "Filter by report kind" });
    await filters.getByRole("button", { name: /^qualification/ }).click();
    await expect(page).toHaveURL(/[?&]kind=openshell/);
    await page.reload();
    await expect(
      filters.getByRole("button", { name: /^qualification/ }),
    ).toHaveAttribute("aria-pressed", "true");
    await page.goto("/reports?kind=not-a-kind");
    await expect(filters.getByRole("button", { name: /^All/ })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
  });

  test("case-table filters survive a reload", async ({ page }) => {
    await page.goto("/reports/model-20261005T090000Z.json");
    const cases = page.locator("div.rounded-lg", {
      has: page.getByRole("heading", { name: "Cases", exact: true }),
    });
    await cases
      .getByRole("combobox", { name: "Outcome" })
      .selectOption({ label: "Unsafe negative" });
    await expect(page).toHaveURL(/[?&]outcome=unsafe_negative/);
    await cases
      .getByRole("textbox", { name: "Filter cases" })
      .fill("java sqli");
    await expect(
      cases.getByRole("textbox", { name: "Filter cases" }),
    ).toHaveValue("java sqli");
    await page.reload();
    await expect(cases.getByRole("combobox", { name: "Outcome" })).toHaveValue(
      "unsafe_negative",
    );
    await expect(
      cases.getByRole("textbox", { name: "Filter cases" }),
    ).toHaveValue("java sqli");
  });
});

test.describe("live indicator", () => {
  test("auto-refreshing views say so and finished ones do not", async ({
    page,
  }) => {
    await page.goto("/");
    await expect(page.getByText("Live", { exact: true })).toBeVisible();
    await expect(page.getByText("· every 5 s")).toBeVisible();

    await page.goto("/runs/investigate-v11-running-0003");
    await expect(page.getByText("· every 3 s")).toBeVisible();

    await page.goto("/runs/investigate-v11-exploitable-0001");
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await expect(page.getByText("Live", { exact: true })).toHaveCount(0);
    await expect(page.getByText(/^Updated /)).toBeVisible();
  });

  test("a failing refresh is shown as retrying with the last known data", async ({
    page,
    api,
  }) => {
    await page.goto("/");
    await expect(page.getByText("Live", { exact: true })).toBeVisible();
    api.on("GET", /^\/api\/runs$/, {
      status: 503,
      body: { detail: "Workflow service unavailable" },
    });
    // The next 5 s refresh fails, is retried once, and then the view says so.
    await expect(page.getByText("Retrying", { exact: true })).toBeVisible({
      timeout: 15_000,
    });
    await expect(
      page.getByText("Refresh failed · showing last known data"),
    ).toBeVisible();
  });
});

test("unrecognised filter values in the URL are ignored, not applied", async ({
  page,
}) => {
  await page.goto("/?status=bogus&verdict=nope&q=");
  await expect(
    table(page)
      .getByRole("row")
      .filter({ has: page.getByRole("cell") }),
  ).toHaveCount(6);
  await expect(page.getByText("6 on this page")).toBeVisible();
  await expect(page.getByRole("button", { name: "Clear filters" })).toHaveCount(
    0,
  );
});
