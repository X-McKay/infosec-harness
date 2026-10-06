import { expect, test } from "./support/test";

const PAGE_ONE = [
  "Path traversal in static file route",
  "stored XSS",
  "XML external entity in invoice import",
  "SQL injection in report search (fixed revision)",
  "Command injection in archive extraction handler",
  "Server-side request forgery in webhook preview",
];

test.describe("investigations list", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await expect(
      page.getByRole("heading", { level: 1, name: "Investigations" }),
    ).toBeVisible();
  });

  const table = (page: import("@playwright/test").Page) =>
    page.getByRole("table", { name: /Investigations on this page/ });
  const bodyRows = (page: import("@playwright/test").Page) =>
    table(page).getByRole("row").filter({ has: page.getByRole("cell") });

  test("lists every run on the first page with status, verdict and elapsed time", async ({
    page,
  }) => {
    await expect(bodyRows(page)).toHaveCount(PAGE_ONE.length);
    for (const title of PAGE_ONE)
      await expect(table(page)).toContainText(title);
    await expect(page.getByText("6 on this page")).toBeVisible();

    const running = bodyRows(page).filter({ hasText: "Path traversal" });
    await expect(running).toContainText("running");
    // Frozen clock: 11:55 start, 12:00 now.
    await expect(running).toContainText("5m 0s");
    await expect(running).toContainText("CWE-22");

    const exploitable = bodyRows(page).filter({ hasText: "Command injection" });
    await expect(exploitable).toContainText("completed");
    await expect(exploitable).toContainText("potentially exploitable");
    await expect(exploitable).toContainText("9m 45s");
    await expect(exploitable).toContainText("10/5/2026, 7:00:00 AM");

    const cancelled = bodyRows(page).filter({ hasText: "Server-side request" });
    await expect(cancelled).toContainText("cancelled");
  });

  test("status tiles count the page and filter it", async ({ page }) => {
    const tiles = page.getByRole("group", { name: "Status filter" });
    const tile = (name: string) =>
      tiles.getByRole("button", { name: new RegExp(`^${name}`) });
    await expect(tile("Active")).toHaveText(/Active\s*1/);
    await expect(tile("Completed")).toHaveText(/Completed\s*3/);
    await expect(tile("Failed")).toHaveText(/Failed\s*1/);
    await expect(tile("Cancelled")).toHaveText(/Cancelled\s*1/);

    await tile("Failed").click();
    await expect(tile("Failed")).toHaveAttribute("aria-pressed", "true");
    await expect(page).toHaveURL(/[?&]status=failed/);
    await expect(bodyRows(page)).toHaveCount(1);
    await expect(table(page)).toContainText("XML external entity");
    await expect(
      page.getByText("1 of 6 on this page match · filters apply to the loaded page"),
    ).toBeVisible();

    await tile("Failed").click();
    await expect(tile("Failed")).toHaveAttribute("aria-pressed", "false");
    await expect(bodyRows(page)).toHaveCount(PAGE_ONE.length);
  });

  test("search matches title, id, CWE and repository", async ({ page }) => {
    const search = page.getByRole("searchbox", { name: "Search investigations" });
    await search.fill("CWE-89");
    await expect(page).toHaveURL(/[?&]q=CWE-89/);
    await expect(bodyRows(page)).toHaveCount(1);
    await expect(table(page)).toContainText("SQL injection in report search");

    await search.fill("acme/billing");
    await expect(bodyRows(page)).toHaveCount(1);
    await expect(table(page)).toContainText("XML external entity");

    await search.fill("no such investigation");
    await expect(
      page.getByText("No investigations on this page match these filters."),
    ).toBeVisible();
    await page.getByRole("button", { name: "Clear filters" }).first().click();
    await expect(search).toHaveValue("");
    await expect(bodyRows(page)).toHaveCount(PAGE_ONE.length);
  });

  test("the / key focuses the search box", async ({ page }) => {
    await page.getByRole("heading", { level: 1 }).click();
    await page.keyboard.press("/");
    await expect(
      page.getByRole("searchbox", { name: "Search investigations" }),
    ).toBeFocused();
  });

  test("verdict filter keeps only matching verdicts", async ({ page }) => {
    const verdicts = page.getByRole("group", { name: "Verdict filter" });
    await verdicts.getByRole("button", { name: "potentially exploitable" }).click();
    await expect(page).toHaveURL(/[?&]verdict=potentially_exploitable/);
    await expect(
      verdicts.getByRole("button", { name: "potentially exploitable" }),
    ).toHaveAttribute("aria-pressed", "true");
    await expect(bodyRows(page)).toHaveCount(1);
    await expect(table(page)).toContainText("Command injection");

    await verdicts.getByRole("button", { name: "likely not exploitable" }).click();
    await expect(bodyRows(page)).toHaveCount(1);
    await expect(table(page)).toContainText("SQL injection");

    await verdicts.getByRole("button", { name: "All verdicts" }).click();
    await expect(bodyRows(page)).toHaveCount(PAGE_ONE.length);
  });

  test("Next and Previous page through the API's page tokens", async ({
    page,
    api,
  }) => {
    const previous = page.getByRole("button", { name: "Previous", exact: true });
    const next = page.getByRole("button", { name: "Next", exact: true });
    await expect(previous).toBeDisabled();
    await next.click();
    await expect(page).toHaveURL(/[?&]page=tok-page-2/);
    await expect(bodyRows(page)).toHaveCount(2);
    await expect(table(page)).toContainText("Deserialization of session cookie");
    // terminated is grouped with failed
    await expect(
      page
        .getByRole("group", { name: "Status filter" })
        .getByRole("button", { name: /^Failed/ }),
    ).toHaveText(/Failed\s*1/);
    await expect(next).toBeDisabled();
    expect(
      api.calls("GET", "/api/runs").some((call) => call.search === "?page_token=tok-page-2"),
    ).toBe(true);

    await previous.click();
    await expect(bodyRows(page)).toHaveCount(PAGE_ONE.length);
    await expect(page).not.toHaveURL(/page=/);
  });

  test("a row opens its investigation and the detail steps through the page", async ({
    page,
  }) => {
    await bodyRows(page).filter({ hasText: "SQL injection" }).getByRole("link").click();
    await expect(page).toHaveURL(/\/runs\/investigate-v11-fixed-0002/);
    await expect(
      page.getByRole("heading", {
        level: 1,
        name: "SQL injection in report search (fixed revision)",
      }),
    ).toBeVisible();
    const nav = page.getByRole("navigation", { name: "Investigation navigation" });
    await expect(nav).toContainText("Investigation 4 of 6 on this list page");
    await nav.getByRole("link", { name: "Next" }).click();
    await expect(page).toHaveURL(/\/runs\/investigate-v11-exploitable-0001/);
    await page.getByRole("link", { name: "Back to investigations" }).click();
    await expect(page).toHaveURL(/\/$|\/\?/);
    await expect(bodyRows(page)).toHaveCount(PAGE_ONE.length);
  });

  test("an API failure shows an error with a retry", async ({ page, api }) => {
    api.on("GET", /^\/api\/runs$/, { status: 503, body: { detail: "Workflow service unavailable" } });
    await page.reload();
    const alert = page.getByRole("alert");
    await expect(alert).toContainText("503 Workflow service unavailable", { timeout: 10_000 });
    await expect(alert.getByRole("button", { name: "Try again" })).toBeVisible();
  });
});
