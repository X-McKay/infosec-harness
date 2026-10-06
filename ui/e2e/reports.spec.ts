import type { Locator, Page } from "@playwright/test";
import { expect, pwned, test } from "./support/test";

const FAILED_COHORT = "model-20261005T090000Z.json";
const PASSED_COHORT = "model-20261004T090000Z.json";
const RUNNING_COHORT = "model-20261006T080000Z.json";
const DIAGNOSTIC = "diagnostic-20261005T150000Z.json";
const QUALIFICATION = "openshell-20261005T100000Z.json";
const REPLAY = "replay-20261005T110000Z.json";
const UNREADABLE = "legacy-broken.json";

/** A Section card by its title. */
const section = (page: Page, title: string): Locator =>
  page.locator("div.rounded-lg", {
    has: page.getByRole("heading", { name: title, exact: true }),
  });

/** Opens a report from the list, as a user would. */
async function openReport(page: Page, name: string) {
  await page.goto("/reports");
  await page.getByRole("link", { name, exact: true }).click();
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
}

test.describe("reports list", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/reports");
    await expect(
      page.getByRole("heading", { level: 1, name: "Reports" }),
    ).toBeVisible();
  });

  const table = (page: Page) =>
    page.getByRole("table", { name: "Recorded reports, newest first" });
  const row = (page: Page, name: string) =>
    table(page)
      .getByRole("row")
      .filter({
        has: page.getByRole("rowheader", {
          name: new RegExp(name.replaceAll(".", "\\.")),
        }),
      });

  test("lists every report newest first with its kind", async ({ page }) => {
    await expect(table(page).getByRole("rowheader")).toHaveCount(8);
    await expect(table(page).getByRole("rowheader").first()).toContainText(
      RUNNING_COHORT,
    );
    await expect(table(page).getByRole("rowheader").last()).toContainText(
      UNREADABLE,
    );
    await expect(row(page, FAILED_COHORT)).toContainText("cohort");
    await expect(row(page, DIAGNOSTIC)).toContainText("diagnostic");
    await expect(row(page, QUALIFICATION)).toContainText("qualification");
    await expect(row(page, REPLAY)).toContainText("replay");
    await expect(row(page, UNREADABLE)).toContainText("unknown");
    await expect(row(page, UNREADABLE)).toContainText("unreadable");
    // Qualification and replay record no times; the file write time is shown instead.
    await expect(row(page, REPLAY)).toContainText("file written");
  });

  test("shows success rate, unsafe negatives and completion", async ({
    page,
  }) => {
    await expect(row(page, FAILED_COHORT)).toContainText("28 / 36");
    await expect(row(page, FAILED_COHORT)).toContainText("66.7%");
    await expect(row(page, PASSED_COHORT)).toContainText("36 / 36");
    await expect(row(page, PASSED_COHORT)).toContainText("91.7%");
    await expect(row(page, DIAGNOSTIC)).toContainText("100.0%");
    // A running cohort has recorded no rate yet: shown as a dash, never 0%.
    await expect(row(page, RUNNING_COHORT)).not.toContainText("%");
  });

  test("gates that were not checked never look like passed gates", async ({
    page,
  }) => {
    const passed = row(page, PASSED_COHORT).getByText("success · passed");
    const notChecked = row(page, FAILED_COHORT).getByText(
      "success · not checked",
    );
    const failed = row(page, FAILED_COHORT).getByText("corpus · failed");
    await expect(passed).toBeVisible();
    await expect(notChecked).toBeVisible();
    await expect(failed).toBeVisible();
    await expect(row(page, RUNNING_COHORT).getByText(/· passed/)).toHaveCount(
      0,
    );
    const style = (locator: Locator) =>
      locator.evaluate((node) => {
        const computed = getComputedStyle(node);
        return {
          color: computed.color,
          border: computed.borderStyle,
          borderColor: computed.borderColor,
        };
      });
    // Gate states are outlined badges (never the filled verdict pills): a pass has a solid
    // coloured outline, not checked a dashed neutral one with different text colour.
    const passedStyle = await style(passed);
    const notCheckedStyle = await style(notChecked);
    expect(passedStyle.border).toBe("solid");
    expect(notCheckedStyle.border).toBe("dashed");
    expect(notCheckedStyle.borderColor).not.toBe(passedStyle.borderColor);
    expect(notCheckedStyle.color).not.toBe(passedStyle.color);
  });

  test("kind filter narrows the list", async ({ page }) => {
    const filters = page.getByRole("group", { name: "Filter by report kind" });
    await expect(
      filters.getByRole("button", { name: "All · 8" }),
    ).toHaveAttribute("aria-pressed", "true");
    await filters.getByRole("button", { name: "cohort · 3" }).click();
    await expect(table(page).getByRole("rowheader")).toHaveCount(3);
    await filters.getByRole("button", { name: "qualification · 2" }).click();
    await expect(table(page).getByRole("rowheader")).toHaveCount(2);
    await filters.getByRole("button", { name: "All · 8" }).click();
    await expect(table(page).getByRole("rowheader")).toHaveCount(8);
  });
});

test.describe("cohort report detail", () => {
  test.beforeEach(async ({ page }) => {
    await openReport(page, FAILED_COHORT);
    await expect(
      page.getByText("Cohort evaluation", { exact: true }),
    ).toBeVisible();
  });

  test("release gates state their evidence and never pass unchecked gates", async ({
    page,
  }) => {
    const gates = page.getByRole("table", { name: "Release gate states" });
    const gate = (label: string) =>
      gates.getByRole("row", { name: new RegExp(`^${label}`) });
    await expect(gate("Complete corpus")).toContainText("failed");
    await expect(gate("Complete corpus")).toContainText(
      "28 of 36 planned cases completed.",
    );
    await expect(gate("Task success rate")).toContainText("not checked");
    await expect(gate("Task success rate")).toContainText(
      "24 / 36 correct (66.7%); policy minimum 80.0%.",
    );
    await expect(gate("Task success rate")).toContainText(
      "Not evaluated: gates are evaluated only over the complete corpus.",
    );
    await expect(gate("Unsafe negatives")).toContainText("not checked");
    await expect(gate("Unsafe negatives")).toContainText(
      "1 recorded; policy maximum 0.",
    );
    await expect(gates.getByText("passed", { exact: true })).toHaveCount(0);
  });

  test("capacity pre-flight and summary tiles", async ({ page }) => {
    const capacity = section(page, "Capacity pre-flight");
    await expect(capacity).toContainText(
      "2,000 of 20,000 admissions retained; 18,000 free against 4,320 required. Sufficient for the planned cases at one observation.",
    );
    await expect(
      capacity.getByRole("img", {
        name: "2,000 of 20,000 admissions retained; 4,320 required",
      }),
    ).toBeVisible();
    await expect(capacity).toContainText(
      "operator-configured read-only occupancy command",
    );

    const tile = (label: string) =>
      page.locator("div.rounded-lg", {
        has: page.locator("p", { hasText: new RegExp(`^${label}$`) }),
      });
    await expect(tile("Completed")).toContainText("28 / 36");
    await expect(tile("Completed")).toContainText("Incomplete corpus");
    await expect(tile("Correct")).toContainText("24 / 36");
    await expect(tile("Unsafe negatives")).toContainText("Policy maximum 0");
    await expect(tile("Median duration")).toContainText("of 36 cases measured");
  });

  test("charts have accessible data tables", async ({ page }) => {
    for (const title of [
      "Duration per case",
      "Model requests per case",
      "Tokens per case",
      "Native operations per case",
    ]) {
      const card = section(page, title);
      await expect(card.getByRole("img")).toHaveAttribute(
        "aria-label",
        /median .*90th percentile/,
      );
      await card.getByText("View accessible distribution table").click();
      const data = card.getByRole("table", { name: `${title} histogram data` });
      await expect(data).toBeVisible();
      await expect(data.getByRole("row")).not.toHaveCount(0);
    }
    await expect(section(page, "Duration per case")).toContainText(
      "30 of 36 cases measured",
    );
  });

  test("case table sorts and filters", async ({ page }) => {
    const cases = section(page, "Cases");
    const table = cases.getByRole("table", { name: /Cohort cases/ });
    const names = () => table.getByRole("rowheader").allTextContents();
    await expect(cases.getByRole("status")).toHaveText("36 of 36 cases");
    expect((await names())[0]).toBe("cmdi-fixed");

    const nameHeader = table.getByRole("columnheader", { name: /^Case/ });
    await expect(nameHeader).toHaveAttribute("aria-sort", "ascending");
    await nameHeader.getByRole("button").click();
    await expect(nameHeader).toHaveAttribute("aria-sort", "descending");
    expect((await names())[0]).toBe("xxe-vulnerable");

    const duration = table.getByRole("columnheader", { name: /^Duration/ });
    await duration.getByRole("button").click();
    await expect(duration).toHaveAttribute("aria-sort", "ascending");
    // Missing durations (unstarted cases) sort last.
    expect((await names()).slice(-6).sort()).toEqual(
      [
        "javascript-xssesm-fixed",
        "javascript-xssesm-vulnerable",
        "perl-cmdi-fixed",
        "perl-cmdi-vulnerable",
        "perl-xss-fixed",
        "perl-xss-vulnerable",
      ].sort(),
    );

    await cases
      .getByRole("combobox", { name: "Outcome" })
      .selectOption({ label: "Error" });
    await expect(cases.getByRole("status")).toHaveText("2 of 36 cases");
    await cases
      .getByRole("combobox", { name: "Outcome" })
      .selectOption({ label: "Unsafe negative" });
    await expect(cases.getByRole("status")).toHaveText("1 of 36 cases");
    await expect(table.getByRole("rowheader")).toHaveText([
      "java-sqli-vulnerable",
    ]);
    await cases
      .getByRole("combobox", { name: "Outcome" })
      .selectOption({ label: "All" });

    await cases
      .getByRole("combobox", { name: "Language" })
      .selectOption("perl");
    await expect(cases.getByRole("status")).toHaveText("6 of 36 cases");
    await cases.getByRole("combobox", { name: "Language" }).selectOption("");
    await cases
      .getByRole("textbox", { name: "Filter cases" })
      .fill("TimeoutError");
    await expect(cases.getByRole("status")).toHaveText("1 of 36 cases");
    await cases
      .getByRole("textbox", { name: "Filter cases" })
      .fill("no-such-case");
    await expect(
      cases.getByText("No cases match these filters."),
    ).toBeVisible();
  });

  test("case details expand and a case links to its run", async ({ page }) => {
    const table = section(page, "Cases").getByRole("table", {
      name: /Cohort cases/,
    });
    await table
      .getByRole("button", { name: "Show details for sqli-vulnerable" })
      .click();
    await expect(
      table.getByRole("button", { name: "Hide details for sqli-vulnerable" }),
    ).toHaveAttribute("aria-expanded", "true");
    await expect(table).toContainText("Recorded investigation limitations");
    await expect(table).toContainText("Probe claims are self-reported.");

    const unstarted = table.getByRole("row", { name: /perl-xss-fixed/ });
    await expect(unstarted).toContainText("Not started");
    await expect(unstarted.getByRole("link")).toHaveCount(0);

    const link = table.getByRole("link", {
      name: "Open run for sqli-vulnerable",
    });
    const href = await link.getAttribute("href");
    expect(href).toMatch(/^\/runs\/investigate-v11-eval-[0-9a-f]+$/);
    await link.click();
    await expect(page).toHaveURL(new RegExp(`${href}$`));
    // The synthetic API does not know this eval run.
    await expect(
      page.getByRole("heading", { level: 1, name: "Investigation not found" }),
    ).toBeVisible();
  });

  test("failures show the recorded cause chain as text", async ({ page }) => {
    const failures = section(page, "Failures");
    await expect(failures.getByLabel("Failures by class")).toContainText(
      "Agent / model · 1",
    );
    await expect(failures.getByLabel("Failures by class")).toContainText(
      "Timeout · 1",
    );
    const chained = failures
      .getByRole("listitem")
      .filter({ hasText: "perl-sqli-vulnerable" })
      .first();
    await expect(chained).toContainText("WorkflowFailureError");
    await expect(chained).toContainText("caused by ActivityError");
    await expect(chained).toContainText("caused by UsageLimitExceeded");
    await expect(
      chained.getByText(
        "The next request would exceed the request_limit of 40 <script>window.__e2ePwned=20</script>",
      ),
    ).toBeVisible();
    await expect(chained).toContainText(
      "Local receipts: observed · 2 recorded",
    );
    const timeout = failures
      .getByRole("listitem")
      .filter({ hasText: "perl-sqli-fixed" })
      .first();
    await expect(timeout).toContainText("No cause chain was recorded.");
    await expect(timeout).toContainText("cancellation terminal");
    expect(await pwned(page)).toBeNull();
  });

  test("the recorded document is available as a tree", async ({ page }) => {
    const raw = section(page, "Recorded document (raw)");
    await raw.getByText("Show the recorded document").click();
    await expect(raw).toContainText("release_policy_sha256");
  });
});

test("a running cohort is marked unfinished with unchecked gates", async ({
  page,
}) => {
  await openReport(page, RUNNING_COHORT);
  await expect(
    page
      .getByRole("status")
      .filter({ hasText: "This cohort has not finished" }),
  ).toBeVisible();
  const gates = page.getByRole("table", { name: "Release gate states" });
  await expect(gates.getByText("not checked", { exact: true })).toHaveCount(3);
  await expect(gates).toContainText(
    "Not evaluated: the cohort has not finished.",
  );
});

test("diagnostic report detail", async ({ page }) => {
  await openReport(page, DIAGNOSTIC);
  await expect(
    page.getByText("Diagnostic subset", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText(
      "Diagnostic subset: selected cases only. Its gates stay not checked",
    ),
  ).toBeVisible();
  const gates = page.getByRole("table", { name: "Release gate states" });
  await expect(gates.getByText("not checked", { exact: true })).toHaveCount(3);
  await expect(gates).toContainText("A diagnostic subset never qualifies");
  await expect(section(page, "Capacity pre-flight")).toContainText(
    "Not checked: No read-only native occupancy command is configured.",
  );
  await expect(section(page, "Cases").getByRole("status")).toHaveText(
    "2 of 2 cases",
  );
});

test("qualification report detail", async ({ page }) => {
  await openReport(page, QUALIFICATION);
  await expect(
    page.getByText("Native qualification", { exact: true }),
  ).toBeVisible();
  const summary = section(page, "Native boundary qualification");
  await expect(summary).toContainText("qualify-20261005-1000");
  await expect(summary).toContainText("Model calls0");
  await expect(
    summary
      .locator("dt", { hasText: "Model quality" })
      .locator("xpath=following-sibling::dd"),
  ).toHaveText("not checked");
  const profiles = page.getByRole("table", {
    name: "Qualification checks by sandbox profile",
  });
  await expect(profiles.getByRole("rowheader")).toHaveText([
    "workspace",
    "probe",
  ]);
  await expect(profiles.getByRole("columnheader")).toHaveText([
    "Profile",
    "Boundary",
    "Roundtrip",
    "Saved operation",
    "Sandbox reuse",
    "Cleanup",
  ]);
});

test("replay report detail links to the replayed run", async ({ page }) => {
  await openReport(page, REPLAY);
  await expect(
    page.getByText("History replay", { exact: true }).first(),
  ).toBeVisible();
  const histories = page.getByRole("table", {
    name: "Replayed workflow histories",
  });
  await expect(histories).toContainText("None attempted (guarded)");
  await expect(histories).toContainText("42");
  await expect(histories).toContainText("potentially exploitable");
  await histories
    .getByRole("link", { name: "investigate-v11-exploitable-0001" })
    .click();
  await expect(page).toHaveURL(/\/runs\/investigate-v11-exploitable-0001$/);
  await expect(
    page.getByRole("heading", {
      level: 1,
      name: "Command injection in archive extraction handler",
    }),
  ).toBeVisible();
});

test("an unreadable report shows the API's error", async ({ page }) => {
  await openReport(page, UNREADABLE);
  await expect(page.getByRole("alert")).toContainText(
    "422 Report is not a readable JSON object",
    { timeout: 10_000 },
  );
});

test("a report path loads directly", async ({ page }) => {
  await page.goto(`/reports/${PASSED_COHORT}`);
  await expect(
    page.getByRole("heading", { level: 1, name: PASSED_COHORT }),
  ).toBeVisible();
  await expect(
    page
      .getByRole("table", { name: "Release gate states" })
      .getByText("passed", { exact: true }),
  ).toHaveCount(3);
});

test("an invalid report name is not found and never requested", async ({
  page,
  api,
}) => {
  await page.goto("/reports/not-a-report");
  await expect(
    page.getByRole("heading", { level: 1, name: "Page not found" }),
  ).toBeVisible();
  expect(api.calls("GET", /^\/api\/reports\/.+/)).toHaveLength(0);
});
