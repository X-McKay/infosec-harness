/**
 * The application shell at both widths: the fixed sidebar from 768px, and below that a compact
 * header whose navigation is one horizontally scrolling row. The investigations list keeps its
 * essential columns at phone width without scrolling sideways.
 */
import { expect, horizontalOverflow, test } from "./support/test";

const PHONE_HEADER_MAX = 140; // px; the stacked sidebar it replaces took about 300px

test.describe("phone shell", () => {
  test.beforeEach(({}, info) => {
    test.skip(info.project.name !== "mobile", "phone layout only");
  });

  test("the header is compact and the navigation is one scrolling row", async ({
    page,
  }) => {
    await page.goto("/");
    await expect(
      page.getByRole("heading", { level: 1, name: "Investigations" }),
    ).toBeVisible();
    const header = page.locator("aside");
    const box = await header.boundingBox();
    expect(box?.height).toBeLessThanOrEqual(PHONE_HEADER_MAX);

    const nav = page.getByRole("navigation", { name: "Main navigation" });
    const tops = await nav
      .getByRole("link")
      .evaluateAll((links) =>
        links.map((link) => Math.round(link.getBoundingClientRect().top)),
      );
    expect(tops).toHaveLength(5);
    expect(new Set(tops).size, "every link on one row").toBe(1);
    // The row scrolls inside itself; the page never does.
    const { scrollWidth, clientWidth } = await horizontalOverflow(page);
    expect(scrollWidth).toBeLessThanOrEqual(clientWidth);
    await expect(
      page.getByRole("combobox", { name: "Appearance" }),
    ).toBeVisible();
  });

  test("the current route's link is scrolled into the navigation row", async ({
    page,
  }) => {
    await page.goto("/runtime");
    const nav = page.getByRole("navigation", { name: "Main navigation" });
    const current = nav.getByRole("link", { name: "Runtime" });
    await expect(current).toHaveAttribute("aria-current", "page");
    const navBox = await nav.boundingBox();
    const linkBox = await current.boundingBox();
    expect(navBox && linkBox).toBeTruthy();
    expect(linkBox!.x).toBeGreaterThanOrEqual(navBox!.x);
    expect(linkBox!.x + linkBox!.width).toBeLessThanOrEqual(
      navBox!.x + navBox!.width + 1,
    );
    // Following a link from the row keeps the page at the top.
    await nav.getByRole("link", { name: "Investigations" }).click();
    await expect(
      page.getByRole("heading", { level: 1, name: "Investigations" }),
    ).toBeInViewport();
  });

  test("runtime details open from the summary line", async ({ page }) => {
    await page.goto("/");
    const status = page
      .getByRole("status")
      .filter({ hasText: "Native runtime" });
    await expect(status.getByText("control plane ready")).toBeVisible();
    await expect(status.getByText("Native runtime: not checked")).toBeHidden();
    const toggle = page.getByRole("button", { name: "Runtime details" });
    await expect(toggle).toHaveAttribute("aria-expanded", "false");
    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-expanded", "true");
    await expect(status.getByText("Native runtime: not checked")).toBeVisible();
    await expect(status.getByText("Temporal: reachable")).toBeVisible();
  });

  test("the list keeps title, status, verdict and elapsed time without sideways scroll", async ({
    page,
  }) => {
    await page.goto("/");
    const table = page.getByRole("table", {
      name: /Investigations on this page/,
    });
    await expect(table.getByRole("columnheader")).toHaveText([
      "Investigation",
      "Elapsed",
    ]);
    const row = table
      .getByRole("row")
      .filter({ hasText: "Command injection in archive extraction handler" });
    // Each appears once on screen (the desktop-only cells are hidden, not duplicated).
    for (const text of ["completed", "potentially exploitable"])
      await expect(
        row.getByText(text, { exact: true }).filter({ visible: true }),
      ).toHaveCount(1);
    await expect(row.getByText("9m 45s")).toBeVisible();
    // The table fits its card: no horizontal scroll inside the wrapper either.
    const fits = await table.evaluate((element) => {
      const wrapper = element.parentElement!;
      return wrapper.scrollWidth <= wrapper.clientWidth;
    });
    expect(fits).toBe(true);
  });
});

test.describe("desktop shell", () => {
  test.beforeEach(({}, info) => {
    test.skip(info.project.name === "mobile", "sidebar layout only");
  });

  test("the sidebar holds the full runtime summary and a vertical navigation", async ({
    page,
  }) => {
    await page.goto("/");
    const sidebar = page.locator("aside");
    const box = await sidebar.boundingBox();
    expect(box?.width).toBe(224);
    await expect(
      page.getByRole("button", { name: "Runtime details" }),
    ).toBeHidden();
    await expect(
      sidebar.getByText("Native runtime: not checked"),
    ).toBeVisible();
    const lefts = await page
      .getByRole("navigation", { name: "Main navigation" })
      .getByRole("link")
      .evaluateAll((links) =>
        links.map((link) => Math.round(link.getBoundingClientRect().left)),
      );
    expect(new Set(lefts).size, "links stacked in one column").toBe(1);
    const table = page.getByRole("table", {
      name: /Investigations on this page/,
    });
    await expect(table.getByRole("columnheader")).toHaveText([
      "Status",
      "Verdict",
      "Investigation",
      "Started",
      "Elapsed",
    ]);
  });
});
