import type { Page } from "@playwright/test";
import { expect, pwned, test } from "./support/test";

/**
 * Finding text, probe output, model output and event details are untrusted. They must render
 * as literal text: no element is created from them and none becomes a link target.
 */
async function assertInert(page: Page) {
  // Only the app's own module script exists; no recorded markup became an element.
  const scripts = await page.locator("script").evaluateAll((nodes) =>
    nodes.map((node) => (node as HTMLScriptElement).src),
  );
  expect(scripts.every((src) => /\/assets\/index-[\w-]+\.js$/.test(src))).toBe(true);
  await expect(page.locator("img, iframe, object, embed")).toHaveCount(0);
  await expect(page.locator("main b")).toHaveCount(0);
  const hrefs = await page
    .locator("[href]")
    .evaluateAll((nodes) => nodes.map((node) => node.getAttribute("href") ?? ""));
  for (const href of hrefs) {
    expect(href).not.toMatch(/javascript:|__e2ePwned|onerror|<|>/i);
  }
  const srcs = await page
    .locator("[src]")
    .evaluateAll((nodes) => nodes.map((node) => node.getAttribute("src") ?? ""));
  for (const src of srcs) expect(src).not.toMatch(/javascript:|^x$/);
  // No attribute anywhere carries recorded text.
  const attributes = await page.evaluate(() =>
    [...document.querySelectorAll("*")].flatMap((node) =>
      [...node.attributes]
        .filter((attribute) => /__e2ePwned|onerror/.test(attribute.value))
        .map((attribute) => `${node.tagName}[${attribute.name}]`),
    ),
  );
  expect(attributes).toEqual([]);
  expect(await pwned(page)).toBeNull();
}

test("list renders a hostile title as literal text", async ({ page }) => {
  await page.goto("/");
  const link = page.getByRole("link", { name: /stored XSS/ });
  await expect(link).toHaveText(
    '<script>window.__e2ePwned=1</script><img src=x onerror="window.__e2ePwned=2"> stored XSS',
  );
  await expect(page.getByText("javascript:window.__e2ePwned=5", { exact: false })).toBeVisible();
  await assertInert(page);
});

test("detail renders hostile finding, verdict, evidence and events as text", async ({
  page,
}) => {
  await page.goto("/runs/investigate-v11-untrusted-0005");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(
    '<script>window.__e2ePwned=1</script><img src=x onerror="window.__e2ePwned=2"> stored XSS',
  );
  await expect(page.getByRole("region", { name: "Verdict summary" })).toHaveText(
    'Model said: <script>window.__e2ePwned=6</script> and <img src=x onerror="window.__e2ePwned=7">',
  );
  // Citation path stays a table cell, never a link.
  await expect(page.getByRole("cell", { name: "javascript:window.__e2ePwned=9" })).toBeVisible();
  await expect(page.getByRole("link", { name: /e2ePwned/ })).toHaveCount(0);
  await expect(
    page.getByText('<a href="javascript:window.__e2ePwned=15">click me</a> was printed by the probe.'),
  ).toBeVisible();
  // A non-boolean claim is not recorded, never true.
  const observations = page.getByRole("table", { name: /Recorded probe observations/ });
  await expect(
    observations.getByRole("row", { name: /^Vulnerability observed/ }),
  ).toContainText("not recorded");
  await expect(
    page.getByText('<a href="javascript:window.__e2ePwned=14">see</a>'),
  ).toBeVisible();

  // Open every output block so its text is in the DOM.
  for (const summary of await page.locator("summary").all()) await summary.click();
  await expect(page.getByText(/<script>window.__e2ePwned=11<\/script>/)).toBeVisible();
  await expect(
    page.getByText('<iframe src="javascript:window.__e2ePwned=13"></iframe>'),
  ).toBeVisible();
  await expect(page.getByText('<img src=x onerror="window.__e2ePwned=17">')).toBeVisible();
  await expect(page.getByText("<script>window.__e2ePwned=16</script>")).toBeVisible();
  // Evidence card ids come from position, not from the recorded id.
  const ids = await page
    .locator("[id^=evidence-]")
    .evaluateAll((nodes) => nodes.map((node) => node.id));
  expect(ids.filter((id) => id !== "evidence-heading")).toEqual(["evidence-0"]);
  await assertInert(page);
});
