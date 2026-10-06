import { NEW_RUN_ID } from "./support/mock-api";
import { expect, test } from "./support/test";

test.describe("new investigation form", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: "New investigation" }).click();
    await expect(
      page.getByRole("heading", { name: "New investigation" }),
    ).toBeVisible();
  });

  const submit = (page: import("@playwright/test").Page) =>
    page.getByRole("button", { name: "Start investigation" });

  test("required fields block submission and nothing is sent", async ({
    page,
    api,
  }) => {
    const title = page.getByLabel("Finding title");
    const repo = page.getByLabel("Repository URL or approved local path");
    await submit(page).click();
    expect(
      await title.evaluate((input: HTMLInputElement) => input.validity.valueMissing),
    ).toBe(true);
    await title.fill("Only a title");
    await submit(page).click();
    expect(
      await repo.evaluate((input: HTMLInputElement) => input.validity.valueMissing),
    ).toBe(true);
    await page.getByRole("textbox", { name: "Revision", exact: true }).fill("");
    await repo.fill("https://git.example.test/acme/app.git");
    await submit(page).click();
    expect(
      await page
        .getByRole("textbox", { name: "Revision", exact: true })
        .evaluate((input: HTMLInputElement) => input.validity.valueMissing),
    ).toBe(true);
    expect(await title.getAttribute("maxlength")).toBe("1000");
    expect(api.calls("POST", "/api/runs")).toHaveLength(0);
  });

  test("submits a trimmed finding, omits blank optional fields and opens the run", async ({
    page,
    api,
  }) => {
    await page.getByLabel("Finding title").fill("  Reflected XSS in search  ");
    await page
      .getByLabel("Repository URL or approved local path")
      .fill(" https://git.example.test/acme/app.git ");
    await expect(page.getByRole("textbox", { name: "Revision", exact: true })).toHaveValue("HEAD");
    await page.getByRole("combobox", { name: /^Source/ }).selectOption("working_snapshot");
    await page.getByLabel("CWE (optional)").fill(" CWE-79 ");
    await page.getByLabel("Finding description").fill("The q parameter is echoed.");
    await submit(page).click();

    await expect(page).toHaveURL(new RegExp(`/runs/${NEW_RUN_ID}`));
    const posts = api.calls("POST", "/api/runs");
    expect(posts).toHaveLength(1);
    expect(posts[0].body).toEqual({
      title: "Reflected XSS in search",
      repo_url: "https://git.example.test/acme/app.git",
      revision: "HEAD",
      source_mode: "working_snapshot",
      description: "The q parameter is echoed.",
      cwe: "CWE-79",
    });
    await expect(
      page.getByRole("heading", { level: 1, name: "Reflected XSS in search" }),
    ).toBeVisible();
    await expect(page.getByRole("heading", { name: "In progress" })).toBeVisible();
  });

  test("an API validation error is shown and the form stays open", async ({
    page,
    api,
  }) => {
    api.on("POST", /^\/api\/runs$/, {
      status: 422,
      body: {
        detail: [{ loc: ["body", "repo_url"], msg: "repository is not approved", type: "value_error" }],
      },
    });
    await page.getByLabel("Finding title").fill("Rejected finding");
    await page
      .getByLabel("Repository URL or approved local path")
      .fill("/not/approved");
    await submit(page).click();
    await expect(page.getByRole("alert")).toHaveText("422 repository is not approved");
    await expect(page).toHaveURL(/\/$/);
    await expect(submit(page)).toBeEnabled();
  });

  test("Close hides the form without sending anything", async ({ page, api }) => {
    await page.getByLabel("Finding title").fill("Draft");
    await page.getByRole("button", { name: "Close" }).click();
    await expect(page.getByLabel("Finding title")).toHaveCount(0);
    await expect(page.getByRole("button", { name: "New investigation" })).toBeVisible();
    expect(api.calls("POST", "/api/runs")).toHaveLength(0);
  });
});
