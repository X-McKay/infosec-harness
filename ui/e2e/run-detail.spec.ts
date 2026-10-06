import type { Locator, Page } from "@playwright/test";
import { expect, test } from "./support/test";

/** The evidence card whose header shows this recorded evidence id. */
const evidenceCard = (page: Page, id: string): Locator =>
  page
    .getByRole("region", { name: "Execution evidence" })
    .locator("[id^=evidence-]")
    .filter({ has: page.locator("code", { hasText: id }) });

test.describe("run detail: potentially exploitable", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/runs/investigate-v11-exploitable-0001");
    await expect(
      page.getByRole("heading", {
        level: 1,
        name: "Command injection in archive extraction handler",
      }),
    ).toBeVisible();
  });

  test("shows status, verdict, its meaning and source citations", async ({
    page,
  }) => {
    await expect(page.getByText("Investigation · finished")).toBeVisible();
    await expect(
      page.getByText("investigate-v11-exploitable-0001", { exact: true }),
    ).toBeVisible();
    const verdict = page.locator("div.rounded-lg", {
      has: page.getByRole("heading", { name: "Verdict", exact: true }),
    });
    await expect(
      verdict.getByText("potentially exploitable", { exact: true }),
    ).toBeVisible();
    await expect(verdict).toContainText("Admitted with source citations");
    await expect(
      page.getByRole("region", { name: "Verdict summary" }),
    ).toContainText("observed the injected marker command");
    const citations = verdict.getByRole("table");
    await expect(citations.getByRole("row")).toHaveCount(3);
    await expect(citations).toContainText("app/handlers/extract.py");
    await expect(citations).toContainText("41–48");
    await expect(citations.getByRole("row").nth(2)).toContainText("12");
    // The probe-claim basis note
    await expect(page.getByRole("note")).toContainText(
      "recorded origin: self reported",
    );
  });

  test("cited, uncited evidence and the probe observation table", async ({
    page,
  }) => {
    const cited = page
      .getByRole("listitem")
      .filter({ hasText: "probe-cmdi-1" });
    await expect(cited).toContainText(
      "vulnerability observed (self-reported): true",
    );
    await expect(cited).toContainText("complete, source-verified");

    const probe = evidenceCard(page, "probe-cmdi-1");
    await expect(probe.getByText("cited", { exact: true })).toBeVisible();
    await expect(probe.getByText("not cited", { exact: true })).toHaveCount(0);
    await expect(probe.getByText("exit 0", { exact: true })).toBeVisible();
    await expect(probe).toContainText(
      "Recorded values meet the complete, source-verified probe rule",
    );
    const observations = probe.getByRole("table", {
      name: "Recorded probe observations for probe-cmdi-1",
    });
    for (const claim of [
      "Target reached",
      "Oracle valid",
      "Positive control",
      "Negative control",
      "Vulnerability observed",
      "Source verified",
    ]) {
      const row = observations.getByRole("row", {
        name: new RegExp(`^${claim}`),
      });
      await expect(row.getByRole("cell").first()).toHaveText("true");
    }
    await expect(
      observations.getByRole("row", { name: /^Target reached/ }),
    ).toContainText("Probe output (self reported)");
    await expect(
      observations.getByRole("row", { name: /^Workspace digest/ }),
    ).toContainText("sha256:aa11bb22");
    await expect(probe.getByText("Final probe line")).toBeVisible();

    const command = evidenceCard(page, "cmd-grep-1");
    await expect(command.getByText("not cited", { exact: true })).toBeVisible();
    await expect(
      command.getByText("output truncated", { exact: true }),
    ).toBeVisible();
    await expect(command.getByRole("table")).toHaveCount(0);

    // Selecting a cited id moves focus to its card.
    await page.getByRole("button", { name: "probe-cmdi-1" }).click();
    await expect(probe).toBeFocused();
  });

  test("stdout is collapsed until opened and then shown as text", async ({
    page,
  }) => {
    const probe = evidenceCard(page, "probe-cmdi-1");
    const summary = probe.locator("summary", { hasText: "stdout" });
    await expect(summary).toContainText(/\d+ lines · 206 characters/);
    await expect(
      probe.getByText("positive control: marker written"),
    ).toHaveCount(0);
    await summary.click();
    await expect(
      probe.getByText(/positive control: marker written/),
    ).toBeVisible();
    await expect(probe).toContainText("stderr: no output recorded");
    await summary.click();
    await expect(
      probe.getByText("positive control: marker written"),
    ).toHaveCount(0);
  });

  test("the stdout summary counts newline-terminated output's lines", async ({
    page,
  }) => {
    const probe = evidenceCard(page, "probe-cmdi-1");
    await expect(probe.locator("summary", { hasText: "stdout" })).toContainText(
      "3 lines",
    );
  });

  test("limitations, model identity and usage", async ({ page }) => {
    const limitations = page.locator("div.rounded-lg", {
      has: page.getByRole("heading", { name: "Limitations" }),
    });
    await expect(limitations.getByRole("listitem")).toHaveText([
      "Target binding and oracle semantics are self-reported by the probe.",
      "Only the extract endpoint was exercised; other callers of run_shell were not tested.",
    ]);
    const identity = page.locator("div.rounded-lg", {
      has: page.getByRole("heading", { name: "Model and worker identity" }),
    });
    await expect(identity).toContainText("example-model-2026-09");
    await expect(identity).toContainText("wkr-5d6e7f80");
    await identity.getByText("Dependencies (2)").click();
    await expect(
      identity.getByRole("cell", { name: "temporalio" }),
    ).toBeVisible();

    const usage = page.locator("div.rounded-lg", {
      has: page.getByRole("heading", { name: "Usage", exact: true }),
    });
    // Well-known counters first, in a fixed order.
    await expect(usage.getByRole("rowheader")).toHaveText([
      "requests",
      "tool calls",
      "input tokens",
      "output tokens",
    ]);
    await expect(
      usage.getByRole("row", { name: /input tokens/ }),
    ).toContainText("51,200");
  });

  test("timeline lists events and says when the API truncated it", async ({
    page,
  }) => {
    const timeline = page.locator("div.rounded-lg", {
      has: page.getByRole("heading", { name: "Event timeline" }),
    });
    await expect(timeline.getByRole("listitem")).toHaveCount(6);
    await expect(timeline).toContainText(
      "6 of 7 events · 1 workflow-task and activity-start events hidden",
    );
    await expect(timeline.getByRole("listitem").first()).toContainText(
      "InvestigationWorkflow",
    );
    await expect(timeline.getByRole("listitem").first()).toContainText(
      "workflow started",
    );
    await expect(timeline).toContainText("exit 0");
    await expect(timeline).toContainText(
      "The API bounded this timeline; not every recorded event is shown.",
    );
    await timeline.getByRole("button", { name: "Show all events" }).click();
    await expect(timeline.getByRole("listitem")).toHaveCount(7);
    await expect(timeline).toContainText("workflow_task_scheduled");
    await expect(
      timeline.getByRole("button", { name: "Hide bookkeeping" }),
    ).toHaveAttribute("aria-pressed", "true");
    // A terminal run shows no cancel control.
    await expect(
      page.getByRole("button", { name: "Cancel investigation" }),
    ).toHaveCount(0);
  });
});

test("run detail: likely not exploitable with a superseded probe", async ({
  page,
}) => {
  await page.goto("/runs/investigate-v11-fixed-0002");
  await expect(
    page.getByText("likely not exploitable", { exact: true }).first(),
  ).toBeVisible();

  const superseded = evidenceCard(page, "probe-sqli-1");
  await expect(
    superseded.getByText("superseded", { exact: true }),
  ).toBeVisible();
  await expect(superseded.getByText("cited", { exact: true })).toHaveCount(0);
  await expect(superseded).toContainText(
    "The investigator disowned this probe",
  );
  await expect(superseded.getByText("exit 1", { exact: true })).toBeVisible();
  await expect(superseded).toContainText(
    "Not a complete, source-verified probe: exit code 1;",
  );
  await expect(
    superseded
      .getByRole("table")
      .getByRole("row", { name: /^Vulnerability observed/ }),
  ).toContainText("not recorded");

  const cited = evidenceCard(page, "probe-sqli-2");
  await expect(cited.getByText("cited", { exact: true })).toBeVisible();
  await expect(
    cited
      .getByRole("table")
      .getByRole("row", { name: /^Vulnerability observed/ }),
  ).toContainText("false");

  await expect(
    page.getByText(
      "The report recorded no limitations. An absent limitation is not evidence that a check passed.",
    ),
  ).toBeVisible();
  await expect(
    page.getByText("Worker identity", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Not recorded", { exact: true })).toBeVisible();
  await expect(page.getByText("The API bounded this timeline")).toHaveCount(0);
});

test("run detail: a failed run shows its error and hides a missing timeline", async ({
  page,
  api,
}) => {
  await page.goto("/runs/investigate-v11-failed-0004");
  const alert = page.getByRole("alert");
  await expect(alert).toContainText(
    "The investigation ended without a report (failed).",
  );
  await expect(alert).toContainText(
    "Activity task failed: OpenShellError: sandbox admission refused",
  );
  await expect(page.getByRole("heading", { name: "No report" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Verdict" })).toHaveCount(0);
  await expect
    .poll(
      () =>
        api.calls("GET", "/api/runs/investigate-v11-failed-0004/events").length,
    )
    .toBeGreaterThan(0);
  await expect(
    page.getByRole("heading", { name: "Event timeline" }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("heading", { name: "Finding as submitted" }),
  ).toBeVisible();
  await expect(
    page.getByText("working snapshot", { exact: false }),
  ).toBeVisible();
});

test("run detail: a failed run names the failure type Temporal recorded", async ({
  page,
  api,
}) => {
  api.on("GET", /^\/api\/runs\/investigate-v11-failed-0004\/events$/, {
    body: {
      run_id: "investigate-v11-failed-0004",
      events: [
        {
          at: "2026-10-05T09:00:00+00:00",
          kind: "workflow_started",
          name: "InvestigationWorkflow",
          detail: "",
        },
        {
          at: "2026-10-05T09:02:00+00:00",
          kind: "activity_failed",
          name: "run_probe",
          detail: "OpenShellError",
        },
        {
          at: "2026-10-05T09:02:05+00:00",
          kind: "workflow_failed",
          name: null,
          detail: "UsageLimitExceeded",
        },
      ],
      truncated: false,
    },
  });
  await page.goto("/runs/investigate-v11-failed-0004");
  await expect(page.getByRole("alert")).toContainText(
    "Temporal recorded the failure as UsageLimitExceeded.",
  );
  const timeline = page.locator("div.rounded-lg", {
    has: page.getByRole("heading", { name: "Event timeline" }),
  });
  await expect(timeline.getByRole("listitem")).toHaveCount(3);
  await expect(timeline.getByRole("listitem").nth(1)).toContainText(
    "activity failed",
  );
});

test.describe("run detail: cancelling a running investigation", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/runs/investigate-v11-running-0003");
    await expect(
      page.getByRole("heading", { name: "In progress" }),
    ).toBeVisible();
    await expect(
      page.getByText("running", { exact: true }).first(),
    ).toBeVisible();
  });

  test("dismissing the confirmation sends nothing", async ({ page, api }) => {
    let message = "";
    page.once("dialog", (dialog) => {
      message = dialog.message();
      void dialog.dismiss();
    });
    await page.getByRole("button", { name: "Cancel investigation" }).click();
    expect(message).toBe("Request cancellation of this investigation?");
    await expect(
      page.getByRole("button", { name: "Cancel investigation" }),
    ).toBeEnabled();
    expect(api.calls("POST", /\/cancel$/)).toHaveLength(0);
  });

  test("confirming sends exactly one cancel request", async ({ page, api }) => {
    page.once("dialog", (dialog) => void dialog.accept());
    await page.getByRole("button", { name: "Cancel investigation" }).click();
    await expect(
      page.getByRole("button", { name: "Cancellation requested" }),
    ).toBeDisabled();
    expect(
      api.calls("POST", "/api/runs/investigate-v11-running-0003/cancel"),
    ).toHaveLength(1);
  });

  test("a running run's timeline is shown without a truncation note", async ({
    page,
  }) => {
    const timeline = page.locator("div.rounded-lg", {
      has: page.getByRole("heading", { name: "Event timeline" }),
    });
    await expect(timeline.getByRole("listitem")).toHaveCount(2);
    await expect(timeline).not.toContainText("The API bounded this timeline");
  });
});

test("an unknown run id shows a not-found state", async ({ page }) => {
  await page.goto("/runs/investigate-v11-does-not-exist");
  await expect(
    page.getByRole("heading", { level: 1, name: "Investigation not found" }),
  ).toBeVisible();
  await expect(page.getByText("investigate-v11-does-not-exist")).toBeVisible();
  await page.getByRole("link", { name: "Back to investigations" }).click();
  await expect(
    page.getByRole("heading", { level: 1, name: "Investigations" }),
  ).toBeVisible();
});

test("an unknown route shows the page-not-found view", async ({ page }) => {
  await page.goto("/no/such/page");
  await expect(
    page.getByRole("heading", { level: 1, name: "Page not found" }),
  ).toBeVisible();
  await expect(
    page.getByRole("link", { name: "Back to investigations" }),
  ).toBeVisible();
});
