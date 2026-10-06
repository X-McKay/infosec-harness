import assert from "node:assert/strict";
import test from "node:test";
import {
  isReportName,
  isWorkflowId,
  parseCase,
  parseCohortReport,
  parseQualificationReport,
  parseReplayReport,
  parseReportDocument,
  parseReportSummaries,
  reportApiPath,
  reportPath,
  runPath,
} from "./reports.ts";

test("report names accept harness file names and reject traversal or markup", () => {
  // `harness eval|qualify` write `<kind>-<UTC>.json` (cli.py `new_report`).
  assert.ok(isReportName("model-20261005T120000Z.json"));
  assert.ok(isReportName("openshell-20261005T120000Z.json"));
  assert.ok(isReportName("replay_1.v2.json"));
  for (const name of [
    "../secrets.json",
    "a/b.json",
    ".hidden.json",
    "model.json?x=1",
    "model",
    "javascript:alert(1).json",
    "<img>.json",
    "",
  ])
    assert.equal(isReportName(name), false, name);
  assert.equal(reportPath("../x.json"), null);
  assert.equal(reportApiPath("a b.json"), null);
  assert.equal(reportApiPath("model-1.json"), "/api/reports/model-1.json");
});

test("only current-prefix workflow IDs become run links", () => {
  // cohort.py builds `PREFIX + "eval-" + uuid4().hex` with PREFIX `investigate-v11-`.
  assert.equal(
    runPath("investigate-v11-eval-0123abcd"),
    "/runs/investigate-v11-eval-0123abcd",
  );
  for (const id of [
    "qualification-0123",
    "investigate-v11-EVAL",
    "investigate-v11-../x",
    "investigate-vx-a",
    "https://example.com",
    null,
    undefined,
  ])
    assert.equal(isWorkflowId(id), false, String(id));
  assert.equal(runPath("javascript:alert(1)"), null);
});

test("summaries drop rows without a name and treat unknown gates as not_checked", () => {
  const rows = parseReportSummaries([
    {
      name: "model-2.json",
      kind: "model",
      gates: { complete_corpus: "passed", task_success_rate: "yes" },
      planned: 36,
      task_success_rate: "0.9",
      bytes: 1200,
    },
    { kind: "model" },
    "garbage",
    { name: "odd.json", kind: "brokered" },
  ]);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].gates.complete_corpus, "passed");
  // A gate state other than passed/failed is missing evidence, never success.
  assert.equal(rows[0].gates.task_success_rate, "not_checked");
  // A numeric field recorded as text is not coerced into a measurement.
  assert.equal(rows[0].task_success_rate, null);
  assert.equal(rows[0].planned, 36);
  assert.equal(rows[1].kind, "unknown");
  assert.deepEqual(
    parseReportSummaries({ items: [{ name: "a.json" }] }).length,
    1,
  );
  assert.deepEqual(parseReportSummaries(null), []);
});

test("a freshly started cohort parses with every measurement unavailable", () => {
  // The first write in `evaluate_corpus` has no completed/planned/rate fields yet.
  const report = parseCohortReport({
    version: 1,
    kind: "cohort",
    status: "running",
    gates: {
      complete_corpus: "not_checked",
      task_success_rate: "not_checked",
      unsafe_negatives: "not_checked",
    },
    cases: [
      {
        name: "sqli-vulnerable",
        expected: "potentially_exploitable",
        status: "unstarted",
      },
    ],
  });
  assert.equal(report.kind, "cohort");
  assert.equal(report.completed, null);
  assert.equal(report.task_success_rate, null);
  assert.equal(report.native_operation_budget, null);
  assert.equal(report.cases[0].status, "unstarted");
  assert.equal(report.cases[0].predicted, null);
  assert.deepEqual(report.cases[0].usage, {});
});

test("case records keep failure chains as text and native counts as observed", () => {
  const item = parseCase({
    name: "java-xxe-fixed",
    expected: "likely_not_exploitable",
    status: "failed",
    error_type: "WorkflowFailureError",
    failure_chain: [
      { type: "WorkflowFailureError", message: "<b>failed</b>" },
      { type: "UsageLimitExceeded", message: 42 },
      "not a link",
    ],
    usage: { requests: 3, tool_calls: "7", input_tokens: 100 },
    native_operations: {
      status: "observed",
      categories: { exec: { completed: 4, unknown: 1 }, bogus: "x" },
      total: { completed: 6, unknown: 1 },
      limitations: ["Unknown intents may not have reached native dispatch.", 3],
    },
    receipts: {
      status: "observed",
      count: 2,
      items: [{ operation_id: "a", exit_code: 0 }],
    },
  });
  assert.equal(item.failure_chain.length, 2);
  // Markup stays literal text for React to escape.
  assert.equal(item.failure_chain[0].message, "<b>failed</b>");
  assert.equal(item.failure_chain[1].message, "");
  assert.deepEqual(item.usage, { requests: 3, input_tokens: 100 });
  assert.deepEqual(Object.keys(item.native_operations!.categories), ["exec"]);
  assert.deepEqual(item.native_operations!.total, { completed: 6, unknown: 1 });
  assert.equal(item.native_operations!.limitations.length, 1);
  assert.equal(item.receipts!.items[0].exit_code, 0);
  assert.equal(item.receipts!.items[0].output_truncated, false);
});

test("capacity pre-flight states other than passed or failed stay not_checked", () => {
  const report = parseCohortReport({
    kind: "cohort",
    cases: [],
    native_operation_budget: { status: "skipped", planned_cases: 36 },
  });
  assert.equal(report.native_operation_budget!.status, "not_checked");
  assert.equal(report.native_operation_budget!.planned_cases, 36);
});

test("qualification profiles keep each recorded check state", () => {
  const report = parseQualificationReport({
    version: 1,
    status: "passed",
    model_calls: 0,
    model_quality: "not_checked",
    cleanup: "passed",
    profiles: {
      workspace: { boundary: "passed", roundtrip: "passed", cleanup: 1 },
      probe: { boundary: "passed", roundtrip: "not_checked" },
    },
  });
  assert.equal(report.profiles.length, 2);
  assert.equal(report.profiles[0].name, "workspace");
  // A non-string check value is not evidence of anything.
  assert.equal(report.profiles[0].checks.cleanup, "not_checked");
  assert.equal(report.profiles[1].checks.roundtrip, "not_checked");
});

test("a single replay document becomes one history row", () => {
  // `replay_history` returns one flat document per workflow.
  const report = parseReplayReport({
    status: "failed",
    workflow_id: "investigate-v11-abc",
    history_events: 120,
    history_sha256: "f".repeat(64),
    verdict: null,
    failure_chain: [
      {
        type: "AssertionError",
        message: "Replay attempted native operation: execute",
      },
    ],
  });
  assert.equal(report.histories.length, 1);
  assert.equal(report.histories[0].history_events, 120);
  assert.equal(report.histories[0].failure_chain[0].type, "AssertionError");
});

test("documents are classified by shape, falling back to unknown", () => {
  assert.equal(
    parseReportDocument({ kind: "cohort", cases: [] }).shape,
    "cohort",
  );
  assert.equal(
    parseReportDocument({ kind: "diagnostic", cases: [] }).shape,
    "cohort",
  );
  assert.equal(
    parseReportDocument({ profiles: {}, model_calls: 0 }).shape,
    "qualification",
  );
  assert.equal(parseReportDocument({ history_events: 3 }).shape, "replay");
  // A self-declared cohort kind without case records is not trusted as a cohort.
  assert.equal(parseReportDocument({ kind: "cohort" }).shape, "unknown");
  assert.equal(parseReportDocument([1, 2]).shape, "unknown");
  assert.equal(parseReportDocument("text").shape, "unknown");
});
