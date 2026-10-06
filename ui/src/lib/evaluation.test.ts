import assert from "node:assert/strict";
import test from "node:test";
import {
  breakdown,
  caseMetrics,
  caseOutcome,
  failureClass,
  failureSummary,
  gateRows,
  headroomSummary,
  histogram,
  measured,
  pairRows,
  parseCaseName,
  percentile,
  sortCases,
  successFraction,
  unsafeNegativeCount,
} from "./evaluation.ts";
import {
  parseCase,
  parseCohortReport,
  type CapacityPreflight,
  type CohortCase,
} from "./reports.ts";

// Small hand-built fixtures; every expectation below is derived from the rule cited beside
// it (evals/cohort.py or the corpus naming convention), not from running the helper.
const VULN = "potentially_exploitable";
const SAFE = "likely_not_exploitable";
const done = (
  name: string,
  expected: string,
  predicted: string,
  extra: Record<string, unknown> = {},
): CohortCase =>
  parseCase({
    name,
    expected,
    predicted,
    status: "completed",
    passed: expected === predicted,
    ...extra,
  });
const failed = (name: string, expected: string, extra = {}) =>
  parseCase({ name, expected, status: "failed", ...extra });
const unstarted = (name: string, expected: string) =>
  parseCase({ name, expected, status: "unstarted" });

const cases = [
  done("sqli-vulnerable", VULN, VULN, {
    duration_seconds: 100,
    usage: {
      requests: 10,
      tool_calls: 20,
      input_tokens: 1000,
      output_tokens: 50,
    },
    native_operations: {
      status: "observed",
      total: { completed: 30, unknown: 2 },
    },
  }),
  done("sqli-fixed", SAFE, SAFE, {
    duration_seconds: 200,
    usage: { requests: 5, total_tokens: 700 },
    native_operations: { status: "not_checked" },
  }),
  done("java-xxe-vulnerable", VULN, SAFE, { duration_seconds: 300 }),
  done("java-xxe-fixed", SAFE, "inconclusive", { duration_seconds: 400 }),
  failed("perl-cmdi-vulnerable", VULN, {
    error_type: "WorkflowFailureError",
    duration_seconds: 50,
    failure_chain: [
      { type: "WorkflowFailureError", message: "Workflow execution failed" },
      { type: "UsageLimitExceeded", message: "request limit of 40" },
    ],
  }),
  unstarted("perl-cmdi-fixed", SAFE),
];

test("success fraction counts correct cases over planned, as cohort.py does", () => {
  // `task_success_rate = passed / len(rows)`: 2 correct (sqli pair) of 6 planned.
  const report = parseCohortReport({
    kind: "cohort",
    cases: cases.map((c) => ({ ...c })),
  });
  const fraction = successFraction({ ...report, cases });
  assert.equal(fraction.correct, 2);
  assert.equal(fraction.planned, 6);
  assert.equal(fraction.completed, 4);
  assert.equal(fraction.rate, 2 / 6);
});

test("a recorded rate and counts take precedence over recomputation", () => {
  const report = parseCohortReport({
    kind: "cohort",
    planned: 36,
    completed: 36,
    task_success_rate: 0.75,
    cases: [],
  });
  assert.deepEqual(successFraction(report), {
    correct: 0,
    completed: 36,
    planned: 36,
    rate: 0.75,
  });
});

test("only a vulnerable case predicted not exploitable is an unsafe negative", () => {
  // cohort.py: predicted == likely_not_exploitable and expected == potentially_exploitable.
  // The inconclusive fixed case and the failed vulnerable case are not unsafe negatives.
  assert.equal(unsafeNegativeCount(cases), 1);
});

test("outcomes separate correct negatives from inconclusive answers", () => {
  assert.deepEqual(caseOutcome(cases[0]), {
    outcome: "correct_positive",
    correct: true,
  });
  assert.deepEqual(caseOutcome(cases[1]), {
    outcome: "correct_negative",
    correct: true,
  });
  assert.deepEqual(caseOutcome(cases[2]), {
    outcome: "unsafe_negative",
    correct: false,
  });
  assert.deepEqual(caseOutcome(cases[3]), {
    outcome: "inconclusive",
    correct: false,
  });
  assert.deepEqual(caseOutcome(cases[4]), { outcome: "error", correct: false });
  assert.deepEqual(caseOutcome(cases[5]), {
    outcome: "not_run",
    correct: false,
  });
  assert.deepEqual(caseOutcome(done("xss-fixed", SAFE, VULN)), {
    outcome: "false_positive",
    correct: false,
  });
  // A `passed: true` flag without a completed prediction is not trusted.
  assert.equal(
    caseOutcome(
      parseCase({
        name: "x",
        expected: VULN,
        status: "starting",
        passed: true,
      }),
    ).correct,
    false,
  );
});

test("gate rows follow policy order and never upgrade a missing gate", () => {
  const report = parseCohortReport({
    kind: "cohort",
    status: "failed",
    gates: { complete_corpus: "failed", extra_gate: "passed" },
    release_policy: {
      minimum_task_success_rate: 0.75,
      maximum_unsafe_negatives: 0,
    },
    cases,
  });
  const rows = gateRows(report);
  assert.deepEqual(
    rows.map((row) => [row.key, row.status]),
    [
      ["complete_corpus", "failed"],
      ["task_success_rate", "not_checked"],
      ["unsafe_negatives", "not_checked"],
      ["extra_gate", "passed"],
    ],
  );
  assert.match(rows[0].detail, /4 of 6 planned cases completed/);
  assert.match(rows[1].detail, /2 \/ 6 correct/);
  assert.match(rows[1].detail, /Not evaluated/);
  assert.match(rows[2].detail, /1 recorded; policy maximum 0/);
  assert.equal(rows[3].label, "Extra gate");
});

test("diagnostic gates explain why they cannot qualify", () => {
  const report = parseCohortReport({
    kind: "diagnostic",
    status: "completed",
    cases: [],
  });
  for (const row of gateRows(report)) {
    assert.equal(row.status, "not_checked");
    assert.match(row.detail, /diagnostic subset never qualifies/);
  }
});

test("case metrics read usage and only observed native operations", () => {
  assert.deepEqual(caseMetrics(cases[0]), {
    duration: 100,
    requests: 10,
    toolCalls: 20,
    inputTokens: 1000,
    outputTokens: 50,
    tokens: 1050,
    nativeCompleted: 30,
    nativeUnknown: 2,
    // Unknown intents may have reached dispatch, so they count toward the total.
    nativeOps: 32,
  });
  const second = caseMetrics(cases[1]);
  assert.equal(second.tokens, 700);
  // `not_checked` receipts are unknown, never zero operations.
  assert.equal(second.nativeOps, null);
  assert.equal(caseMetrics(cases[5]).duration, null);
  assert.deepEqual(measured(cases, "duration"), [100, 200, 300, 400, 50]);
  assert.deepEqual(measured(cases, "nativeOps"), [32]);
});

test("percentile uses the nearest-rank method", () => {
  assert.equal(percentile([], 0.5), null);
  // n=5: p50 rank ceil(2.5)=3 -> 30; p90 rank ceil(4.5)=5 -> 50; p0 clamps to rank 1.
  assert.equal(percentile([50, 10, 40, 20, 30], 0.5), 30);
  assert.equal(percentile([50, 10, 40, 20, 30], 0.9), 50);
  assert.equal(percentile([50, 10, 40, 20, 30], 0), 10);
  // n=4: p50 rank 2 -> 20 (the lower middle value, not an interpolated 25).
  assert.equal(percentile([10, 20, 30, 40], 0.5), 20);
});

test("histogram bins cover the range and include the maximum", () => {
  const bins = histogram([0, 1, 2, 3, 4, 10], 5);
  assert.equal(bins.length, 5);
  assert.deepEqual(
    bins.map((bin) => bin.count),
    [2, 2, 1, 0, 1],
  );
  assert.equal(bins[0].lower, 0);
  assert.equal(bins[4].upper, 10);
  assert.deepEqual(histogram([7, 7], 5), [{ lower: 7, upper: 7, count: 2 }]);
  assert.deepEqual(histogram([]), []);
});

test("case names yield language, CWE topic and variant", () => {
  assert.deepEqual(parseCaseName("sqli-fixed"), {
    language: "python",
    topic: "sqli",
    variant: "fixed",
    pair: "sqli",
  });
  assert.deepEqual(parseCaseName("java-xxe-vulnerable"), {
    language: "java",
    topic: "xxe",
    variant: "vulnerable",
    pair: "java-xxe",
  });
  assert.equal(parseCaseName("javascript-xssesm-fixed").topic, "xssesm");
  assert.equal(parseCaseName("perl-cmdi-fixed").language, "perl");
  // No variant suffix: a standalone Python case.
  assert.deepEqual(parseCaseName("unreachable"), {
    language: "python",
    topic: "unreachable",
    variant: null,
    pair: "unreachable",
  });
  // A bare language word is a topic, not a prefix.
  assert.equal(parseCaseName("java-fixed").language, "python");
});

test("breakdowns count outcomes per language and per topic over planned cases", () => {
  const languages = breakdown(cases, "language");
  assert.deepEqual(
    languages.map((row) => [row.key, row.planned, row.correct, row.rate]),
    [
      ["java", 2, 0, 0],
      ["perl", 2, 0, 0],
      ["python", 2, 2, 1],
    ],
  );
  const java = languages[0];
  assert.equal(java.unsafeNegatives, 1);
  assert.equal(java.inconclusive, 1);
  assert.equal(languages[1].errors, 1);
  assert.equal(languages[2].correctNegatives, 1);
  const topics = breakdown(cases, "topic");
  assert.deepEqual(
    topics.map((row) => row.key),
    ["cmdi", "sqli", "xxe"],
  );
});

test("pairs put vulnerable and fixed side by side", () => {
  const rows = pairRows([...cases, done("unreachable", SAFE, SAFE)]);
  assert.deepEqual(
    rows.map((row) => [
      row.pair,
      row.vulnerable?.name,
      row.fixed?.name,
      row.bothCorrect,
    ]),
    [
      ["sqli", "sqli-vulnerable", "sqli-fixed", true],
      ["java-xxe", "java-xxe-vulnerable", "java-xxe-fixed", false],
      ["perl-cmdi", "perl-cmdi-vulnerable", "perl-cmdi-fixed", false],
      ["unreachable", undefined, "unreachable", false],
    ],
  );
});

test("failure classes mirror cohort.py's agent-level rule", () => {
  // Every link after the first is an AGENT_FAILURES type.
  assert.equal(failureClass(cases[4]), "agent_model");
  const native = failed("x-vulnerable", VULN, {
    error_type: "WorkflowFailureError",
    failure_chain: [
      { type: "WorkflowFailureError", message: "failed" },
      {
        type: "UsageLimitExceeded",
        message: "then ExecutionUnknown during cleanup",
      },
    ],
  });
  // The chain text names unknown dispatch: native wins over agent-level.
  assert.equal(failureClass(native), "native_dispatch");
  assert.equal(
    failureClass(failed("t", VULN, { error_type: "TimeoutError" })),
    "timeout",
  );
  assert.equal(
    failureClass(failed("c", VULN, { error_type: "CancelledError" })),
    "cancelled",
  );
  assert.equal(
    failureClass(
      failed("i", VULN, {
        error_type: "ValueError",
        failure_chain: [
          {
            type: "ValueError",
            message:
              "Evaluation result does not match the requested worker/model identity",
          },
        ],
      }),
    ),
    "identity",
  );
  assert.equal(
    failureClass(failed("o", VULN, { error_type: "RuntimeError" })),
    "other",
  );
  assert.equal(failureClass(cases[0]), null);
  assert.deepEqual(failureSummary([...cases, native]), [
    { kind: "agent_model", count: 1, errorTypes: ["WorkflowFailureError"] },
    { kind: "native_dispatch", count: 1, errorTypes: ["WorkflowFailureError"] },
  ]);
});

const budget = (fields: Partial<CapacityPreflight>): CapacityPreflight => ({
  status: "not_checked",
  planned_cases: 36,
  per_case_ceiling: 180,
  required_headroom: 6480,
  retained: null,
  quota: null,
  headroom: null,
  observed_at_ms: null,
  reason: null,
  error_type: null,
  source: null,
  limitations: [],
  ...fields,
});

test("headroom summary states capacity plainly and never assumes sufficiency", () => {
  assert.equal(headroomSummary(null).status, "not_checked");
  const unconfigured = headroomSummary(
    budget({ reason: "No read-only native occupancy command is configured." }),
  );
  assert.equal(unconfigured.status, "not_checked");
  assert.equal(unconfigured.margin, null);
  assert.match(unconfigured.summary, /^Not checked: No read-only/);
  // 20,000 quota with 12,000 retained leaves 8,000 against 6,480 required: margin 1,520.
  const passed = headroomSummary(
    budget({ status: "passed", retained: 12000, quota: 20000, headroom: 8000 }),
  );
  assert.equal(passed.margin, 1520);
  assert.equal(passed.utilization, 0.6);
  assert.match(passed.summary, /Sufficient/);
  // Headroom is derived from quota - retained when not recorded: 20,000 - 15,000 = 5,000.
  const short = headroomSummary(
    budget({ status: "failed", retained: 15000, quota: 20000 }),
  );
  assert.equal(short.headroom, 5000);
  assert.equal(short.margin, -1480);
  assert.match(short.summary, /Insufficient/);
  const broken = headroomSummary(
    budget({
      status: "failed",
      reason: "The occupancy command did not return a read-only observation.",
      error_type: "TimeoutExpired",
    }),
  );
  assert.match(broken.summary, /TimeoutExpired/);
  assert.equal(broken.utilization, null);
});

test("case sorting is stable and puts missing measurements last", () => {
  const byDuration = sortCases(cases, "duration").map((item) => item.name);
  assert.deepEqual(byDuration, [
    "perl-cmdi-vulnerable",
    "sqli-vulnerable",
    "sqli-fixed",
    "java-xxe-vulnerable",
    "java-xxe-fixed",
    "perl-cmdi-fixed",
  ]);
  const descending = sortCases(cases, "duration", true).map(
    (item) => item.name,
  );
  assert.equal(descending[0], "java-xxe-fixed");
  assert.equal(descending.at(-1), "perl-cmdi-fixed");
  assert.equal(sortCases(cases, "name")[0].name, "java-xxe-fixed");
});
