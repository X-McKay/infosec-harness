// Regenerates the synthetic report fixtures under e2e/fixtures/reports/ and the
// GET /api/reports listing in e2e/fixtures/reports-index.json.
//
//   node e2e/fixtures/generate-reports.mjs
//
// Shapes follow src/infosec_harness/evals/cohort.py (cohort and diagnostic reports, replay)
// and `harness qualify` (openshell reports); summaries follow api.summarize_report. Values
// are synthetic and fixed, so the output is byte-for-byte stable.
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const here = (path) => fileURLToPath(new URL(path, import.meta.url));

const CASES = [
  "sqli-vulnerable", "sqli-fixed", "cmdi-vulnerable", "cmdi-fixed",
  "pathtraversal-vulnerable", "pathtraversal-fixed", "xss-vulnerable", "xss-fixed",
  "codeinjection-vulnerable", "codeinjection-fixed", "deserialization-vulnerable",
  "deserialization-fixed", "xxe-vulnerable", "xxe-fixed", "ssrf-vulnerable", "ssrf-fixed",
  "unreachable", "testonly", "java-sqli-vulnerable", "java-sqli-fixed",
  "java-cmdi-vulnerable", "java-cmdi-fixed", "java-xxe-vulnerable", "java-xxe-fixed",
  "javascript-cmdi-vulnerable", "javascript-cmdi-fixed", "javascript-xss-vulnerable",
  "javascript-xss-fixed", "perl-sqli-vulnerable", "perl-sqli-fixed",
  "perl-cmdi-vulnerable", "perl-cmdi-fixed", "javascript-xssesm-vulnerable",
  "javascript-xssesm-fixed", "perl-xss-vulnerable", "perl-xss-fixed",
];
const expected = (name) =>
  name.endsWith("-vulnerable") ? "potentially_exploitable" : "likely_not_exploitable";
const hex = (seed, length = 64) =>
  Array.from({ length }, (_, i) => "0123456789abcdef"[(seed * 7 + i * 13) % 16]).join("");

const IDENTITY = {
  fingerprint: `wkr-${hex(3, 16)}`,
  code_sha256: hex(4),
  config_sha256: hex(5),
  dependencies: { "pydantic-ai": "1.2.3", temporalio: "1.18.0" },
};
const LIMITS = {
  max_requests: 40,
  max_tool_calls: 60,
  total_tokens: 400000,
  timeout_seconds: 1800,
  command_timeout_seconds: 120,
};
const CEILING = 40 + 60 + 20;
const POLICY = { minimum_task_success_rate: 0.8, maximum_unsafe_negatives: 0 };

function iso(base, offsetSeconds) {
  return new Date(Date.parse(base) + offsetSeconds * 1000).toISOString().replace(".000Z", "+00:00").replace("Z", "+00:00");
}

/** One case record; `outcome` is "correct", a predicted label, "failed", "starting" or "unstarted". */
function caseRecord(name, index, outcome, start, extra = {}) {
  const row = { name, expected: expected(name), status: "unstarted" };
  if (outcome === "unstarted") return row;
  const startedAt = iso(start, index * 400);
  const workflow = `investigate-v11-eval-${hex(index + 11, 12)}`;
  if (outcome === "starting")
    return { ...row, status: "starting", workflow_id: workflow, started_at: startedAt };
  const duration = 240 + ((index * 37) % 180) + 0.25;
  const finished = { finished_at: iso(start, index * 400 + duration), duration_seconds: duration };
  const native = {
    status: "observed",
    categories: {
      workspace: { completed: 20 + (index % 5), unknown: 0 },
      probe: { completed: 8 + (index % 4), unknown: index % 3 === 0 ? 1 : 0 },
    },
    total: { completed: 28 + (index % 5) + (index % 4), unknown: index % 3 === 0 ? 1 : 0 },
    limitations: [],
  };
  if (outcome === "failed")
    return {
      ...row,
      status: "failed",
      workflow_id: workflow,
      started_at: startedAt,
      ...finished,
      native_operations: native,
      ...extra,
    };
  const predicted = outcome === "correct" ? expected(name) : outcome;
  return {
    ...row,
    status: "completed",
    workflow_id: workflow,
    started_at: startedAt,
    ...finished,
    predicted,
    passed: predicted === expected(name),
    source_digest: `sha256:${hex(index + 21)}`,
    usage: {
      requests: 8 + (index % 7),
      tool_calls: 12 + (index % 9),
      input_tokens: 20000 + index * 1000,
      output_tokens: 1000 + index * 50,
    },
    limitations: ["Probe claims are self-reported."],
    worker_identity: IDENTITY,
    native_operations: native,
  };
}

function estimate(rows) {
  const observed = rows.filter((row) => row.native_operations?.status === "observed");
  const samples = observed.filter((row) => row.status === "completed");
  const counts = samples.map((row) => row.native_operations.total.completed + row.native_operations.total.unknown);
  const actual = observed.reduce(
    (total, row) => total + row.native_operations.total.completed + row.native_operations.total.unknown,
    0,
  );
  const unobserved = rows.length - observed.length;
  return {
    status: samples.length ? "estimate" : "not_checked",
    completed_case_samples: samples.length,
    planned_cases: rows.length,
    observed_totals: {
      completed: observed.reduce((total, row) => total + row.native_operations.total.completed, 0),
      unknown: observed.reduce((total, row) => total + row.native_operations.total.unknown, 0),
    },
    native_capacity: "not_checked",
    limitations: [
      "Actual observed attempts plus completed-case range extrapolated to unobserved cases; not a capacity gate.",
    ],
    ...(samples.length
      ? {
          observed_attempt_range_per_case: [Math.min(...counts), Math.max(...counts)],
          unobserved_cases: unobserved,
          estimated_cohort_attempt_range: [
            actual + Math.min(...counts) * unobserved,
            actual + Math.max(...counts) * unobserved,
          ],
        }
      : {}),
  };
}

function cohort({ kind = "cohort", start, cases, status, gates, finished = true, budget }) {
  const complete = cases.filter((row) => row.status === "completed").length;
  const passed = cases.filter((row) => row.passed === true).length;
  const unsafe = cases.filter(
    (row) => row.expected === "potentially_exploitable" && row.predicted === "likely_not_exploitable",
  ).length;
  const report = {
    version: 1,
    kind,
    commit: hex(1, 40),
    generation: "v11",
    model: "example-model-2026-09",
    task_queue: `investigate-v11-eval-${hex(2, 32)}`,
    owned_worker: true,
    worker_identity: IDENTITY,
    dataset_sha256: hex(6),
    runtime_config_sha256: hex(7),
    limits: LIMITS,
    native_operation_budget: budget ?? {
      status: "passed",
      planned_cases: cases.length,
      per_case_ceiling: CEILING,
      required_headroom: cases.length * CEILING,
      retained: 2000,
      quota: 20000,
      headroom: 18000,
      observed_at_ms: Date.parse(start) - 5000,
      source: "operator-configured read-only occupancy command",
      limitations: [
        "One ledger snapshot: other callers and 24 h retention expiry change occupancy during the run.",
      ],
    },
    started_at: iso(start, 0),
    status,
    gates,
    threshold: POLICY.minimum_task_success_rate,
    release_policy_sha256: hex(8),
    release_policy: POLICY,
    cases,
    native_operation_estimate: estimate(cases),
  };
  if (finished)
    Object.assign(report, {
      completed: complete,
      planned: cases.length,
      task_success_rate: passed / cases.length,
      unsafe_negatives: unsafe,
      finished_at: iso(start, cases.length * 400),
    });
  return report;
}

// A failed full cohort: 28 completed (24 correct, 2 inconclusive, 1 false positive, 1 unsafe
// negative), one agent-level failure with a cause chain (kept going), one timeout that
// stopped the cohort, and 6 unstarted cases.
const failedStart = "2026-10-05T09:00:00+00:00";
const failedCases = CASES.map((name, index) => {
  if (index >= 30) return caseRecord(name, index, "unstarted", failedStart);
  if (index === 28)
    return caseRecord(name, index, "failed", failedStart, {
      error_type: "WorkflowFailureError",
      failure_chain: [
        { type: "WorkflowFailureError", message: "Workflow execution failed" },
        { type: "ActivityError", message: "Activity task failed" },
        {
          type: "UsageLimitExceeded",
          message: "The next request would exceed the request_limit of 40 <script>window.__e2ePwned=20</script>",
        },
      ],
      receipts: {
        status: "observed",
        count: 2,
        items: [
          { operation_id: "op-1", exit_code: 0, output_truncated: false },
          { operation_id: "op-2", exit_code: 1, output_truncated: true },
        ],
      },
    });
  if (index === 29)
    return caseRecord(name, index, "failed", failedStart, {
      error_type: "TimeoutError",
      failure_chain: [],
      cancellation: "terminal",
      receipts: { status: "not_checked", error_type: "FileNotFoundError" },
    });
  const outcome =
    { 4: "inconclusive", 16: "inconclusive", 7: "potentially_exploitable", 18: "likely_not_exploitable" }[index] ??
    "correct";
  return caseRecord(name, index, outcome, failedStart);
});
const failedCohort = cohort({
  start: failedStart,
  cases: failedCases,
  status: "failed",
  gates: { complete_corpus: "failed", task_success_rate: "not_checked", unsafe_negatives: "not_checked" },
});

// A complete, passing cohort: 33 of 36 correct, no unsafe negatives.
const passedStart = "2026-10-04T09:00:00+00:00";
const passedCohort = cohort({
  start: passedStart,
  cases: CASES.map((name, index) =>
    caseRecord(
      name,
      index,
      { 4: "inconclusive", 16: "inconclusive", 7: "potentially_exploitable" }[index] ?? "correct",
      passedStart,
    ),
  ),
  status: "passed",
  gates: { complete_corpus: "passed", task_success_rate: "passed", unsafe_negatives: "passed" },
});

// A cohort still running: 10 completed, one starting, the rest unstarted.
const runningStart = "2026-10-06T08:00:00+00:00";
const runningCohort = cohort({
  start: runningStart,
  cases: CASES.map((name, index) =>
    caseRecord(name, index, index < 10 ? "correct" : index === 10 ? "starting" : "unstarted", runningStart),
  ),
  status: "running",
  gates: { complete_corpus: "not_checked", task_success_rate: "not_checked", unsafe_negatives: "not_checked" },
  finished: false,
});

// A --case diagnostic subset: completed, every gate not_checked by construction.
const diagnosticStart = "2026-10-05T15:00:00+00:00";
const diagnostic = cohort({
  kind: "diagnostic",
  start: diagnosticStart,
  cases: ["cmdi-vulnerable", "cmdi-fixed"].map((name, index) =>
    caseRecord(name, index, "correct", diagnosticStart),
  ),
  status: "completed",
  gates: { complete_corpus: "not_checked", task_success_rate: "not_checked", unsafe_negatives: "not_checked" },
  budget: {
    status: "not_checked",
    planned_cases: 2,
    per_case_ceiling: CEILING,
    required_headroom: 2 * CEILING,
    reason: "No read-only native occupancy command is configured.",
    limitations: [],
  },
});

const CHECKS = ["boundary", "roundtrip", "saved_operation", "sandbox_reuse", "cleanup"];
const qualification = {
  version: 1,
  status: "passed",
  run_id: "qualify-20261005-1000",
  config_sha256: hex(9),
  model_calls: 0,
  model_quality: "not_checked",
  cleanup: "passed",
  profiles: {
    workspace: Object.fromEntries(CHECKS.map((check) => [check, "passed"])),
    probe: Object.fromEntries(CHECKS.map((check) => [check, "passed"])),
  },
};
const olderQualification = {
  version: 1,
  status: "failed",
  run_id: "qualify-20261001-1000",
  config_sha256: hex(10),
  model_calls: 0,
  model_quality: "not_checked",
  cleanup: "failed",
  error_type: "OpenShellError",
  cleanup_error_type: "TimeoutError",
  profiles: {
    workspace: { boundary: "passed", roundtrip: "failed", saved_operation: "not_checked", sandbox_reuse: "not_checked", cleanup: "not_checked" },
  },
};
const replay = {
  status: "passed",
  workflow_id: "investigate-v11-exploitable-0001",
  history_events: 42,
  history_sha256: hex(12),
  verdict: "potentially_exploitable",
};

const documents = [
  ["model-20261006T080000Z.json", "model", runningCohort, "2026-10-06T08:40:00+00:00"],
  ["diagnostic-20261005T150000Z.json", "diagnostic", diagnostic, "2026-10-05T15:20:00+00:00"],
  ["replay-20261005T110000Z.json", "replay", replay, "2026-10-05T11:00:30+00:00"],
  ["openshell-20261005T100000Z.json", "openshell", qualification, "2026-10-05T10:05:00+00:00"],
  ["model-20261005T090000Z.json", "model", failedCohort, "2026-10-05T12:20:00+00:00"],
  ["model-20261004T090000Z.json", "model", passedCohort, "2026-10-04T13:00:00+00:00"],
  ["openshell-20261001T100000Z.json", "openshell", olderQualification, "2026-10-01T10:05:00+00:00"],
];

const text = (value) => (typeof value === "string" ? value : null);
const count = (value) => (Number.isInteger(value) && value >= 0 ? value : null);
function summary(name, kind, document, modified) {
  const body = `${JSON.stringify(document, null, 2)}\n`;
  writeFileSync(here(`./reports/${name}`), body);
  const rate = document.task_success_rate;
  return {
    name,
    kind,
    bytes: Buffer.byteLength(body),
    modified_at: modified,
    status: text(document.status),
    started_at: text(document.started_at),
    finished_at: text(document.finished_at),
    commit: text(document.commit),
    model: text(document.model),
    planned: count(document.planned),
    completed: count(document.completed),
    task_success_rate: typeof rate === "number" ? rate : null,
    unsafe_negatives: count(document.unsafe_negatives),
    gates: document.gates ?? {},
  };
}

const items = documents.map(([name, kind, document, modified]) => summary(name, kind, document, modified));
// A file the API could not parse: listed with status "unreadable", detail answers 422.
items.push({
  name: "legacy-broken.json",
  kind: "unknown",
  bytes: 17,
  modified_at: "2026-09-30T00:00:00+00:00",
  status: "unreadable",
  gates: {},
});
writeFileSync(here("./reports-index.json"), `${JSON.stringify({ items, truncated: false }, null, 2)}\n`);
