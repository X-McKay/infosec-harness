import assert from "node:assert/strict";
import test from "node:test";
import type { ExperimentCase, ExperimentSummary } from "../api/client.ts";
import {
  caseCost,
  caseNumber,
  caseResources,
  comparisonPoints,
  gateObservations,
  percentile,
  qualityFraction,
} from "./evaluation.ts";

// Small summary-shaped fixtures exercise interpretation only, never operational data.
type Headline = Partial<
  Pick<
    ExperimentSummary,
    | "status"
    | "accuracy"
    | "cost_usd_per_case"
    | "passed"
    | "cases_completed"
    | "cases_planned"
    | "budget_exhausted_count"
    | "gate_status"
  >
>;
const experiment = (
  headline: Headline = {},
  fields: Partial<ExperimentSummary> = {},
): ExperimentSummary => ({
  id: "report-a",
  agent: "verdict",
  dataset: "triage",
  dataset_version: "v1",
  git_sha: "",
  overlay: "",
  repetitions: 1,
  config_hash: "",
  git_dirty: false,
  model_name: "",
  backend: "",
  pricing: "",
  harness_version: "",
  created_at: "",
  status: null,
  accuracy: null,
  cost_usd_per_case: null,
  p50_latency_s: null,
  p95_latency_s: null,
  passed: null,
  cases_completed: null,
  cases_planned: null,
  budget_exhausted_count: null,
  gate_status: null,
  ...headline,
  ...fields,
});
const caseRecord = (
  scores: ExperimentCase["scores"] = {},
  fields: Partial<ExperimentCase> = {},
): ExperimentCase => ({
  case_name: "case",
  repetition: 0,
  passed: true,
  scores,
  cost_usd: 0,
  latency_s: null,
  ...fields,
});

test("absent gate measurements remain unknown and never establish promotion", () => {
  assert.deepEqual(gateObservations(experiment()), [
    {
      label: "Quality evidence",
      status: "unknown",
      detail: "No accuracy measurement was recorded.",
    },
    {
      label: "Budget evidence",
      status: "unknown",
      detail: "No budget exhaustion count was recorded.",
    },
    {
      label: "Release gates",
      status: "unknown",
      detail:
        "No release-gate evaluation was recorded (only complete runs are evaluated).",
    },
    {
      label: "Completion evidence",
      status: "unknown",
      detail: "No completion status was recorded.",
    },
  ]);
  assert.equal(qualityFraction(experiment()), undefined);
  const quality = gateObservations(experiment({ accuracy: 0.8 }))[0];
  assert.equal(quality.status, "unknown");
  assert.equal(quality.detail, "80.0% accuracy; case numerator unavailable.");
});

// Regression: a recorded case fraction without an accuracy measurement used to render
// "0.0% accuracy", fabricating a measurement.
test("a case fraction without recorded accuracy never reports zero accuracy", () => {
  const quality = gateObservations(
    experiment({ passed: 3, cases_completed: 4 }),
  )[0];
  assert.equal(quality.status, "unknown");
  assert.equal(quality.detail, "3 / 4 cases passed · accuracy unavailable");
});

test("recorded gates retain measured fractions, budget findings, and completion counts", () => {
  const headline: Headline = {
    accuracy: 0.75,
    passed: 3,
    cases_completed: 4,
    cases_planned: 5,
    status: "complete",
    budget_exhausted_count: 0,
    gate_status: "passed",
  };
  assert.deepEqual(gateObservations(experiment(headline)), [
    {
      label: "Quality evidence",
      status: "recorded",
      detail: "3 / 4 cases passed · 75.0% accuracy",
    },
    {
      label: "Budget evidence",
      status: "clear",
      detail: "0 case runs exhausted their budget",
    },
    {
      label: "Release gates",
      status: "passed",
      detail: "The agent's release policy evaluated this run as passed.",
    },
    {
      label: "Completion evidence",
      status: "complete",
      detail: "4 of 5 planned case runs recorded · status complete",
    },
  ]);
  assert.equal(qualityFraction(experiment(headline)), "3 / 4 cases");
  assert.equal(
    gateObservations(experiment({ budget_exhausted_count: 2 }))[1].status,
    "findings",
  );
  assert.equal(
    gateObservations(experiment({ gate_status: "failed" }))[2].status,
    "failed",
  );
  assert.equal(
    gateObservations(experiment({ status: "running" }))[3].detail,
    "Run status: running; planned and completed counts unavailable.",
  );
});

test("descriptive points use matching complete reports with measured accuracy and cost", () => {
  const measured: Headline = {
    status: "complete",
    accuracy: 0.8,
    cost_usd_per_case: 0,
  };
  const selected = experiment(measured);
  const reports = [
    selected,
    experiment(measured, { id: "other-agent", agent: "intake" }),
    experiment(measured, { id: "other-dataset", dataset: "other" }),
    experiment(measured, { id: "other-version", dataset_version: "v2" }),
    experiment({ ...measured, status: "running" }, { id: "incomplete" }),
    experiment({ status: "complete", accuracy: 0.8 }, { id: "no-cost" }),
    experiment(
      { status: "complete", cost_usd_per_case: 0 },
      { id: "no-accuracy" },
    ),
    experiment(
      { status: "complete", accuracy: 0.9, cost_usd_per_case: 0.2 },
      { id: "measured" },
    ),
  ];
  assert.deepEqual(
    comparisonPoints(reports, selected).map(
      ({ experiment, accuracy, cost }) => [experiment.id, accuracy, cost],
    ),
    [
      ["report-a", 0.8, 0],
      ["measured", 0.9, 0.2],
    ],
  );
  assert.deepEqual(comparisonPoints(reports), []);
});

test("case cost distinguishes explicitly measured zero from unknown or legacy zero", () => {
  assert.equal(caseCost(caseRecord()), null);
  assert.equal(
    caseCost(caseRecord({ cost_status: "unknown" }, { cost_usd: 1 })),
    null,
  );
  assert.equal(caseCost(caseRecord({ cost_status: "known_zero" })), 0);
  assert.equal(caseCost(caseRecord({ cost_usd: 0 })), 0);
  assert.equal(caseCost(caseRecord({ cost_usd: 0.2 }, { cost_usd: 1 })), 0.2);
  assert.equal(caseCost(caseRecord({}, { cost_usd: 1 })), 1);
});

test("case resources use observed totals or complete token pairs, with direct measurement precedence", () => {
  assert.equal(
    caseNumber(
      { tokens: 0, usage: { total_tokens: 100 } },
      "total_tokens",
      "tokens",
    ),
    0,
  );
  const cases = [
    caseRecord({ total_tokens: 0, latency_s: 30 }, { latency_s: 1 }),
    caseRecord({ usage: { input_tokens: 10, output_tokens: 5, latency_s: 2 } }),
    caseRecord({ input_tokens: 20 }),
    caseRecord({ total_tokens: "100", latency_s: Infinity }),
  ];
  assert.deepEqual(caseResources(cases), {
    latencies: [1, 2],
    tokens: [0, 15],
  });
  assert.deepEqual(caseResources(), { latencies: [], tokens: [] });
});

test("resource percentiles use nearest rank without mutating recorded observations", () => {
  const values = [8, 2, 4, 6];
  assert.equal(percentile(values, 0.5), 4);
  assert.equal(percentile(values, 0.95), 8);
  assert.deepEqual(values, [8, 2, 4, 6]);
  assert.equal(percentile([], 0.5), null);
});
