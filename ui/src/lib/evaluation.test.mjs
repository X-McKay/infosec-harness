import assert from "node:assert/strict";
import test from "node:test";
import {
  caseCost,
  caseNumber,
  caseResources,
  comparisonPoints,
  gateObservations,
  metricNumber,
  numeric,
  percentile,
  qualityFraction,
  record,
  text,
} from "./evaluation.ts";

// Small report-shaped fixtures exercise interpretation only, never operational data.
const experiment = (metrics = {}, fields = {}) => ({
  id: "report-a",
  agent: "verdict",
  dataset: "triage",
  dataset_version: "v1",
  metrics,
  ...fields,
});
const caseRecord = (scores = {}, fields = {}) => ({
  scores,
  cost_usd: 0,
  latency_s: null,
  ...fields,
});

test("metric interpretation accepts finite measurements without coercing absent data", () => {
  for (const invalid of [null, undefined, "1", NaN, Infinity, -Infinity])
    assert.equal(numeric(invalid), null);
  assert.equal(numeric(0), 0);
  assert.equal(text(""), null);
  assert.equal(text(1), null);
  assert.equal(text("complete"), "complete");
  assert.deepEqual(record([1]), {});
  assert.deepEqual(record(null), {});
  assert.deepEqual(record({ n: 0 }), { n: 0 });
  assert.equal(
    metricNumber({ accuracy: 0, distributions: { accuracy: 1 } }, "accuracy"),
    0,
  );
  assert.equal(
    metricNumber(
      { accuracy_mean: 1, distributions: { accuracy: 0.5 } },
      "accuracy",
      "accuracy_mean",
    ),
    0.5,
  );
  assert.equal(
    metricNumber(
      { accuracy: "1", distributions: { accuracy: 0.5 } },
      "accuracy",
    ),
    0.5,
  );
  assert.equal(metricNumber({}, "accuracy"), null);
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
      detail: "No budget enforcement counters were recorded.",
    },
    {
      label: "Completion evidence",
      status: "unknown",
      detail: "No completion status was recorded.",
    },
  ]);
  assert.equal(qualityFraction({}), undefined);
  const quality = gateObservations(experiment({ accuracy: 0.8 }))[0];
  assert.equal(quality.status, "unknown");
  assert.equal(quality.detail, "80.0% accuracy; case numerator unavailable.");
});

test("recorded gates retain measured fractions, budget findings, and completion counts", () => {
  const metrics = {
    accuracy: 0.75,
    passed: 3,
    n: 4,
    n_planned: 5,
    status: "complete",
    budget_enforcement_violations: 0,
    unexpected_budget_stops: 0,
    expected_budget_stops: 1,
  };
  assert.deepEqual(gateObservations(experiment(metrics)), [
    {
      label: "Quality evidence",
      status: "recorded",
      detail: "3 / 4 cases passed · 75.0% accuracy",
    },
    {
      label: "Budget evidence",
      status: "clear",
      detail:
        "0 enforcement violations · 0 unexpected stops · 1 expected stops",
    },
    {
      label: "Completion evidence",
      status: "complete",
      detail: "4 of 5 planned case runs recorded · status complete",
    },
  ]);
  assert.equal(qualityFraction(metrics), "3 / 4 cases");
  assert.equal(
    gateObservations(experiment({ unexpected_budget_stops: 1 }))[1].status,
    "findings",
  );
  assert.equal(
    gateObservations(experiment({ budget_enforcement_violations: 0 }))[1]
      .status,
    "findings",
  );
  assert.equal(
    gateObservations(experiment({ status: "running" }))[2].detail,
    "Run status: running; planned and completed counts unavailable.",
  );
});

test("descriptive points use matching complete reports with measured accuracy and cost", () => {
  const measured = { status: "complete", accuracy: 0.8, cost_usd_per_case: 0 };
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
      {
        status: "complete",
        distributions: { accuracy_mean: 0.9, mean_cost_usd: 0.2 },
      },
      { id: "nested" },
    ),
  ];
  assert.deepEqual(
    comparisonPoints(reports, selected).map(
      ({ experiment, accuracy, cost }) => [experiment.id, accuracy, cost],
    ),
    [
      ["report-a", 0.8, 0],
      ["nested", 0.9, 0.2],
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
