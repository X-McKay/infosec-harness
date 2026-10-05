import type { ExperimentCase, ExperimentSummary } from "../api/client.ts";
import { percent } from "./format.ts";
import { asRecord, numeric, text, type JsonRecord } from "./json.ts";

export type Gate = { label: string; status: string; detail: string };

/** A recorded metric, read directly or from the report's distributions block. */
export function metricNumber(metrics: JsonRecord, ...keys: string[]) {
  for (const key of keys) {
    const value =
      numeric(metrics[key]) ?? numeric(asRecord(metrics.distributions)[key]);
    if (value != null) return value;
  }
  return null;
}
export const accuracyOf = (metrics: JsonRecord) =>
  metricNumber(metrics, "accuracy", "accuracy_mean");
export const costPerCaseOf = (metrics: JsonRecord) =>
  metricNumber(metrics, "cost_usd_per_case");

export function gateObservations(experiment: ExperimentSummary): Gate[] {
  const metrics = experiment.metrics;
  const total = metricNumber(metrics, "n", "cases_completed");
  const passed = metricNumber(metrics, "passed");
  const accuracy = accuracyOf(metrics);
  const planned = metricNumber(metrics, "n_planned");
  const status = text(metrics.status);
  const violations = metricNumber(metrics, "budget_enforcement_violations");
  const unexpectedStops = metricNumber(metrics, "unexpected_budget_stops");
  const expectedStops = metricNumber(metrics, "expected_budget_stops");
  return [
    {
      label: "Quality evidence",
      status: accuracy != null && total != null ? "recorded" : "unknown",
      detail:
        passed != null && total != null
          ? `${passed} / ${total} cases passed · ${accuracy == null ? "accuracy unavailable" : `${percent(accuracy)} accuracy`}`
          : accuracy == null
            ? "No accuracy measurement was recorded."
            : `${percent(accuracy)} accuracy; case numerator unavailable.`,
    },
    {
      label: "Budget evidence",
      status:
        violations == null && unexpectedStops == null
          ? "unknown"
          : violations === 0 && unexpectedStops === 0
            ? "clear"
            : "findings",
      detail:
        violations == null && unexpectedStops == null
          ? "No budget enforcement counters were recorded."
          : `${violations ?? 0} enforcement violations · ${unexpectedStops ?? 0} unexpected stops · ${expectedStops ?? 0} expected stops`,
    },
    {
      label: "Completion evidence",
      status: status || "unknown",
      detail:
        total != null && planned != null
          ? `${total} of ${planned} planned case runs recorded${status ? ` · status ${status}` : ""}`
          : status
            ? `Run status: ${status}; planned and completed counts unavailable.`
            : "No completion status was recorded.",
    },
  ];
}

export function qualityFraction(metrics: JsonRecord) {
  const passed = metricNumber(metrics, "passed");
  const total = metricNumber(metrics, "n", "cases_completed");
  return passed != null && total != null
    ? `${passed} / ${total} cases`
    : undefined;
}

export type ComparisonPoint = {
  experiment: ExperimentSummary;
  accuracy: number;
  cost: number;
};
export function comparisonPoints(
  experiments: ExperimentSummary[],
  selected?: ExperimentSummary,
): ComparisonPoint[] {
  const cohort = selected
    ? experiments.filter(
        (item) =>
          item.agent === selected.agent &&
          item.dataset === selected.dataset &&
          item.dataset_version === selected.dataset_version &&
          text(item.metrics.status) === "complete",
      )
    : [];
  return cohort
    .map((experiment) => ({
      experiment,
      accuracy: accuracyOf(experiment.metrics),
      cost: costPerCaseOf(experiment.metrics),
    }))
    .filter(
      (item): item is ComparisonPoint =>
        item.accuracy != null && item.cost != null,
    );
}

export function caseNumber(scores: JsonRecord, ...keys: string[]) {
  for (const key of keys) {
    const direct = numeric(scores[key]);
    if (direct != null) return direct;
  }
  const usage = asRecord(scores.usage);
  for (const key of keys) {
    const nested = numeric(usage[key]);
    if (nested != null) return nested;
  }
  return null;
}

export function caseCost(item: ExperimentCase) {
  const observed = numeric(item.scores.cost_usd);
  const status = text(item.scores.cost_status);
  if (observed != null) return observed;
  if (status === "known_zero") return 0;
  if (status === "unknown" || (item.cost_usd === 0 && !status)) return null;
  return item.cost_usd;
}

export function percentile(values: number[], quantile: number) {
  if (!values.length) return null;
  const ordered = [...values].sort((a, b) => a - b);
  return ordered[Math.max(0, Math.ceil(ordered.length * quantile) - 1)];
}

export function caseResources(cases: ExperimentCase[] = []) {
  const latencies = cases
    .map((item) => item.latency_s ?? caseNumber(item.scores, "latency_s"))
    .filter((value): value is number => value != null);
  const tokens = cases
    .map((item) => {
      const total = caseNumber(item.scores, "total_tokens", "tokens");
      if (total != null) return total;
      const input = caseNumber(item.scores, "input_tokens");
      const output = caseNumber(item.scores, "output_tokens");
      return input != null && output != null ? input + output : null;
    })
    .filter((value): value is number => value != null);
  return { latencies, tokens };
}
