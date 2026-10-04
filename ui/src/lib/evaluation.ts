import type {
  ExperimentCase,
  ExperimentDetail,
  ExperimentSummary,
} from "../api/client";

export type Metrics = ExperimentSummary["metrics"];
export type Experiment = ExperimentSummary;
export type { ExperimentCase, ExperimentDetail };
export type Gate = { label: string; status: string; detail: string };

export const text = (value: unknown): string | null =>
  typeof value === "string" && value ? value : null;
export const numeric = (value: unknown): number | null =>
  typeof value === "number" && Number.isFinite(value) ? value : null;
export const record = (value: unknown): Metrics =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Metrics)
    : {};
export function metricNumber(metrics: Metrics, ...keys: string[]) {
  for (const key of keys) {
    const value =
      numeric(metrics[key]) ?? numeric(record(metrics.distributions)[key]);
    if (value != null) return value;
  }
  return null;
}
export function gateObservations(experiment: Experiment): Gate[] {
  const metrics = experiment.metrics;
  const total = metricNumber(metrics, "n", "cases_completed");
  const passed = metricNumber(metrics, "passed");
  const accuracy = metricNumber(metrics, "accuracy", "accuracy_mean");
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
          ? `${passed} / ${total} cases passed · ${((accuracy ?? 0) * 100).toFixed(1)}% accuracy`
          : accuracy == null
            ? "No accuracy measurement was recorded."
            : `${(accuracy * 100).toFixed(1)}% accuracy; case numerator unavailable.`,
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

export function qualityFraction(metrics: Metrics) {
  const passed = metricNumber(metrics, "passed");
  const total = metricNumber(metrics, "n", "cases_completed");
  return passed != null && total != null
    ? `${passed} / ${total} cases`
    : undefined;
}

export function comparisonPoints(
  experiments: Experiment[],
  selected?: Experiment,
) {
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
      accuracy: metricNumber(experiment.metrics, "accuracy", "accuracy_mean"),
      cost: metricNumber(
        experiment.metrics,
        "cost_usd_per_case",
        "mean_cost_usd",
      ),
    }))
    .filter(
      (
        item,
      ): item is { experiment: Experiment; accuracy: number; cost: number } =>
        item.accuracy != null && item.cost != null,
    );
}

export function caseNumber(scores: Metrics, ...keys: string[]) {
  for (const key of keys) {
    const direct = numeric(scores[key]);
    if (direct != null) return direct;
  }
  const usage = record(scores.usage);
  for (const key of keys) {
    const nested = numeric(usage[key]);
    if (nested != null) return nested;
  }
  return null;
}

export function caseCost(item: ExperimentCase) {
  const observed = numeric(item.scores.cost_usd);
  const status =
    typeof item.scores.cost_status === "string"
      ? item.scores.cost_status
      : null;
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
