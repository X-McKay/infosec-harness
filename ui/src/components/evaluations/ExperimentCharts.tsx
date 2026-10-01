import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { money, seconds } from "@/lib/format";
import type { Experiment, ExperimentCase, Metrics } from "./ExperimentReport";

const numeric = (value: unknown): number | null =>
  typeof value === "number" && Number.isFinite(value) ? value : null;
const record = (value: unknown): Metrics =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Metrics)
    : {};

function caseNumber(scores: Metrics, ...keys: string[]) {
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

function caseCost(item: ExperimentCase) {
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

function percentile(values: number[], quantile: number) {
  if (!values.length) return null;
  const ordered = [...values].sort((a, b) => a - b);
  return ordered[Math.max(0, Math.ceil(ordered.length * quantile) - 1)];
}

export function ResourceDistribution({ cases }: { cases?: ExperimentCase[] }) {
  const latencies = (cases || [])
    .map((item) => item.latency_s ?? caseNumber(item.scores, "latency_s"))
    .filter((value): value is number => value != null);
  const tokens = (cases || [])
    .map((item) => {
      const total = caseNumber(item.scores, "total_tokens", "tokens");
      if (total != null) return total;
      const input = caseNumber(item.scores, "input_tokens");
      const output = caseNumber(item.scores, "output_tokens");
      return input != null && output != null ? input + output : null;
    })
    .filter((value): value is number => value != null);
  const rows = [
    {
      label: "Tokens",
      values: tokens,
      format: (value: number) => Math.round(value).toLocaleString(),
    },
    { label: "Latency", values: latencies, format: seconds },
  ];
  return (
    <Card>
      <CardHeader>
        <CardTitle>Case resource observations</CardTitle>
        <p className="text-xs text-muted-foreground">
          Percentiles use the nearest-rank method over case records with the
          requested measurement, matching the evaluation reports.
        </p>
      </CardHeader>
      <CardContent>
        <div className="overflow-auto">
          <table className="data-table">
            <caption className="sr-only">
              Observed token and latency distributions by case
            </caption>
            <thead>
              <tr>
                <th scope="col">Measure</th>
                <th scope="col">Cases</th>
                <th scope="col">p50</th>
                <th scope="col">p95</th>
                <th scope="col">Range</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const p50 = percentile(row.values, 0.5);
                const p95 = percentile(row.values, 0.95);
                return (
                  <tr key={row.label}>
                    <th scope="row">{row.label}</th>
                    <td>
                      {row.values.length
                        ? `${row.values.length} / ${(cases || []).length}`
                        : "Unavailable"}
                    </td>
                    <td>{p50 == null ? "Unavailable" : row.format(p50)}</td>
                    <td>{p95 == null ? "Unavailable" : row.format(p95)}</td>
                    <td>
                      {row.values.length
                        ? `${row.format(Math.min(...row.values))} – ${row.format(Math.max(...row.values))}`
                        : "Unavailable"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

export function CaseTable({ cases }: { cases?: ExperimentCase[] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Case completion</CardTitle>
      </CardHeader>
      <CardContent>
        {cases?.length ? (
          <div className="overflow-auto">
            <table className="data-table">
              <caption className="sr-only">Case completion records</caption>
              <thead>
                <tr>
                  <th scope="col">Case</th>
                  <th scope="col">Rep</th>
                  <th scope="col">Result</th>
                  <th scope="col">Latency</th>
                  <th scope="col">Cost</th>
                </tr>
              </thead>
              <tbody>
                {cases.map((item, index) => {
                  const cost = caseCost(item);
                  return (
                    <tr key={`${item.case_name}-${item.repetition}-${index}`}>
                      <th scope="row">{item.case_name}</th>
                      <td>{item.repetition}</td>
                      <td>{item.passed ? "Passed" : "Failed"}</td>
                      <td>
                        {item.latency_s == null
                          ? "Unavailable"
                          : seconds(item.latency_s)}
                      </td>
                      <td>{cost == null ? "Unavailable" : money(cost)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="empty">Case-level completion data was not included.</p>
        )}
      </CardContent>
    </Card>
  );
}

export function Scatter({
  points,
}: {
  points: Array<{ experiment: Experiment; accuracy: number; cost: number }>;
}) {
  const maxCost = Math.max(...points.map((point) => point.cost), 0.0001);
  return (
    <div className="space-y-3">
      <svg
        viewBox="0 0 520 240"
        className="h-56 w-full"
        role="img"
        aria-label="Accuracy and cost comparison scatter plot"
      >
        <line
          x1="45"
          y1="205"
          x2="500"
          y2="205"
          stroke="currentColor"
          className="text-border"
        />
        <line
          x1="45"
          y1="20"
          x2="45"
          y2="205"
          stroke="currentColor"
          className="text-border"
        />
        <text
          x="260"
          y="232"
          textAnchor="middle"
          className="fill-muted-foreground text-[11px]"
        >
          Cost per case
        </text>
        <text
          x="14"
          y="115"
          textAnchor="middle"
          transform="rotate(-90 14 115)"
          className="fill-muted-foreground text-[11px]"
        >
          Accuracy
        </text>
        {points.map((point) => {
          const x = 55 + (point.cost / maxCost) * 430;
          const y = 195 - Math.max(0, Math.min(1, point.accuracy)) * 165;
          return (
            <circle
              key={point.experiment.id}
              cx={x}
              cy={y}
              r="6"
              className="fill-primary stroke-background"
              strokeWidth="2"
            >
              <title>
                {point.experiment.agent} ·{" "}
                {point.experiment.model_name || "model unavailable"} ·{" "}
                {(point.accuracy * 100).toFixed(1)}% · {money(point.cost)}
              </title>
            </circle>
          );
        })}
      </svg>
      <div className="space-y-1 text-xs text-muted-foreground">
        {points.map((point) => (
          <p key={point.experiment.id}>
            <span className="mr-2 inline-block h-2 w-2 rounded-full bg-primary" />
            {point.experiment.agent} ·{" "}
            {point.experiment.model_name || "model unavailable"}
          </p>
        ))}
      </div>
    </div>
  );
}
