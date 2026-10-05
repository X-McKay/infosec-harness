import type { ExperimentCase } from "@/api/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { integer, money, percent, seconds } from "@/lib/format";
import {
  caseCost,
  caseResources,
  percentile,
  type ComparisonPoint,
} from "@/lib/evaluation";

export function ResourceDistribution({ cases }: { cases?: ExperimentCase[] }) {
  const { latencies, tokens } = caseResources(cases);
  const rows = [
    { label: "Tokens", values: tokens, format: integer },
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
                    <td>{row.format(p50)}</td>
                    <td>{row.format(p95)}</td>
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
                {cases.map((item, index) => (
                  <tr key={`${item.case_name}-${item.repetition}-${index}`}>
                    <th scope="row">{item.case_name}</th>
                    <td>{item.repetition}</td>
                    <td>{item.passed ? "Passed" : "Failed"}</td>
                    <td>{seconds(item.latency_s)}</td>
                    <td>{money(caseCost(item))}</td>
                  </tr>
                ))}
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

export function Scatter({ points }: { points: ComparisonPoint[] }) {
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
                {percent(point.accuracy)} · {money(point.cost)}
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
