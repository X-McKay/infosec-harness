import type { MetricsResponse, StageMetric, TrendPoint } from "@/api/client";
import { queries } from "@/api/queries";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { DistributionChart } from "@/components/DistributionChart";
import { Freshness, QueryState } from "@/components/QueryState";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { integer, money, number, percent, seconds } from "@/lib/format";

const TOKEN_METRICS = {
  tokens: "total_tokens",
  input_tokens: "input_tokens",
  output_tokens: "output_tokens",
} as const;

export function Metrics() {
  const [tokenMetric, setTokenMetric] =
    useState<keyof typeof TOKEN_METRICS>("tokens");
  const query = useQuery(queries.metrics());
  const metrics = query.data;

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="eyebrow">System performance</p>
          <h1>Metrics</h1>
          <p className="mt-2 text-sm text-muted-foreground">
            Understand resource use, tail latency, and measurement coverage.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <p className="text-xs text-muted-foreground">Operational records</p>
          <Button
            variant="outline"
            disabled={query.isFetching}
            onClick={() => void query.refetch()}
          >
            Refresh
          </Button>
        </div>
      </header>
      {!metrics && (
        <QueryState
          loading={query.isPending}
          error={query.error}
          retry={() => void query.refetch()}
        />
      )}
      {metrics && (
        <>
          <Freshness
            at={metrics.as_of}
            fetching={query.isFetching}
            stale={query.isError}
          />
          <SummaryCards metrics={metrics} />
          <label className="flex items-center gap-2 text-sm">
            Token measure
            <select
              className="field"
              value={tokenMetric}
              onChange={(event) =>
                setTokenMetric(event.target.value as typeof tokenMetric)
              }
            >
              <option value="tokens">Total tokens</option>
              <option value="input_tokens">Input tokens</option>
              <option value="output_tokens">Output tokens</option>
            </select>
            <span className="text-xs text-muted-foreground">
              Select a bar or table range to inspect its runs.
            </span>
          </label>
          <div className="grid gap-5 lg:grid-cols-3">
            <DistributionChart
              title="Token distribution"
              unit="tokens"
              data={metrics[tokenMetric]}
              metric={TOKEN_METRICS[tokenMetric]}
            />
            <DistributionChart
              title="Cost distribution"
              unit="USD inference cost"
              data={metrics.cost_usd}
              format={money}
              metric="cost_usd"
            />
            <DistributionChart
              title="Elapsed time distribution"
              unit="elapsed seconds"
              data={metrics.wall_time_s}
              format={seconds}
              metric="wall_time_s"
            />
          </div>
          <div className="grid gap-5 lg:grid-cols-2">
            <TrendCard trends={metrics.trends} />
            <StageCard stages={metrics.stages} />
          </div>
          <Definitions definitions={metrics.definitions} />
        </>
      )}
    </div>
  );
}

function SummaryCards({ metrics }: { metrics: MetricsResponse }) {
  const cards = [
    ["Runs", integer(metrics.total_runs)],
    ["Mean tokens", number(metrics.tokens.mean)],
    ["Mean cost", money(metrics.cost_usd.mean)],
    ["Mean elapsed", seconds(metrics.wall_time_s.mean)],
  ];
  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      {cards.map(([label, value]) => (
        <Card key={label}>
          <CardContent className="pt-5">
            <p className="text-xs text-muted-foreground">{label}</p>
            <p className="mt-2 text-2xl font-medium tabular-nums">{value}</p>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function TrendCard({ trends }: { trends: TrendPoint[] }) {
  const measured = trends.filter((day) => day.tokens != null);
  const max = Math.max(1, ...measured.map((day) => day.tokens || 0));
  const x = (index: number) =>
    30 + (index * 440) / Math.max(1, trends.length - 1);
  const y = (value: number) => 120 - (value / max) * 90;
  const segments: TrendPoint[][] = [];
  for (const day of trends) {
    if (day.tokens == null) continue;
    const previous = segments.at(-1);
    if (
      previous &&
      trends.indexOf(day) === trends.indexOf(previous.at(-1)!) + 1
    )
      previous.push(day);
    else segments.push([day]);
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle>Daily means · UTC</CardTitle>
        <p className="text-xs text-muted-foreground">
          {measured.length} of {trends.length} days have a recorded token mean;
          gaps remain unconnected.
        </p>
      </CardHeader>
      <CardContent>
        {trends.length ? (
          <>
            <svg
              viewBox="0 0 520 165"
              className="h-40 w-full"
              role="img"
              aria-label="Daily mean token trend; unavailable days are not plotted"
            >
              <line
                x1="30"
                y1="120"
                x2="470"
                y2="120"
                stroke="currentColor"
                className="text-border"
              />
              <line
                x1="30"
                y1="30"
                x2="30"
                y2="120"
                stroke="currentColor"
                className="text-border"
              />
              <text
                x="25"
                y="124"
                textAnchor="end"
                className="fill-muted-foreground text-[10px]"
              >
                0
              </text>
              <text
                x="25"
                y="34"
                textAnchor="end"
                className="fill-muted-foreground text-[10px]"
              >
                {integer(max)}
              </text>
              {segments.map((segment, index) => (
                <polyline
                  key={index}
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  className="text-primary"
                  points={segment
                    .map(
                      (day) =>
                        `${x(trends.indexOf(day))},${y(day.tokens || 0)}`,
                    )
                    .join(" ")}
                />
              ))}
              {measured.map((day) => (
                <circle
                  key={day.date}
                  cx={x(trends.indexOf(day))}
                  cy={y(day.tokens || 0)}
                  r="4"
                  className="fill-primary"
                >
                  <title>
                    {day.date}: {number(day.tokens)} mean tokens
                  </title>
                </circle>
              ))}
              <text
                x="30"
                y="143"
                className="fill-muted-foreground text-[10px]"
              >
                {trends[0]?.date || ""}
              </text>
              <text
                x="470"
                y="143"
                textAnchor="end"
                className="fill-muted-foreground text-[10px]"
              >
                {trends.at(-1)?.date || ""}
              </text>
              <text
                x="250"
                y="160"
                textAnchor="middle"
                className="fill-muted-foreground text-[10px]"
              >
                date (UTC)
              </text>
              <text
                x="8"
                y="80"
                textAnchor="middle"
                transform="rotate(-90 8 80)"
                className="fill-muted-foreground text-[10px]"
              >
                mean tokens
              </text>
            </svg>
            <div className="overflow-auto">
              <table className="data-table">
                <caption className="sr-only">
                  Daily means and observation coverage
                </caption>
                <thead>
                  <tr>
                    <th scope="col">Date</th>
                    <th scope="col">Runs</th>
                    <th scope="col">Mean tokens</th>
                    <th scope="col">Mean cost</th>
                    <th scope="col">Mean elapsed</th>
                  </tr>
                </thead>
                <tbody>
                  {trends.map((day) => (
                    <tr key={day.date}>
                      <td>{day.date}</td>
                      <td>{integer(day.runs)}</td>
                      <td>{number(day.tokens)}</td>
                      <td>{money(day.cost_usd)}</td>
                      <td>{seconds(day.wall_time_s)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        ) : (
          <p className="empty">No trend observations yet.</p>
        )}
      </CardContent>
    </Card>
  );
}

function StageCard({ stages }: { stages: StageMetric[] }) {
  const maximum = Math.max(1, ...stages.map((stage) => stage.agent_time_s));
  return (
    <Card>
      <CardHeader>
        <CardTitle>Agent resource breakdown</CardTitle>
        <p className="text-xs text-muted-foreground">
          Summed invocation time; concurrent stages can overlap.
        </p>
      </CardHeader>
      <CardContent className="space-y-4">
        {stages.length ? (
          stages.map((stage) => (
            <div key={stage.agent}>
              <div className="mb-2 flex justify-between text-sm">
                <span>{stage.agent}</span>
                <span className="text-muted-foreground">
                  {seconds(stage.agent_time_s)} · {integer(stage.tokens)} tokens
                </span>
              </div>
              <div className="h-2 rounded bg-muted">
                <div
                  className="h-2 rounded bg-primary/70"
                  style={{ width: `${(stage.agent_time_s / maximum) * 100}%` }}
                />
              </div>
              <p className="mt-1 text-xs text-muted-foreground">
                {integer(stage.invocations)} calls ·{" "}
                {money(stage.known_cost_usd)} known cost ·{" "}
                {percent(stage.cost_coverage)} coverage
              </p>
            </div>
          ))
        ) : (
          <p className="empty">No recorded invocations yet.</p>
        )}
      </CardContent>
    </Card>
  );
}

function Definitions({ definitions }: { definitions: Record<string, string> }) {
  return (
    <details className="rounded-lg border p-4 text-sm">
      <summary className="cursor-pointer">
        Metric definitions and limitations
      </summary>
      <dl className="mt-4 space-y-3">
        {Object.entries(definitions).map(([key, value]) => (
          <div key={key}>
            <dt className="font-medium capitalize">{key}</dt>
            <dd className="text-muted-foreground">{value}</dd>
          </div>
        ))}
      </dl>
    </details>
  );
}
