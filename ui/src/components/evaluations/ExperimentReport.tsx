import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { QueryState } from "@/components/QueryState";
import type { ExperimentCase, ExperimentDetail } from "@/api/client";
import { money, seconds, timestamp } from "@/lib/format";
import { CaseTable, ResourceDistribution, Scatter } from "./ExperimentCharts";

import {
  comparisonPoints,
  gateObservations,
  metricNumber,
  qualityFraction,
  record,
  text,
  type Experiment,
  type Metrics,
} from "@/lib/evaluation";

// Retain the report's exports for existing consumers; interpretation lives in
// the React-independent evaluation module.
export {
  gateObservations,
  metricNumber,
  numeric,
  record,
  text,
} from "@/lib/evaluation";
export type { Experiment, Gate, Metrics } from "@/lib/evaluation";
export type { ExperimentCase, ExperimentDetail };

export function ExperimentContent({
  experiments,
  selected,
  setSelectedId,
  detail,
  detailQuery,
}: {
  experiments: Experiment[];
  selected?: Experiment;
  setSelectedId: (id: string) => void;
  detail?: ExperimentDetail;
  detailQuery: {
    isError: boolean;
    error: unknown;
    refetch: () => Promise<unknown>;
  };
}) {
  const points = comparisonPoints(experiments, selected);
  const confusion = record(
    (detail?.metrics || selected?.metrics || {}).confusion,
  );
  return (
    <>
      <ExperimentTable
        experiments={experiments}
        selected={selected}
        onSelect={setSelectedId}
      />
      <div className="grid gap-5 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Descriptive efficacy / cost comparison</CardTitle>
            <p className="text-xs text-muted-foreground">
              Same agent, dataset, and version; complete experiments with
              recorded accuracy and cost only. This related-run view does not
              establish release comparability or compute a frontier; use the
              strict comparison report for an eligibility decision.
            </p>
          </CardHeader>
          <CardContent>
            {points.length ? (
              <Scatter points={points} />
            ) : (
              <p className="empty">
                No related completed runs have both accuracy and cost
                measurements.
              </p>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Selected experiment</CardTitle>
          </CardHeader>
          <CardContent className="space-y-5">
            {selected && <Metadata experiment={selected} />}
            {selected && <ProvenanceNotice experiment={selected} />}
            {selected && <GateSummary experiment={selected} />}
            {detailQuery.isError && (
              <QueryState
                error={
                  detailQuery.error instanceof Error
                    ? detailQuery.error
                    : new Error("Experiment detail unavailable")
                }
                retry={() => void detailQuery.refetch()}
              />
            )}
          </CardContent>
        </Card>
      </div>
      {selected && (
        <SelectedMetrics experiment={selected} confusion={confusion} />
      )}
      {detail && (
        <>
          <ResourceDistribution cases={detail.cases} />
          <CaseTable cases={detail.cases} />
        </>
      )}
    </>
  );
}

function ExperimentTable({
  experiments,
  selected,
  onSelect,
}: {
  experiments: Experiment[];
  selected?: Experiment;
  onSelect: (id: string) => void;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Recorded eval runs</CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-auto">
          <table className="data-table">
            <caption className="sr-only">Recorded evaluation runs</caption>
            <thead>
              <tr>
                <th scope="col">Experiment</th>
                <th scope="col">Model / backend</th>
                <th scope="col">Config</th>
                <th scope="col">Completion</th>
                <th scope="col" className="text-right">
                  Accuracy
                </th>
                <th scope="col" className="text-right">
                  Cost / case
                </th>
                <th scope="col" className="text-right">
                  Latency p95
                </th>
              </tr>
            </thead>
            <tbody>
              {experiments.map((experiment) => (
                <ExperimentRow
                  key={experiment.id}
                  experiment={experiment}
                  selected={selected?.id === experiment.id}
                  onSelect={onSelect}
                />
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}
function ExperimentRow({
  experiment,
  selected,
  onSelect,
}: {
  experiment: Experiment;
  selected: boolean;
  onSelect: (id: string) => void;
}) {
  const accuracy = metricNumber(
    experiment.metrics,
    "accuracy",
    "accuracy_mean",
  );
  const cost = metricNumber(
    experiment.metrics,
    "cost_usd_per_case",
    "mean_cost_usd",
  );
  const latency = metricNumber(
    experiment.metrics,
    "p95_latency_s",
    "latency_p95_s",
  );
  return (
    <tr
      className={`cursor-pointer ${selected ? "bg-muted/60" : ""}`}
      onClick={() => onSelect(experiment.id)}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") onSelect(experiment.id);
      }}
      tabIndex={0}
    >
      <td>
        <p className="font-medium">{experiment.agent}</p>
        <p className="text-xs text-muted-foreground">
          {experiment.dataset}@{experiment.dataset_version}
        </p>
      </td>
      <td className="text-xs">
        {experiment.model_name || "Unavailable"}
        <br />
        <span className="text-muted-foreground">
          {experiment.backend || "backend unavailable"}
        </span>
      </td>
      <td className="font-mono text-xs">
        {experiment.config_hash
          ? experiment.config_hash.slice(0, 10)
          : "Unavailable"}
      </td>
      <td>
        <Badge variant="outline">
          {text(experiment.metrics.status) || "unknown"}
        </Badge>
      </td>
      <td className="text-right">
        {accuracy == null ? "Unavailable" : `${(accuracy * 100).toFixed(1)}%`}
      </td>
      <td className="text-right font-mono text-xs">
        {cost == null ? "Unavailable" : money(cost)}
      </td>
      <td className="text-right font-mono text-xs">
        {latency == null ? "Unavailable" : seconds(latency)}
      </td>
    </tr>
  );
}
function SelectedMetrics({
  experiment,
  confusion,
}: {
  experiment: Experiment;
  confusion: Metrics;
}) {
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Metric tradeoffs</CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-4">
          <Metric
            label="Accuracy"
            value={metricNumber(
              experiment.metrics,
              "accuracy",
              "accuracy_mean",
            )}
            suffix="%"
            multiplier={100}
            detail={qualityFraction(experiment.metrics)}
          />
          <Metric
            label="Cost / case"
            value={metricNumber(
              experiment.metrics,
              "cost_usd_per_case",
              "mean_cost_usd",
            )}
            format={money}
          />
          <Metric
            label="p50 latency"
            value={metricNumber(
              experiment.metrics,
              "p50_latency_s",
              "latency_p50_s",
            )}
            format={seconds}
          />
          <Metric
            label="p95 latency"
            value={metricNumber(
              experiment.metrics,
              "p95_latency_s",
              "latency_p95_s",
            )}
            format={seconds}
          />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Confusion evidence</CardTitle>
          <p className="text-xs text-muted-foreground">
            Reported by the selected experiment when available.
          </p>
        </CardHeader>
        <CardContent>
          {Object.keys(confusion).length ? (
            <div className="space-y-2">
              {Object.entries(confusion).map(([label, count]) => (
                <div
                  key={label}
                  className="flex justify-between border-b py-2 text-sm"
                >
                  <span className="font-mono">{label}</span>
                  <span>
                    {typeof count === "object"
                      ? JSON.stringify(count)
                      : String(count)}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="empty">
              No confusion data was included in this report.
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
function GateSummary({ experiment }: { experiment: Experiment }) {
  return (
    <section aria-labelledby="gate-observations" className="space-y-3">
      <div>
        <h2 id="gate-observations" className="text-sm font-semibold">
          Recorded gate observations
        </h2>
        <p className="text-xs text-muted-foreground">
          Evidence reported by this run; these rows do not make a promotion
          decision.
        </p>
      </div>
      <div className="space-y-2">
        {gateObservations(experiment).map((gate) => (
          <div key={gate.label} className="rounded-md border p-3">
            <div className="flex items-center justify-between gap-3">
              <p className="text-sm font-medium">{gate.label}</p>
              <Badge
                variant={
                  gate.status === "clear" ||
                  gate.status === "complete" ||
                  gate.status === "recorded"
                    ? "default"
                    : "outline"
                }
              >
                {gate.status}
              </Badge>
            </div>
            <p className="mt-1 text-xs text-muted-foreground">{gate.detail}</p>
          </div>
        ))}
      </div>
    </section>
  );
}
function ProvenanceNotice({ experiment }: { experiment: Experiment }) {
  const isStub =
    experiment.backend === "stub" || experiment.model_name?.startsWith("stub:");
  return isStub ? (
    <p className="rounded-md border border-amber-300/60 bg-amber-50/60 p-3 text-xs text-amber-950 dark:bg-amber-950/20 dark:text-amber-100">
      Stub provenance: this run uses the deterministic local stub backend. Its
      accuracy and cost figures exercise the harness and report shape; they are
      not model quality or provider billing measurements.
    </p>
  ) : null;
}
function Metadata({ experiment }: { experiment: Experiment }) {
  return (
    <dl className="grid grid-cols-2 gap-4 text-sm">
      <div>
        <dt className="text-xs text-muted-foreground">Model</dt>
        <dd>{experiment.model_name || "Unavailable"}</dd>
      </div>
      <div>
        <dt className="text-xs text-muted-foreground">Backend</dt>
        <dd>{experiment.backend || "Unavailable"}</dd>
      </div>
      <div>
        <dt className="text-xs text-muted-foreground">Git</dt>
        <dd className="break-all font-mono text-xs">
          {experiment.git_sha || "Unavailable"}
          {experiment.git_dirty == null
            ? ""
            : experiment.git_dirty
              ? " · dirty"
              : " · clean"}
        </dd>
      </div>
      <div>
        <dt className="text-xs text-muted-foreground">Harness</dt>
        <dd>{experiment.harness_version || "Unavailable"}</dd>
      </div>
      <div className="col-span-2">
        <dt className="text-xs text-muted-foreground">Recorded</dt>
        <dd>
          {timestamp(experiment.created_at)} · {experiment.repetitions}{" "}
          repetition(s)
        </dd>
      </div>
    </dl>
  );
}
function Metric({
  label,
  value,
  format,
  suffix,
  multiplier = 1,
  detail,
}: {
  label: string;
  value: number | null;
  format?: (value: number | null) => string;
  suffix?: string;
  multiplier?: number;
  detail?: string;
}) {
  const shown =
    value == null
      ? "Unavailable"
      : format
        ? format(value)
        : `${(value * multiplier).toFixed(1)}${suffix || ""}`;
  return (
    <div>
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="mt-1 font-medium tabular-nums">{shown}</p>
      {detail && <p className="mt-1 text-xs text-muted-foreground">{detail}</p>}
    </div>
  );
}
