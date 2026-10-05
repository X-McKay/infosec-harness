import type { UseQueryResult } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { QueryState } from "@/components/QueryState";
import type { ExperimentDetail, ExperimentSummary } from "@/api/client";
import { money, percent, seconds, timestamp } from "@/lib/format";
import { asRecord, type JsonRecord } from "@/lib/json";
import { CaseTable, ResourceDistribution, Scatter } from "./ExperimentCharts";

import {
  accuracyOf,
  comparisonPoints,
  costPerCaseOf,
  gateObservations,
  metricNumber,
  qualityFraction,
} from "@/lib/evaluation";

export function ExperimentContent({
  experiments,
  selected,
  setSelectedId,
  detailQuery,
}: {
  experiments: ExperimentSummary[];
  selected?: ExperimentSummary;
  setSelectedId: (id: string) => void;
  detailQuery: UseQueryResult<ExperimentDetail>;
}) {
  const detail = detailQuery.data;
  const points = comparisonPoints(experiments, selected);
  const confusion = asRecord(
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
                error={detailQuery.error}
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
  experiments: ExperimentSummary[];
  selected?: ExperimentSummary;
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
  experiment: ExperimentSummary;
  selected: boolean;
  onSelect: (id: string) => void;
}) {
  // The row is a mouse convenience; the button is the accessible control.
  return (
    <tr
      className={`cursor-pointer ${selected ? "bg-muted/60" : ""}`}
      onClick={() => onSelect(experiment.id)}
    >
      <td>
        <button
          type="button"
          className="text-left font-medium hover:underline"
          aria-pressed={selected}
          onClick={(event) => {
            event.stopPropagation();
            onSelect(experiment.id);
          }}
        >
          {experiment.agent}
        </button>
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
        <Badge variant="outline">{experiment.status ?? "unknown"}</Badge>
      </td>
      <td className="text-right">{percent(accuracyOf(experiment.metrics))}</td>
      <td className="text-right font-mono text-xs">
        {money(costPerCaseOf(experiment.metrics))}
      </td>
      <td className="text-right font-mono text-xs">
        {seconds(metricNumber(experiment.metrics, "p95_latency_s"))}
      </td>
    </tr>
  );
}
function SelectedMetrics({
  experiment,
  confusion,
}: {
  experiment: ExperimentSummary;
  confusion: JsonRecord;
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
            value={percent(accuracyOf(experiment.metrics))}
            detail={qualityFraction(experiment.metrics)}
          />
          <Metric
            label="Cost / case"
            value={money(costPerCaseOf(experiment.metrics))}
          />
          <Metric
            label="p50 latency"
            value={seconds(metricNumber(experiment.metrics, "p50_latency_s"))}
          />
          <Metric
            label="p95 latency"
            value={seconds(metricNumber(experiment.metrics, "p95_latency_s"))}
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
function GateSummary({ experiment }: { experiment: ExperimentSummary }) {
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
function ProvenanceNotice({ experiment }: { experiment: ExperimentSummary }) {
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
function Metadata({ experiment }: { experiment: ExperimentSummary }) {
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
  detail,
}: {
  label: string;
  value: string;
  detail?: string;
}) {
  return (
    <div>
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="mt-1 font-medium tabular-nums">{value}</p>
      {detail && <p className="mt-1 text-xs text-muted-foreground">{detail}</p>}
    </div>
  );
}
