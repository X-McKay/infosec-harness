import { useQueries, useQuery } from "@tanstack/react-query";
import { Freshness, QueryState } from "@/components/QueryState";
import { Button } from "@/components/ui/button";
import { SeriesChart, type SeriesPoint } from "@/components/evaluations/charts";
import {
  GateBadge,
  GateTable,
  Section,
  StatusBadge,
  Tile,
} from "@/components/evaluations/common";
import { EvalLink } from "@/components/evaluations/links";
import { reportQuery, reportsQuery } from "@/components/evaluations/queries";
import {
  cohortUnfinished,
  gateRows,
  measured,
  percentile,
  successFraction,
  unsafeNegativeCount,
} from "@/lib/evaluation";
import { integer, percent, seconds, timestamp } from "@/lib/format";
import {
  reportPath,
  type CohortReport,
  type ReportSummary,
} from "@/lib/reports";

/** Detail documents fetched for the cross-cohort view; the newest cohorts only. */
const MAX_COHORTS = 20;

type Cohort = { summary: ReportSummary; report: CohortReport | null };

/**
 * Trends across full-corpus cohorts (`model-*` reports). Diagnostic subsets are excluded:
 * they never qualify and their rates are over a hand-picked selection.
 */
export function Metrics() {
  const list = useQuery(reportsQuery());
  const summaries = (list.data?.items ?? [])
    .filter((report) => report.kind === "model")
    .slice(0, MAX_COHORTS);
  const details = useQueries({
    queries: summaries.map((summary) => reportQuery(summary.name)),
  });
  // Oldest first for the series; the list arrives newest first.
  const cohorts: Cohort[] = summaries
    .map((summary, index) => {
      const document = details[index]?.data?.document;
      return {
        summary,
        report: document?.shape === "cohort" ? document.report : null,
      };
    })
    .reverse();
  const failedDetails = details.filter((query) => query.isError).length;
  const loadingDetails = details.filter((query) => query.isPending).length;
  const latestComplete = [...cohorts]
    .reverse()
    .find(
      (cohort) =>
        (cohort.report?.gates.complete_corpus ??
          cohort.summary.gates.complete_corpus) === "passed",
    );
  const policy = cohorts.find((cohort) => cohort.report)?.report
    ?.release_policy;
  const minimum = policy?.minimum_task_success_rate ?? null;
  const maximum = policy?.maximum_unsafe_negatives ?? null;

  // Unfinished cohorts are partial: unstarted cases count against their rate.
  const unfinished = (cohort: Cohort) =>
    cohort.report
      ? cohortUnfinished(cohort.report)
      : cohort.summary.status === "running" ||
        (!!cohort.summary.started_at && !cohort.summary.finished_at);
  const label = (cohort: Cohort) =>
    `${cohort.summary.name}${unfinished(cohort) ? " (not finished, partial)" : ""}`;
  const rate = (cohort: Cohort) =>
    cohort.summary.task_success_rate ??
    (cohort.report ? successFraction(cohort.report).rate : null);
  const ratePoints: SeriesPoint[] = cohorts.map((cohort) => {
    const value = rate(cohort);
    return {
      key: cohort.summary.name,
      label: label(cohort),
      value,
      // An unfinished cohort's rate is partial: unstarted cases count against it.
      tone: unfinished(cohort)
        ? "muted"
        : minimum != null && value != null && value < minimum
          ? "bad"
          : undefined,
    };
  });
  const unsafePoints: SeriesPoint[] = cohorts.map((cohort) => {
    const value =
      cohort.summary.unsafe_negatives ??
      cohort.report?.unsafe_negatives ??
      (cohort.report ? unsafeNegativeCount(cohort.report.cases) : null);
    return {
      key: cohort.summary.name,
      label: label(cohort),
      value,
      tone: value && !unfinished(cohort) ? "bad" : "muted",
    };
  });
  const completionPoints: SeriesPoint[] = cohorts.map((cohort) => {
    const report = cohort.report;
    const fraction = report ? successFraction(report) : null;
    return {
      key: cohort.summary.name,
      label: label(cohort),
      value: cohort.summary.completed ?? fraction?.completed ?? null,
      total: cohort.summary.planned ?? fraction?.planned ?? null,
    };
  });
  const durationPoints: SeriesPoint[] = cohorts.map((cohort) => ({
    key: cohort.summary.name,
    label: label(cohort),
    value: cohort.report
      ? percentile(measured(cohort.report.cases, "duration"), 0.5)
      : null,
  }));

  const refresh = () => {
    void list.refetch();
    for (const query of details) void query.refetch();
  };
  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="eyebrow">Evaluation performance</p>
          <h1>Metrics</h1>
          <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
            Task success, unsafe negatives, completion and duration across the{" "}
            {MAX_COHORTS} most recent full-corpus cohorts. Diagnostic subsets
            are excluded.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Freshness
            at={list.data ? list.dataUpdatedAt : undefined}
            fetching={
              list.isFetching || details.some((query) => query.isFetching)
            }
            stale={list.isError && !!list.data}
          />
          <Button
            variant="outline"
            disabled={list.isFetching}
            onClick={refresh}
          >
            Refresh
          </Button>
        </div>
      </header>
      {!list.data && (
        <QueryState
          loading={list.isPending}
          error={list.error}
          retry={() => void list.refetch()}
        />
      )}
      {list.data && !summaries.length && (
        <Section title="No cohorts recorded">
          <p className="text-sm text-muted-foreground">
            No full-corpus cohort report exists yet. Run <code>./dev eval</code>{" "}
            to record one.
          </p>
        </Section>
      )}
      {summaries.length > 0 && (
        <>
          {(loadingDetails > 0 || failedDetails > 0) && (
            <p role="status" className="text-xs text-muted-foreground">
              {loadingDetails > 0 &&
                `Loading ${loadingDetails} cohort report(s)… `}
              {failedDetails > 0 &&
                `${failedDetails} cohort report(s) could not be loaded; their duration is shown as n/a.`}
            </p>
          )}
          <LatestComplete cohort={latestComplete} />
          <div className="grid gap-5 lg:grid-cols-2">
            <SeriesChart
              title="Task success rate"
              description="Correct over planned cases per cohort. Columns below the policy minimum are red."
              points={ratePoints}
              format={(value) => percent(value, 0)}
              maximum={1}
              reference={
                minimum != null
                  ? { value: minimum, label: `minimum ${percent(minimum, 0)}` }
                  : null
              }
            />
            <SeriesChart
              title="Unsafe negatives"
              description="Vulnerable cases judged not exploitable. The policy allows none above its maximum."
              points={unsafePoints}
              format={(value) => integer(value)}
              counts
              maximum={1}
              reference={
                maximum != null
                  ? { value: maximum, label: `maximum ${maximum}` }
                  : null
              }
            />
            <SeriesChart
              title="Completed of planned"
              description="Completed cases in front of the planned corpus size. A short column is an incomplete cohort, which cannot pass."
              points={completionPoints}
              format={(value) => integer(value)}
              counts
            />
            <SeriesChart
              title="Median case duration"
              description="Nearest-rank median over cases with a recorded duration."
              points={durationPoints}
              format={seconds}
            />
          </div>
        </>
      )}
    </div>
  );
}

function LatestComplete({ cohort }: { cohort: Cohort | undefined }) {
  if (!cohort)
    return (
      <Section
        title="Latest complete cohort"
        description="Release gates are evaluated only over a complete corpus."
      >
        <p className="text-sm text-muted-foreground">
          None of the recent cohorts completed the full corpus, so no release
          gate has been checked.
        </p>
      </Section>
    );
  const { summary, report } = cohort;
  const path = reportPath(summary.name);
  const fraction = report ? successFraction(report) : null;
  return (
    <Section
      title="Latest complete cohort"
      description="The newest cohort that completed every planned case, with its recorded gate states."
      action={<StatusBadge status={report?.status ?? summary.status} />}
    >
      <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.6fr)]">
        <div className="space-y-4">
          <p className="text-sm">
            {path ? (
              <EvalLink
                href={path}
                className="font-mono text-primary hover:underline"
              >
                {summary.name}
              </EvalLink>
            ) : (
              <span className="font-mono">{summary.name}</span>
            )}
            <span className="block text-xs text-muted-foreground">
              {summary.model ?? report?.model ?? "Model unavailable"} ·{" "}
              {timestamp(summary.finished_at ?? report?.finished_at)}
            </span>
          </p>
          <div className="grid grid-cols-2 gap-3">
            <Tile
              label="Task success"
              value={percent(summary.task_success_rate ?? fraction?.rate)}
              detail={
                fraction
                  ? `${fraction.correct} / ${fraction.planned} correct`
                  : undefined
              }
            />
            <Tile
              label="Unsafe negatives"
              value={integer(
                summary.unsafe_negatives ?? report?.unsafe_negatives,
              )}
              tone={
                (summary.unsafe_negatives ?? report?.unsafe_negatives)
                  ? "bad"
                  : undefined
              }
            />
          </div>
        </div>
        {report ? (
          <GateTable
            rows={gateRows(report)}
            caption="Latest complete cohort gate states"
          />
        ) : (
          <div className="space-y-2">
            <div className="flex flex-wrap gap-1">
              {Object.entries(summary.gates).map(([key, status]) => (
                <GateBadge
                  key={key}
                  status={status}
                  label={key.replaceAll("_", " ")}
                />
              ))}
            </div>
            <p className="text-xs text-muted-foreground">
              Gate states from the report list; the full report is not loaded.
            </p>
          </div>
        )}
      </div>
    </Section>
  );
}
