import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import {
  breakdown,
  caseOutcome,
  cohortUnfinished,
  gateRows,
  headroomSummary,
  measured,
  pairRows,
  percentile,
  successFraction,
  sum,
  unsafeNegativeCount,
  type Breakdown,
} from "@/lib/evaluation";
import { integer, number, percent, seconds, timestamp } from "@/lib/format";
import { shortHash, type CohortReport } from "@/lib/reports";
import { CaseTable } from "./CaseTable";
import type { CaseFilters } from "@/lib/search";
import { CaseHistogram, RateBar } from "./charts";
import {
  Field,
  GateBadge,
  GateTable,
  Limitations,
  OutcomeBadge,
  Section,
  StatusBadge,
  Tile,
} from "./common";
import { FailureList } from "./Failures";

export function CohortReportView({
  report,
  caseFilters,
  onCaseFilters,
}: {
  report: CohortReport;
  caseFilters?: CaseFilters;
  onCaseFilters?: (filters: CaseFilters) => void;
}) {
  return (
    <div className="space-y-6">
      {report.kind === "diagnostic" && (
        <p className="rounded-md border border-amber-300/60 bg-amber-50/60 p-3 text-xs text-amber-950 dark:border-amber-500/30 dark:bg-amber-950/20 dark:text-amber-100">
          Diagnostic subset: selected cases only. Its gates stay not checked and
          it never qualifies a candidate, whatever its pass rate.
        </p>
      )}
      {cohortUnfinished(report) && (
        <p
          role="status"
          className="rounded-md border border-primary/30 bg-primary/5 p-3 text-xs"
        >
          This cohort has not finished: it is still running, or it was
          interrupted before recording its end. Figures cover the cases recorded
          so far and refresh automatically.
        </p>
      )}
      <Provenance report={report} />
      <div className="grid gap-5 xl:grid-cols-2">
        <Section
          title="Release gates"
          description="Evaluated by the harness over the complete corpus only. Not checked means no evidence, never a pass."
        >
          <GateTable rows={gateRows(report)} caption="Release gate states" />
        </Section>
        <CapacityCard report={report} />
      </div>
      <SummaryTiles report={report} />
      <Distributions report={report} />
      <div className="grid gap-5 2xl:grid-cols-2">
        <BreakdownCard
          title="Pass rate by language"
          rows={breakdown(report.cases, "language")}
          keyLabel="Language"
        />
        <BreakdownCard
          title="Pass rate by CWE topic"
          rows={breakdown(report.cases, "topic")}
          keyLabel="Topic"
        />
      </div>
      <PairTable report={report} />
      <CaseTable
        cases={report.cases}
        filters={caseFilters}
        onFilters={onCaseFilters}
      />
      <FailureList cases={report.cases} />
      <EstimateCard report={report} />
    </div>
  );
}

function Provenance({ report }: { report: CohortReport }) {
  const limits = report.limits;
  const identity = report.worker_identity;
  const dependencies = Object.entries(identity?.dependencies ?? {});
  const policy = report.release_policy;
  return (
    <Section
      title="Provenance"
      description="Recorded by the harness when the cohort started. Hashes are shortened; each copy button copies the full value, and the recorded document below holds them all."
      action={<StatusBadge status={report.status} />}
    >
      <dl className="grid grid-cols-2 gap-4 text-sm md:grid-cols-4">
        <Field
          label="Commit"
          mono
          copy={{ value: report.commit, label: "Copy commit" }}
        >
          {shortHash(report.commit) ?? "Unavailable"}
        </Field>
        <Field label="Generation">{report.generation ?? "Unavailable"}</Field>
        <Field label="Model">{report.model ?? "Unavailable"}</Field>
        <Field label="Task queue" mono>
          {report.task_queue ?? "Unavailable"}
          {report.owned_worker != null && (
            <span className="block font-sans text-muted-foreground">
              {report.owned_worker ? "owned worker" : "external worker"}
            </span>
          )}
        </Field>
        <Field label="Started">{timestamp(report.started_at)}</Field>
        <Field label="Finished">
          {report.finished_at ? timestamp(report.finished_at) : "Not finished"}
        </Field>
        <Field
          label="Dataset"
          mono
          copy={{ value: report.dataset_sha256, label: "Copy dataset SHA-256" }}
        >
          {shortHash(report.dataset_sha256) ?? "Unavailable"}
        </Field>
        <Field
          label="Runtime config"
          mono
          copy={{
            value: report.runtime_config_sha256,
            label: "Copy runtime config SHA-256",
          }}
        >
          {shortHash(report.runtime_config_sha256) ?? "Unavailable"}
        </Field>
        <Field
          label="Worker fingerprint"
          mono
          copy={{
            value: identity?.fingerprint,
            label: "Copy worker fingerprint",
          }}
        >
          {shortHash(identity?.fingerprint) ?? "Unavailable"}
        </Field>
        <Field label="Worker code / config" mono>
          {shortHash(identity?.code_sha256) ?? "—"} /{" "}
          {shortHash(identity?.config_sha256) ?? "—"}
        </Field>
        <Field label="Release policy">
          ≥ {percent(policy.minimum_task_success_rate ?? report.threshold)}{" "}
          success · ≤ {integer(policy.maximum_unsafe_negatives)} unsafe
          <span className="block font-mono text-xs text-muted-foreground">
            {shortHash(report.release_policy_sha256) ??
              "policy hash unavailable"}
          </span>
        </Field>
        <Field label="Limits per case">
          {integer(limits.max_requests)} requests ·{" "}
          {integer(limits.max_tool_calls)} tool calls ·{" "}
          {integer(limits.total_tokens)} tokens
          <span className="block text-xs text-muted-foreground">
            {seconds(limits.timeout_seconds)} run ·{" "}
            {seconds(limits.command_timeout_seconds)} per command
          </span>
        </Field>
      </dl>
      {report.error_type && (
        <p className="mt-4 text-sm">
          Cohort stopped with{" "}
          <span className="font-mono">{report.error_type}</span>.
        </p>
      )}
      {dependencies.length > 0 && (
        <details className="mt-4 text-xs">
          <summary className="cursor-pointer text-muted-foreground">
            Worker dependencies ({dependencies.length})
          </summary>
          <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 md:grid-cols-3">
            {dependencies.map(([name, version]) => (
              <div
                key={name}
                className="flex justify-between gap-2 border-b py-1"
              >
                <dt className="font-mono">{name}</dt>
                <dd className="font-mono text-muted-foreground">{version}</dd>
              </div>
            ))}
          </dl>
        </details>
      )}
    </Section>
  );
}

function CapacityCard({ report }: { report: CohortReport }) {
  const budget = report.native_operation_budget;
  const headroom = headroomSummary(budget);
  return (
    <Section
      title="Capacity pre-flight"
      description="Native admission headroom observed once, read-only, before any case started."
      action={<GateBadge status={headroom.status} />}
    >
      <div className="space-y-4">
        <p className="text-sm">{headroom.summary}</p>
        {headroom.quota != null && headroom.retained != null && (
          <div>
            <div
              className="relative h-3 overflow-hidden rounded-full bg-muted"
              role="img"
              aria-label={`${integer(headroom.retained)} of ${integer(headroom.quota)} admissions retained; ${integer(headroom.required)} required`}
            >
              <div
                className="absolute inset-y-0 left-0 bg-muted-foreground/50"
                style={{
                  width: `${Math.min(1, headroom.utilization ?? 0) * 100}%`,
                }}
              />
              {headroom.required != null && (
                <div
                  className={
                    headroom.margin != null && headroom.margin < 0
                      ? "absolute inset-y-0 bg-red-500/70"
                      : "absolute inset-y-0 bg-primary/70"
                  }
                  style={{
                    left: `${Math.min(1, headroom.utilization ?? 0) * 100}%`,
                    width: `${Math.max(0, Math.min(1 - (headroom.utilization ?? 0), headroom.required / headroom.quota)) * 100}%`,
                  }}
                />
              )}
            </div>
            <p className="mt-1 flex flex-wrap gap-x-3 text-xs text-muted-foreground">
              <span>■ retained</span>
              <span className="text-primary">■ required for planned cases</span>
              <span>□ free</span>
            </p>
          </div>
        )}
        <dl className="grid grid-cols-2 gap-3 text-sm md:grid-cols-3">
          <Field label="Retained">{integer(headroom.retained)}</Field>
          <Field label="Quota">{integer(headroom.quota)}</Field>
          <Field label="Headroom">{integer(headroom.headroom)}</Field>
          <Field label="Required">{integer(headroom.required)}</Field>
          <Field label="Per-case ceiling">
            {integer(budget?.per_case_ceiling)}
          </Field>
          <Field label="Margin">
            {headroom.margin == null ? "Unavailable" : integer(headroom.margin)}
          </Field>
          {budget?.observed_at_ms != null && (
            <Field label="Observed" className="col-span-2">
              {timestamp(budget.observed_at_ms)}
            </Field>
          )}
        </dl>
        {budget?.source && (
          <p className="text-xs text-muted-foreground">
            Source: {budget.source}
          </p>
        )}
        <Limitations items={budget?.limitations ?? []} />
      </div>
    </Section>
  );
}

function EstimateCard({ report }: { report: CohortReport }) {
  const estimate = report.native_operation_estimate;
  const range = (value: [number, number] | null) =>
    value ? `${integer(value[0])}–${integer(value[1])}` : "Unavailable";
  return (
    <Section
      title="Native operation estimate"
      description="Observed native-boundary attempts from local receipts, extrapolated to unobserved cases. Not a capacity gate."
      action={<StatusBadge status={estimate?.status ?? "not_checked"} />}
    >
      {estimate ? (
        <div className="space-y-4">
          <dl className="grid grid-cols-2 gap-3 text-sm md:grid-cols-5">
            <Field label="Completed-case samples">
              {integer(estimate.completed_case_samples)} of{" "}
              {integer(estimate.planned_cases)}
            </Field>
            <Field label="Observed completed">
              {integer(estimate.observed_totals?.completed)}
            </Field>
            <Field label="Observed unknown">
              {integer(estimate.observed_totals?.unknown)}
            </Field>
            <Field label="Attempts per case">
              {range(estimate.observed_attempt_range_per_case)}
            </Field>
            <Field label="Estimated cohort attempts">
              {range(estimate.estimated_cohort_attempt_range)}
            </Field>
          </dl>
          <Limitations items={estimate.limitations} />
        </div>
      ) : (
        <p className="empty">No native operation estimate was recorded yet.</p>
      )}
    </Section>
  );
}

function SummaryTiles({ report }: { report: CohortReport }) {
  const success = successFraction(report);
  const unfinished = cohortUnfinished(report);
  const unsafe = report.unsafe_negatives ?? unsafeNegativeCount(report.cases);
  const maximum = report.release_policy.maximum_unsafe_negatives;
  const durations = measured(report.cases, "duration");
  const requests = measured(report.cases, "requests");
  const tokens = measured(report.cases, "tokens");
  const fixed = report.cases.filter(
    (item) => item.expected === "likely_not_exploitable",
  );
  const correctNegatives = fixed.filter(
    (item) => caseOutcome(item).outcome === "correct_negative",
  ).length;
  const coverage = (values: number[]) =>
    `${values.length} of ${report.cases.length} cases measured`;
  return (
    <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
      <Tile
        label="Completed"
        value={`${integer(success.completed)} / ${integer(success.planned)}`}
        detail={
          unfinished
            ? "Not finished"
            : success.completed < success.planned
              ? "Incomplete corpus"
              : "All planned cases"
        }
        tone={
          !unfinished && success.completed < success.planned ? "bad" : undefined
        }
      />
      <Tile
        label="Correct"
        value={`${success.correct} / ${success.planned}`}
        detail={`${percent(success.rate)} task success over planned cases`}
      />
      <Tile
        label="Correct negatives"
        value={`${correctNegatives} / ${fixed.length}`}
        detail="Fixed or unreachable cases judged not exploitable"
      />
      <Tile
        label="Unsafe negatives"
        value={integer(unsafe)}
        detail={`Policy maximum ${integer(maximum)}`}
        tone={maximum != null && unsafe > maximum ? "bad" : undefined}
      />
      <Tile
        label="Median duration"
        value={seconds(percentile(durations, 0.5))}
        detail={coverage(durations)}
      />
      <Tile
        label="p90 duration"
        value={seconds(percentile(durations, 0.9))}
        detail="Nearest-rank percentile"
      />
      <Tile
        label="Total requests"
        value={requests.length ? integer(sum(requests)) : "Unavailable"}
        detail={coverage(requests)}
      />
      <Tile
        label="Total tokens"
        value={tokens.length ? number(sum(tokens), 0) : "Unavailable"}
        detail={coverage(tokens)}
      />
    </div>
  );
}

function Distributions({ report }: { report: CohortReport }) {
  const population = report.cases.length;
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <CaseHistogram
        title="Duration per case"
        unit="elapsed seconds"
        values={measured(report.cases, "duration")}
        population={population}
        format={seconds}
      />
      <CaseHistogram
        title="Model requests per case"
        unit="requests"
        values={measured(report.cases, "requests")}
        population={population}
        format={(value) => number(value, 0)}
      />
      <CaseHistogram
        title="Tokens per case"
        unit="input + output tokens"
        values={measured(report.cases, "tokens")}
        population={population}
        format={(value) => number(value, 0)}
        note="Cohort reports record token usage, not billed cost; tokens are the resource measure here."
      />
      <CaseHistogram
        title="Native operations per case"
        unit="completed + unknown attempts"
        values={measured(report.cases, "nativeOps")}
        population={population}
        format={(value) => number(value, 0)}
        note="Only cases whose local receipts were observed; unknown intents may not have reached dispatch."
      />
    </div>
  );
}

function BreakdownCard({
  title,
  rows,
  keyLabel,
}: {
  title: string;
  rows: Breakdown[];
  keyLabel: string;
}) {
  return (
    <Section
      title={title}
      description="Correct over planned cases in each group. Unstarted and failed cases count against the rate, as in the cohort gate."
    >
      {rows.length ? (
        <div className="relative overflow-auto">
          <table className="data-table">
            <caption className="sr-only">{title}</caption>
            <thead>
              <tr>
                <th scope="col">{keyLabel}</th>
                <th scope="col">Correct</th>
                <th scope="col" className="text-right">
                  Correct neg.
                </th>
                <th scope="col" className="text-right">
                  Unsafe neg.
                </th>
                <th scope="col" className="text-right">
                  Inconcl.
                </th>
                <th scope="col" className="text-right">
                  Errors
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.key}>
                  <th
                    scope="row"
                    className="font-mono font-medium text-foreground"
                  >
                    {row.key}
                  </th>
                  <td>
                    <RateBar correct={row.correct} planned={row.planned} />
                  </td>
                  <td className="text-right tabular-nums">
                    {row.correctNegatives}
                  </td>
                  <td
                    className={
                      row.unsafeNegatives
                        ? "text-right font-semibold tabular-nums text-red-700 dark:text-red-400"
                        : "text-right tabular-nums"
                    }
                  >
                    {row.unsafeNegatives}
                  </td>
                  <td className="text-right tabular-nums">
                    {row.inconclusive}
                  </td>
                  <td className="text-right tabular-nums">{row.errors}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="empty">No cases recorded.</p>
      )}
    </Section>
  );
}

function PairTable({ report }: { report: CohortReport }) {
  const [onlyMisses, setOnlyMisses] = useState(false);
  const rows = pairRows(report.cases);
  const shown = onlyMisses ? rows.filter((row) => !row.bothCorrect) : rows;
  const complete = rows.filter((row) => row.vulnerable && row.fixed);
  return (
    <Section
      title="Vulnerable / fixed pairs"
      description="Each finding beside its fixed counterpart. A pair is fully correct only when the vulnerable case is detected and the fix is recognised as not exploitable."
      action={
        <div className="flex items-center gap-3">
          <Badge variant="outline" className="font-medium">
            {complete.filter((row) => row.bothCorrect).length} /{" "}
            {complete.length} pairs fully correct
          </Badge>
          <label className="flex items-center gap-2 text-xs text-muted-foreground">
            <input
              type="checkbox"
              checked={onlyMisses}
              onChange={(event) => setOnlyMisses(event.target.checked)}
            />
            Only pairs with a miss
          </label>
        </div>
      }
    >
      {shown.length ? (
        <div className="relative overflow-auto">
          <table className="data-table">
            <caption className="sr-only">
              Vulnerable and fixed case outcomes side by side
            </caption>
            <thead>
              <tr>
                <th scope="col">Topic</th>
                <th scope="col">Language</th>
                <th scope="col">Vulnerable</th>
                <th scope="col">Fixed</th>
                <th scope="col">Pair result</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((row, index) => (
                <tr key={`${row.pair}-${index}`}>
                  <th
                    scope="row"
                    className="font-mono font-medium text-foreground"
                  >
                    {row.topic}
                  </th>
                  <td>{row.language}</td>
                  <td>
                    {row.vulnerable ? (
                      <OutcomeBadge
                        outcome={caseOutcome(row.vulnerable).outcome}
                      />
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </td>
                  <td>
                    {row.fixed ? (
                      <OutcomeBadge outcome={caseOutcome(row.fixed).outcome} />
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </td>
                  <td>
                    {row.vulnerable && row.fixed ? (
                      row.bothCorrect ? (
                        <span className="text-emerald-700 dark:text-emerald-400">
                          ✓ both correct
                        </span>
                      ) : (
                        <span className="text-muted-foreground">
                          not both correct
                        </span>
                      )
                    ) : (
                      <span className="text-muted-foreground">unpaired</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="empty">
          {rows.length ? "Every pair is fully correct." : "No cases recorded."}
        </p>
      )}
    </Section>
  );
}
