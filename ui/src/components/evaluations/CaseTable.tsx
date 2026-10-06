import { Fragment, useEffect, useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import {
  caseMetrics,
  caseOutcome,
  failureClass,
  FAILURE_LABELS,
  OUTCOME_LABELS,
  parseCaseName,
  sortCases,
  type CaseSortKey,
  type Outcome,
} from "@/lib/evaluation";
import { integer, seconds, timestamp } from "@/lib/format";
import { runPath, shortHash, type CohortCase } from "@/lib/reports";
import {
  Field,
  Limitations,
  OutcomeBadge,
  Section,
  StatusBadge,
} from "./common";
import { EvalLink } from "./links";
import type { CaseFilters } from "@/lib/search";

const COLUMNS: { key: CaseSortKey; label: string; numeric?: boolean }[] = [
  { key: "name", label: "Case" },
  { key: "expected", label: "Expected" },
  { key: "predicted", label: "Predicted" },
  { key: "outcome", label: "Outcome" },
  { key: "status", label: "Status" },
  { key: "duration", label: "Duration", numeric: true },
  { key: "requests", label: "Requests", numeric: true },
  { key: "toolCalls", label: "Tool calls", numeric: true },
  { key: "tokens", label: "Tokens", numeric: true },
  { key: "nativeOps", label: "Native ops", numeric: true },
  { key: "error", label: "Error type" },
];

const verdictText = (value: string | null) =>
  value ? value.replaceAll("_", " ") : "—";

/**
 * The case table. Filters come from the URL (`?case=&outcome=&language=`) when the route
 * passes them, so a filtered view can be shared and survives reloads; otherwise they are local.
 */
export function CaseTable({
  cases,
  filters: routeFilters,
  onFilters,
}: {
  cases: CohortCase[];
  filters?: CaseFilters;
  onFilters?: (filters: CaseFilters) => void;
}) {
  const [sort, setSort] = useState<{ key: CaseSortKey; descending: boolean }>({
    key: "name",
    descending: false,
  });
  const [localFilters, setLocalFilters] = useState<CaseFilters>({});
  const filters = onFilters ? (routeFilters ?? {}) : localFilters;
  const setFilters = (patch: CaseFilters) => {
    const next = { ...filters, ...patch };
    for (const key of Object.keys(next) as (keyof CaseFilters)[])
      if (!next[key]) delete next[key];
    if (onFilters) onFilters(next);
    else setLocalFilters(next);
  };
  const search = filters.case ?? "";
  // The URL keeps the trimmed filter; the box keeps what was typed (spaces included).
  const [draft, setDraft] = useState(search);
  useEffect(() => {
    setDraft((current) => (current.trim() === search ? current : search));
  }, [search]);
  const outcome = filters.outcome ?? "";
  const language = filters.language ?? "";
  const [open, setOpen] = useState<Set<number>>(new Set());
  const languages = useMemo(
    () =>
      [
        ...new Set(cases.map((item) => parseCaseName(item.name).language)),
      ].sort(),
    [cases],
  );
  const indexed = useMemo(
    () => new Map(cases.map((item, index) => [item, index])),
    [cases],
  );
  const rows = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const filtered = cases.filter(
      (item) =>
        (!needle ||
          item.name.toLowerCase().includes(needle) ||
          (item.error_type ?? "").toLowerCase().includes(needle)) &&
        (!outcome || caseOutcome(item).outcome === outcome) &&
        (!language || parseCaseName(item.name).language === language),
    );
    return sortCases(filtered, sort.key, sort.descending);
  }, [cases, search, outcome, language, sort]);
  const toggle = (index: number) =>
    setOpen((current) => {
      const next = new Set(current);
      if (next.has(index)) next.delete(index);
      else next.add(index);
      return next;
    });

  return (
    <Section
      title="Cases"
      description="Outcome compares the recorded prediction with the corpus's independent expected label. Usage and native operation counts are as recorded; a missing value is shown as —, never as zero."
    >
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-2 text-xs">
          <span className="sr-only">Filter cases</span>
          <input
            className="field w-56"
            placeholder="Filter by case or error type"
            value={draft}
            onChange={(event) => {
              setDraft(event.target.value);
              setFilters({ case: event.target.value.trim() || undefined });
            }}
          />
        </label>
        <label className="flex items-center gap-2 text-xs text-muted-foreground">
          Outcome
          <select
            className="field"
            value={outcome}
            onChange={(event) =>
              setFilters({
                outcome: (event.target.value || undefined) as
                  | Outcome
                  | undefined,
              })
            }
          >
            <option value="">All</option>
            {(Object.keys(OUTCOME_LABELS) as Outcome[]).map((key) => (
              <option key={key} value={key}>
                {OUTCOME_LABELS[key]}
              </option>
            ))}
          </select>
        </label>
        <label className="flex items-center gap-2 text-xs text-muted-foreground">
          Language
          <select
            className="field"
            value={language}
            onChange={(event) =>
              setFilters({ language: event.target.value || undefined })
            }
          >
            <option value="">All</option>
            {languages.map((key) => (
              <option key={key} value={key}>
                {key}
              </option>
            ))}
          </select>
        </label>
        <span className="text-xs text-muted-foreground" role="status">
          {rows.length} of {cases.length} cases
        </span>
      </div>
      {rows.length ? (
        <div className="relative overflow-auto">
          <table className="data-table">
            <caption className="sr-only">
              Cohort cases; column headers sort the table
            </caption>
            <thead>
              <tr>
                <th scope="col">
                  <span className="sr-only">Details</span>
                </th>
                {COLUMNS.map((column) => (
                  <th
                    key={column.key}
                    scope="col"
                    className={column.numeric ? "text-right" : undefined}
                    aria-sort={
                      sort.key === column.key
                        ? sort.descending
                          ? "descending"
                          : "ascending"
                        : "none"
                    }
                  >
                    <button
                      type="button"
                      className="whitespace-nowrap font-medium hover:text-foreground"
                      onClick={() =>
                        setSort((current) => ({
                          key: column.key,
                          descending:
                            current.key === column.key
                              ? !current.descending
                              : false,
                        }))
                      }
                    >
                      {column.label}
                      {sort.key === column.key
                        ? sort.descending
                          ? " ↓"
                          : " ↑"
                        : ""}
                    </button>
                  </th>
                ))}
                <th scope="col">Run</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((item) => {
                const index = indexed.get(item) ?? 0;
                const metrics = caseMetrics(item);
                const expanded = open.has(index);
                const path = runPath(item.workflow_id);
                return (
                  <Fragment key={index}>
                    <tr className={expanded ? "bg-muted/40" : undefined}>
                      <td>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-6 w-6 p-0"
                          aria-expanded={expanded}
                          onClick={() => toggle(index)}
                        >
                          <span aria-hidden>{expanded ? "−" : "+"}</span>
                          {/* Untrusted names stay text content, never attribute values. */}
                          <span className="sr-only">
                            {expanded ? "Hide" : "Show"} details for {item.name}
                          </span>
                        </Button>
                      </td>
                      <th
                        scope="row"
                        className="whitespace-nowrap font-mono text-foreground"
                      >
                        {item.name}
                      </th>
                      <td className="whitespace-nowrap">
                        {verdictText(item.expected)}
                      </td>
                      <td className="whitespace-nowrap">
                        {verdictText(item.predicted)}
                      </td>
                      <td>
                        <OutcomeBadge outcome={caseOutcome(item).outcome} />
                      </td>
                      <td>
                        <StatusBadge status={item.status} />
                      </td>
                      <td className="text-right tabular-nums">
                        {metrics.duration == null
                          ? "—"
                          : seconds(metrics.duration)}
                      </td>
                      <td className="text-right tabular-nums">
                        {metrics.requests == null
                          ? "—"
                          : integer(metrics.requests)}
                      </td>
                      <td className="text-right tabular-nums">
                        {metrics.toolCalls == null
                          ? "—"
                          : integer(metrics.toolCalls)}
                      </td>
                      <td className="text-right tabular-nums">
                        {metrics.tokens == null ? "—" : integer(metrics.tokens)}
                      </td>
                      <td className="text-right tabular-nums">
                        {metrics.nativeOps == null ? (
                          <span title="Native receipts were not observed">
                            —
                          </span>
                        ) : (
                          <>
                            {integer(metrics.nativeOps)}
                            {!!metrics.nativeUnknown && (
                              <span className="text-muted-foreground">
                                {" "}
                                ({integer(metrics.nativeUnknown)} unknown)
                              </span>
                            )}
                          </>
                        )}
                      </td>
                      <td className="whitespace-nowrap font-mono">
                        {item.error_type ?? "—"}
                      </td>
                      <td className="whitespace-nowrap">
                        {path ? (
                          <EvalLink
                            href={path}
                            className="text-primary underline-offset-2 hover:underline"
                          >
                            Open run
                            <span className="sr-only"> for {item.name}</span>
                          </EvalLink>
                        ) : (
                          <span className="text-muted-foreground">
                            {item.workflow_id
                              ? "Unrecognised ID"
                              : "Not started"}
                          </span>
                        )}
                      </td>
                    </tr>
                    {expanded && (
                      <tr>
                        <td
                          colSpan={COLUMNS.length + 2}
                          className="bg-muted/20"
                        >
                          <CaseDetail item={item} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="empty">No cases match these filters.</p>
      )}
    </Section>
  );
}

function CaseDetail({ item }: { item: CohortCase }) {
  const metrics = caseMetrics(item);
  const native = item.native_operations;
  const kind = failureClass(item);
  return (
    <div className="space-y-3 py-1">
      <dl className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Field
          label="Workflow ID"
          mono
          copy={{ value: item.workflow_id, label: "Copy workflow ID" }}
        >
          {item.workflow_id ?? "Not started"}
        </Field>
        <Field label="Started">{timestamp(item.started_at)}</Field>
        <Field label="Finished">{timestamp(item.finished_at)}</Field>
        <Field
          label="Source digest"
          mono
          copy={{ value: item.source_digest, label: "Copy source digest" }}
        >
          {shortHash(item.source_digest, 16) ?? "Unavailable"}
        </Field>
        <Field label="Input / output tokens">
          {integer(metrics.inputTokens)} / {integer(metrics.outputTokens)}
        </Field>
        <Field
          label="Worker fingerprint"
          mono
          copy={{
            value: item.worker_identity?.fingerprint,
            label: "Copy worker fingerprint",
          }}
        >
          {shortHash(item.worker_identity?.fingerprint) ?? "Unavailable"}
        </Field>
        {kind && <Field label="Failure class">{FAILURE_LABELS[kind]}</Field>}
        {item.cancellation && (
          <Field label="Cancellation">{item.cancellation}</Field>
        )}
      </dl>
      {native ? (
        <div className="text-xs">
          <p className="font-medium">
            Native operations ·{" "}
            <span className="font-normal">
              {native.status.replaceAll("_", " ")}
            </span>
          </p>
          {Object.keys(native.categories).length > 0 && (
            <ul className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-muted-foreground">
              {Object.entries(native.categories).map(([category, counts]) => (
                <li key={category}>
                  <span className="font-mono">{category}</span>{" "}
                  {counts.completed} completed
                  {counts.unknown ? `, ${counts.unknown} unknown` : ""}
                </li>
              ))}
            </ul>
          )}
        </div>
      ) : (
        <p className="text-xs text-muted-foreground">
          No native operation observation was recorded.
        </p>
      )}
      <Limitations
        items={item.limitations}
        title="Recorded investigation limitations"
      />
    </div>
  );
}
