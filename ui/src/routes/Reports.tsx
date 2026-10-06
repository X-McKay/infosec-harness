import { useQuery } from "@tanstack/react-query";
import { useMemo, useState, type ReactNode } from "react";
import { Freshness, QueryState } from "@/components/QueryState";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  bytes,
  GateBadge,
  KindBadge,
  kindLabel,
  StatusBadge,
} from "@/components/evaluations/common";
import { EvalLink } from "@/components/evaluations/links";
import { reportsQuery } from "@/components/evaluations/queries";
import { integer, percent, timestamp } from "@/lib/format";
import {
  REPORT_KINDS,
  reportPath,
  shortHash,
  type ReportKind,
} from "@/lib/reports";
import { cn } from "@/lib/utils";

const GATE_SHORT: Record<string, string> = {
  complete_corpus: "corpus",
  task_success_rate: "success",
  unsafe_negatives: "unsafe",
};

/** Every report `harness eval|qualify|replay` wrote, newest first. */
export function Reports() {
  const query = useQuery(reportsQuery());
  const [kind, setKind] = useState<ReportKind | "">("");
  const reports = useMemo(() => query.data?.items ?? [], [query.data]);
  const counts = useMemo(() => {
    const result = new Map<ReportKind, number>();
    for (const report of reports)
      result.set(report.kind, (result.get(report.kind) ?? 0) + 1);
    return result;
  }, [reports]);
  const shown = kind
    ? reports.filter((report) => report.kind === kind)
    : reports;

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="eyebrow">Recorded evidence</p>
          <h1>Reports</h1>
          <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
            Cohort evaluations, diagnostic subsets, native qualification and
            history replays, as the harness wrote them. Gates are only as strong
            as the evidence each report recorded.
          </p>
        </div>
        <Button
          variant="outline"
          disabled={query.isFetching}
          onClick={() => void query.refetch()}
        >
          Refresh
        </Button>
      </header>
      {!query.data && (
        <QueryState
          loading={query.isPending}
          error={query.error}
          retry={() => void query.refetch()}
        />
      )}
      {query.data && (
        <>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div
              className="flex flex-wrap gap-2"
              role="group"
              aria-label="Filter by report kind"
            >
              <FilterButton active={!kind} onClick={() => setKind("")}>
                All · {reports.length}
              </FilterButton>
              {REPORT_KINDS.filter((item) => counts.get(item)).map((item) => (
                <FilterButton
                  key={item}
                  active={kind === item}
                  onClick={() => setKind(item)}
                >
                  {kindLabel(item)} · {counts.get(item)}
                </FilterButton>
              ))}
            </div>
            <Freshness
              at={query.dataUpdatedAt}
              fetching={query.isFetching}
              stale={query.isError}
            />
          </div>
          {query.data.truncated && (
            <p role="status" className="text-xs text-muted-foreground">
              The API lists only the newest {integer(reports.length)} report
              files; older reports are not shown.
            </p>
          )}
          <Card>
            <CardContent className="p-0">
              {shown.length ? (
                <div className="overflow-auto">
                  <table className="data-table">
                    <caption className="sr-only">
                      Recorded reports, newest first
                    </caption>
                    <thead>
                      <tr>
                        <th scope="col">Report</th>
                        <th scope="col">Status</th>
                        <th scope="col">Commit / model</th>
                        <th scope="col" className="text-right">
                          Completed
                        </th>
                        <th scope="col" className="text-right">
                          Success
                        </th>
                        <th scope="col" className="text-right">
                          Unsafe neg.
                        </th>
                        <th scope="col">Gates</th>
                        <th scope="col">Started · finished</th>
                        <th scope="col" className="text-right">
                          Size
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {shown.map((report) => {
                        const path = reportPath(report.name);
                        const gates = Object.entries(report.gates);
                        return (
                          <tr key={report.name}>
                            <th
                              scope="row"
                              className="font-normal text-foreground"
                            >
                              <div className="flex flex-col items-start gap-1">
                                {path ? (
                                  <EvalLink
                                    href={path}
                                    className="break-all font-mono font-medium text-primary hover:underline"
                                  >
                                    {report.name}
                                  </EvalLink>
                                ) : (
                                  <span className="break-all font-mono">
                                    {report.name}
                                  </span>
                                )}
                                <KindBadge kind={report.kind} />
                              </div>
                            </th>
                            <td>
                              <StatusBadge status={report.status} />
                            </td>
                            <td className="text-xs">
                              <span className="font-mono">
                                {shortHash(report.commit, 10) ?? "—"}
                              </span>
                              <br />
                              <span className="text-muted-foreground">
                                {report.model ?? "—"}
                              </span>
                            </td>
                            <td className="whitespace-nowrap text-right tabular-nums">
                              {report.planned == null
                                ? "—"
                                : `${integer(report.completed)} / ${integer(report.planned)}`}
                            </td>
                            <td className="text-right tabular-nums">
                              {report.task_success_rate == null
                                ? "—"
                                : percent(report.task_success_rate)}
                            </td>
                            <td
                              className={cn(
                                "text-right tabular-nums",
                                !!report.unsafe_negatives &&
                                  "font-semibold text-red-700 dark:text-red-400",
                              )}
                            >
                              {report.unsafe_negatives == null
                                ? "—"
                                : integer(report.unsafe_negatives)}
                            </td>
                            <td>
                              {gates.length ? (
                                <div className="flex flex-wrap gap-1">
                                  {gates.map(([key, status]) => (
                                    <GateBadge
                                      key={key}
                                      status={status}
                                      label={
                                        GATE_SHORT[key] ??
                                        key.replaceAll("_", " ")
                                      }
                                      compact
                                    />
                                  ))}
                                </div>
                              ) : (
                                <span className="text-muted-foreground">—</span>
                              )}
                            </td>
                            <td className="whitespace-nowrap text-xs">
                              {timestamp(report.started_at)}
                              <br />
                              <span className="text-muted-foreground">
                                {report.finished_at
                                  ? timestamp(report.finished_at)
                                  : "not finished"}
                              </span>
                            </td>
                            <td className="whitespace-nowrap text-right text-xs tabular-nums">
                              {bytes(report.bytes)}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="empty">
                  {reports.length
                    ? "No reports of this kind."
                    : "No reports yet. Run ./dev eval, ./dev qualify or ./dev replay to record one."}
                </p>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}

function FilterButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <Button
      variant={active ? "default" : "outline"}
      size="sm"
      aria-pressed={active}
      onClick={onClick}
    >
      {children}
    </Button>
  );
}
