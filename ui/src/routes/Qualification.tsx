import { useQuery } from "@tanstack/react-query";
import { Freshness, QueryState } from "@/components/QueryState";
import { Button } from "@/components/ui/button";
import { QualificationReportView } from "@/components/evaluations/QualificationReport";
import { Section, StatusBadge } from "@/components/evaluations/common";
import { EvalLink } from "@/components/evaluations/links";
import { reportQuery, reportsQuery } from "@/components/evaluations/queries";
import { timestamp } from "@/lib/format";
import { reportPath } from "@/lib/reports";

/**
 * The latest `harness qualify` report: real native boundaries, no model calls. Only a
 * recorded report is shown; nothing here is inferred from configuration.
 */
export function Qualification() {
  const list = useQuery(reportsQuery());
  const reports = (list.data ?? []).filter(
    (report) => report.kind === "openshell",
  );
  const latest = reports[0];
  const detail = useQuery({
    ...reportQuery(latest?.name ?? ""),
    enabled: !!latest,
  });
  const document = detail.data?.document;
  const path = latest ? reportPath(latest.name) : null;
  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="eyebrow">Measured evidence</p>
          <h1>Qualification</h1>
          <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
            The latest native OpenShell qualification: workspace and probe
            sandboxes exercised through the production adapter, with no model
            calls. A configured runtime is not evidence; only a recorded run is.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Freshness
            at={list.data ? list.dataUpdatedAt : undefined}
            fetching={list.isFetching || detail.isFetching}
            stale={list.isError && !!list.data}
          />
          <Button
            variant="outline"
            disabled={list.isFetching}
            onClick={() => {
              void list.refetch();
              if (latest) void detail.refetch();
            }}
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
      {list.data && !latest && (
        <Section
          title="No qualification recorded"
          description="Native boundaries: not checked."
        >
          <p className="text-sm text-muted-foreground">
            No openshell qualification report exists yet. Run{" "}
            <code>./dev qualify</code> to record one; until then native
            boundaries are not checked.
          </p>
        </Section>
      )}
      {latest && (
        <>
          <div className="flex flex-wrap items-center gap-3 text-sm">
            <span className="text-muted-foreground">Latest report</span>
            {path ? (
              <EvalLink
                href={path}
                className="font-mono text-primary hover:underline"
              >
                {latest.name}
              </EvalLink>
            ) : (
              <span className="font-mono">{latest.name}</span>
            )}
            <StatusBadge status={latest.status} />
            <span className="text-xs text-muted-foreground">
              {latest.started_at ? timestamp(latest.started_at) : ""}
            </span>
          </div>
          {!document && (
            <QueryState
              loading={detail.isPending}
              error={detail.error}
              retry={() => void detail.refetch()}
            />
          )}
          {document?.shape === "qualification" && (
            <QualificationReportView report={document.report} />
          )}
          {document && document.shape !== "qualification" && (
            <p role="alert" className="text-sm">
              The latest qualification report does not have the expected shape.
              Open the full report to inspect it as recorded.
            </p>
          )}
          {reports.length > 1 && (
            <Section title="Earlier qualification runs">
              <ul className="divide-y text-sm">
                {reports.slice(1, 11).map((report) => {
                  const href = reportPath(report.name);
                  return (
                    <li
                      key={report.name}
                      className="flex flex-wrap items-center gap-3 py-2"
                    >
                      {href ? (
                        <EvalLink
                          href={href}
                          className="font-mono text-primary hover:underline"
                        >
                          {report.name}
                        </EvalLink>
                      ) : (
                        <span className="font-mono">{report.name}</span>
                      )}
                      <StatusBadge status={report.status} />
                      <span className="text-xs text-muted-foreground">
                        {timestamp(report.started_at)}
                      </span>
                    </li>
                  );
                })}
              </ul>
            </Section>
          )}
        </>
      )}
    </div>
  );
}
