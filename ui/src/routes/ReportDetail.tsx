import { useQuery } from "@tanstack/react-query";
import { Freshness, QueryState } from "@/components/QueryState";
import { Breakable } from "@/components/ui/breakable";
import { Button } from "@/components/ui/button";
import { CohortReportView } from "@/components/evaluations/CohortReport";
import { JsonTree } from "@/components/evaluations/JsonTree";
import { QualificationReportView } from "@/components/evaluations/QualificationReport";
import { ReplayReportView } from "@/components/evaluations/ReplayReport";
import { Section } from "@/components/evaluations/common";
import { EvalLink } from "@/components/evaluations/links";
import { UNFINISHED_COHORT_REFRESH_MS, reportQuery } from "@/api/queries";
import { cohortUnfinished } from "@/lib/evaluation";
import { isReportName, type ReportDocument } from "@/lib/reports";
import type { CaseFilters } from "@/lib/search";

const EYEBROWS: Record<ReportDocument["shape"], string> = {
  cohort: "Cohort evaluation",
  qualification: "Native qualification",
  replay: "History replay",
  unknown: "Report",
};

/** One recorded report, rendered by its shape; an unrecognised shape falls back to a tree. */
export function ReportDetail({
  name,
  caseFilters,
  onCaseFilters,
}: {
  name: string;
  /** Case-table filters from the URL; local state when absent. */
  caseFilters?: CaseFilters;
  onCaseFilters?: (filters: CaseFilters) => void;
}) {
  const valid = isReportName(name);
  const query = useQuery({ ...reportQuery(name), enabled: valid });
  const loaded = query.data;
  const document = loaded?.document;
  const eyebrow =
    document?.shape === "cohort" && document.report.kind === "diagnostic"
      ? "Diagnostic subset"
      : EYEBROWS[document?.shape ?? "unknown"];
  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div className="min-w-0">
          <p className="eyebrow">{eyebrow}</p>
          <h1 className="font-mono">
            <Breakable>{name}</Breakable>
          </h1>
          <EvalLink
            href="/reports"
            className="text-xs text-muted-foreground hover:underline"
          >
            ← All reports
          </EvalLink>
        </div>
        {valid && (
          <div className="flex items-center gap-3">
            <Freshness
              at={loaded ? query.dataUpdatedAt : undefined}
              fetching={query.isFetching}
              stale={query.isError && !!loaded}
              live={
                document?.shape === "cohort" &&
                cohortUnfinished(document.report)
                  ? UNFINISHED_COHORT_REFRESH_MS
                  : false
              }
            />
            <Button
              variant="outline"
              disabled={query.isFetching}
              onClick={() => void query.refetch()}
            >
              Refresh
            </Button>
          </div>
        )}
      </header>
      {!valid && (
        <div
          role="alert"
          className="rounded-lg border border-destructive/40 bg-destructive/5 p-5"
        >
          This is not a valid report name. Report names are file names ending in
          .json.
        </div>
      )}
      {valid && !loaded && (
        <QueryState
          loading={query.isPending}
          error={query.error}
          retry={() => void query.refetch()}
        />
      )}
      {document?.shape === "cohort" && (
        <CohortReportView
          report={document.report}
          caseFilters={caseFilters}
          onCaseFilters={onCaseFilters}
        />
      )}
      {document?.shape === "qualification" && (
        <QualificationReportView report={document.report} />
      )}
      {document?.shape === "replay" && (
        <ReplayReportView report={document.report} />
      )}
      {loaded && (
        <Section
          title={
            document?.shape === "unknown"
              ? "Recorded document"
              : "Recorded document (raw)"
          }
          description={
            document?.shape === "unknown"
              ? "This report's shape is not recognised, so it is shown as recorded. Values are untrusted text."
              : "Everything the harness recorded, including full hashes. Values are untrusted text."
          }
        >
          {document?.shape === "unknown" ? (
            <JsonTree value={loaded.raw} label={name} />
          ) : (
            <details>
              <summary className="cursor-pointer text-xs text-muted-foreground">
                Show the recorded document
              </summary>
              <div className="mt-3">
                <JsonTree value={loaded.raw} label={name} />
              </div>
            </details>
          )}
        </Section>
      )}
    </div>
  );
}
