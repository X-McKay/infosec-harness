import { Badge } from "@/components/ui/badge";
import { failureClass, failureSummary, FAILURE_LABELS } from "@/lib/evaluation";
import { seconds } from "@/lib/format";
import { runPath, type CohortCase } from "@/lib/reports";
import { Section } from "./common";
import { EvalLink } from "./links";

/**
 * Failed cases with their recorded cause chains. Chain messages are untrusted text (they can
 * quote model output or exceptions) and render only as preformatted React text.
 */
export function FailureList({ cases }: { cases: CohortCase[] }) {
  const failures = cases.filter((item) => failureClass(item) != null);
  const summary = failureSummary(cases);
  return (
    <Section
      title="Failures"
      description="A failed case is never re-run. Its workflow may have completed external requests before failing, so recorded receipts and exit codes are context, not proof of what executed."
    >
      {failures.length === 0 ? (
        <p className="empty">No case failures were recorded.</p>
      ) : (
        <div className="space-y-4">
          <div className="flex flex-wrap gap-2" aria-label="Failures by class">
            {summary.map((row) => (
              <Badge key={row.kind} variant="outline" className="font-medium">
                {FAILURE_LABELS[row.kind]} · {row.count}
                <span className="ml-1 font-normal text-muted-foreground">
                  ({row.errorTypes.join(", ")})
                </span>
              </Badge>
            ))}
          </div>
          <ol className="space-y-3">
            {failures.map((item, index) => {
              const kind = failureClass(item);
              const path = runPath(item.workflow_id);
              return (
                <li key={index} className="rounded-md border p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-sm font-medium">
                        {item.name}
                      </span>
                      <Badge variant="exploitable">
                        {item.error_type ?? "Unknown error"}
                      </Badge>
                      {kind && (
                        <span className="text-xs text-muted-foreground">
                          {FAILURE_LABELS[kind]}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-3 text-xs text-muted-foreground">
                      {item.duration_seconds != null && (
                        <span>{seconds(item.duration_seconds)}</span>
                      )}
                      {item.cancellation && (
                        <span>cancellation {item.cancellation}</span>
                      )}
                      {path && (
                        <EvalLink
                          href={path}
                          className="text-primary hover:underline"
                        >
                          Open run
                        </EvalLink>
                      )}
                    </div>
                  </div>
                  {item.failure_chain.length ? (
                    <ol className="mt-2 space-y-1 border-l-2 border-red-500/30 pl-3">
                      {item.failure_chain.map((link, position) => (
                        <li key={position} className="text-xs">
                          <span className="font-mono font-medium">
                            {position ? "caused by " : ""}
                            {link.type}
                          </span>
                          {link.message && (
                            <pre className="mt-0.5 whitespace-pre-wrap break-words font-mono text-muted-foreground">
                              {link.message}
                            </pre>
                          )}
                        </li>
                      ))}
                    </ol>
                  ) : (
                    <p className="mt-2 text-xs text-muted-foreground">
                      No cause chain was recorded.
                    </p>
                  )}
                  {item.receipts && (
                    <p className="mt-2 text-xs text-muted-foreground">
                      Local receipts:{" "}
                      {item.receipts.status.replaceAll("_", " ")}
                      {item.receipts.count != null &&
                        ` · ${item.receipts.count} recorded`}
                      {item.receipts.error_type &&
                        ` · ${item.receipts.error_type}`}
                      {item.receipts.items.length > 0 &&
                        ` · first ${item.receipts.items.length}: ${item.receipts.items
                          .map(
                            (receipt) =>
                              `${receipt.operation_id} exit ${receipt.exit_code ?? "unknown"}${receipt.output_truncated ? " (truncated)" : ""}`,
                          )
                          .join(", ")}`}
                    </p>
                  )}
                </li>
              );
            })}
          </ol>
        </div>
      )}
    </Section>
  );
}
