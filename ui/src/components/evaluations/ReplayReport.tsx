import { integer } from "@/lib/format";
import { runPath, shortHash, type ReplayReport } from "@/lib/reports";
import { Section, StatusBadge } from "./common";
import { EvalLink } from "./links";

/**
 * Zero-dispatch history replay. The replayer refuses every native or model operation, so a
 * passed replay has zero dispatches by construction; a failed one names the attempt in its
 * cause chain. The report does not count dispatches itself.
 */
export function ReplayReportView({ report }: { report: ReplayReport }) {
  return (
    <Section
      title="History replay"
      description="Recorded workflow histories replayed against current workflow code with native and model dispatch refused. A replay attempt to dispatch fails the replay rather than executing."
      action={<StatusBadge status={report.status} />}
    >
      {report.histories.length ? (
        <div className="relative overflow-auto">
          <table className="data-table">
            <caption className="sr-only">Replayed workflow histories</caption>
            <thead>
              <tr>
                <th scope="col">Workflow</th>
                <th scope="col">Status</th>
                <th scope="col" className="text-right">
                  History events
                </th>
                <th scope="col">Dispatches</th>
                <th scope="col">History SHA-256</th>
                <th scope="col">Recorded verdict</th>
                <th scope="col">Failure</th>
              </tr>
            </thead>
            <tbody>
              {report.histories.map((history, index) => {
                const path = runPath(history.workflow_id);
                return (
                  <tr key={index}>
                    <th
                      scope="row"
                      className="font-mono font-normal text-foreground"
                    >
                      {path ? (
                        <EvalLink
                          href={path}
                          className="text-primary hover:underline"
                        >
                          {history.workflow_id}
                        </EvalLink>
                      ) : (
                        (history.workflow_id ?? "Unavailable")
                      )}
                    </th>
                    <td>
                      <StatusBadge status={history.status} />
                    </td>
                    <td className="text-right tabular-nums">
                      {integer(history.history_events)}
                    </td>
                    <td className="text-xs">
                      {history.status === "passed" ? (
                        "None attempted (guarded)"
                      ) : (
                        <span className="text-muted-foreground">
                          see failure
                        </span>
                      )}
                    </td>
                    <td className="font-mono text-xs">
                      {shortHash(history.history_sha256, 16) ?? "Unavailable"}
                    </td>
                    <td>
                      {history.verdict
                        ? history.verdict.replaceAll("_", " ")
                        : "—"}
                    </td>
                    <td className="max-w-md text-xs">
                      {history.failure_chain.length ? (
                        <ol className="space-y-1">
                          {history.failure_chain.map((link, position) => (
                            <li key={position}>
                              <span className="font-mono font-medium">
                                {link.type}
                              </span>
                              {link.message && (
                                <pre className="whitespace-pre-wrap break-words font-mono text-muted-foreground">
                                  {link.message}
                                </pre>
                              )}
                            </li>
                          ))}
                        </ol>
                      ) : (
                        "—"
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="empty">No replayed histories were recorded.</p>
      )}
    </Section>
  );
}
