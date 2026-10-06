import { FlaskConical, SquareTerminal } from "lucide-react";
import { useState } from "react";
import type { components } from "@/api/schema";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { integer } from "@/lib/format";
import { cn } from "@/lib/utils";
import {
  claimOrigin,
  finalProbeLine,
  otherObservations,
  probeClaims,
  probeGaps,
  recordedValue,
  reportExcerpted,
  sourceVerified,
  workspaceDigest,
} from "@/lib/provenance";

type Evidence = components["schemas"]["Evidence"];

/** Untrusted output: plain React text in a bounded block, rendered only while open. */
export function OutputBlock({
  label,
  value,
  defaultOpen = false,
}: {
  label: string;
  value: string;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  if (!value)
    return (
      <p className="text-xs text-muted-foreground">
        {label}: no output recorded
      </p>
    );
  const lines = value.split("\n").length;
  return (
    <details
      open={open}
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary className="cursor-pointer text-xs font-medium">
        {label}{" "}
        <span className="font-normal text-muted-foreground">
          · {integer(lines)} {lines === 1 ? "line" : "lines"} ·{" "}
          {integer(value.length)} characters
        </span>
      </summary>
      {open && <pre className="output mt-2">{value}</pre>}
    </details>
  );
}

function exitBadge(evidence: Evidence) {
  if (evidence.exit_code == null)
    return <Badge variant="muted">no exit code</Badge>;
  return (
    <Badge variant={evidence.exit_code === 0 ? "outline" : "failed"}>
      exit {evidence.exit_code}
    </Badge>
  );
}

export function EvidenceCard({
  evidence,
  cited,
  superseded,
  anchor,
}: {
  evidence: Evidence;
  cited: boolean;
  superseded: boolean;
  /** DOM id derived from the card's position, never from recorded text. */
  anchor: string;
}) {
  const probe = evidence.kind === "probe";
  const Icon = probe ? FlaskConical : SquareTerminal;
  const gaps = probe ? probeGaps(evidence) : [];
  const verified = sourceVerified(evidence);
  const digest = workspaceDigest(evidence);
  const origin = claimOrigin(evidence);
  const other = otherObservations(evidence);
  const probeLine = probe ? finalProbeLine(evidence.stdout) : null;
  return (
    <Card
      id={anchor}
      tabIndex={-1}
      className={cn("scroll-mt-6", superseded && "border-dashed")}
    >
      <CardHeader className="gap-2 space-y-0">
        <div className="flex flex-wrap items-center gap-2">
          <Icon className="h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
          <code className="break-all text-xs font-medium">{evidence.id}</code>
          {cited && <Badge>cited</Badge>}
          {superseded && <Badge variant="muted">superseded</Badge>}
          {!cited && !superseded && <Badge variant="muted">not cited</Badge>}
          {exitBadge(evidence)}
          {evidence.timed_out && <Badge variant="failed">timed out</Badge>}
          {evidence.output_truncated && (
            <Badge variant="inconclusive">output truncated</Badge>
          )}
          {reportExcerpted(evidence) && (
            <Badge variant="muted">report excerpt</Badge>
          )}
        </div>
        {superseded && (
          <p className="text-xs text-muted-foreground">
            The investigator disowned this probe as flawed; the verdict summary
            states the claimed flaw. It stays in the report.
          </p>
        )}
      </CardHeader>
      <CardContent className="space-y-4">
        <pre className="output">{evidence.command}</pre>
        <dl className="grid gap-x-6 gap-y-2 text-xs sm:grid-cols-2">
          <div>
            <dt className="text-muted-foreground">Sandbox</dt>
            <dd className="break-all font-mono">{evidence.sandbox_id}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Source digest</dt>
            <dd className="break-all font-mono">{evidence.source_digest}</dd>
          </div>
        </dl>
        {probe && (
          <section aria-label="Probe observations" className="space-y-2">
            <p
              className={
                gaps.length
                  ? "rounded-md border border-amber-300/60 bg-amber-50/60 p-2 text-xs text-amber-950 dark:bg-amber-950/20 dark:text-amber-100"
                  : "rounded-md border border-dashed p-2 text-xs text-muted-foreground"
              }
            >
              {gaps.length
                ? `Not a complete, source-verified probe: ${gaps.join("; ")}.`
                : "Recorded values meet the complete, source-verified probe rule. The claims themselves remain self-reported."}
            </p>
            <div className="relative overflow-auto">
              <table className="data-table">
                <caption className="sr-only">
                  Recorded probe observations for {evidence.id}
                </caption>
                <thead>
                  <tr>
                    <th scope="col">Observation</th>
                    <th scope="col">Recorded value</th>
                    <th scope="col">Recorded by</th>
                  </tr>
                </thead>
                <tbody>
                  {probeClaims(evidence).map((row) => (
                    <tr key={row.key}>
                      <th scope="row" className="font-normal">
                        {row.label}
                      </th>
                      <td
                        className={
                          row.value == null
                            ? "text-muted-foreground"
                            : "font-mono"
                        }
                      >
                        {recordedValue(row.value)}
                      </td>
                      <td className="text-muted-foreground">
                        Probe output (
                        {origin
                          ? origin.replaceAll("_", " ")
                          : "origin not recorded"}
                        )
                      </td>
                    </tr>
                  ))}
                  <tr>
                    <th scope="row" className="font-normal">
                      Source verified
                    </th>
                    <td
                      className={
                        verified == null ? "text-muted-foreground" : "font-mono"
                      }
                    >
                      {recordedValue(verified)}
                    </td>
                    <td className="text-muted-foreground">
                      Harness source check
                    </td>
                  </tr>
                  <tr>
                    <th scope="row" className="font-normal">
                      Workspace digest
                    </th>
                    <td className="break-all font-mono">
                      {digest ?? (
                        <span className="font-sans text-muted-foreground">
                          not recorded
                        </span>
                      )}
                    </td>
                    <td className="text-muted-foreground">
                      Harness source check
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>
        )}
        {other.length > 0 && (
          <section aria-label="Other recorded observations">
            <p className="mb-1 text-xs font-medium">
              Other recorded observations
            </p>
            <dl className="space-y-2 text-xs">
              {other.map(([key, value]) => (
                <div key={key}>
                  <dt className="font-mono text-muted-foreground">{key}</dt>
                  <dd className="prose-text">{value}</dd>
                </div>
              ))}
            </dl>
          </section>
        )}
        {probeLine && (
          <div className="space-y-1">
            <p className="text-xs font-medium">Final probe line</p>
            <pre className="output">{probeLine}</pre>
          </div>
        )}
        <div className="space-y-2">
          <OutputBlock label="stdout" value={evidence.stdout} />
          <OutputBlock label="stderr" value={evidence.stderr} />
        </div>
      </CardContent>
    </Card>
  );
}
