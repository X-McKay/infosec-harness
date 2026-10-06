import { TriangleAlert } from "lucide-react";
import type { components } from "@/api/schema";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  evidenceBasis,
  originSummary,
  probeClaims,
  probeGaps,
  recordedValue,
} from "@/lib/provenance";
import { verdictLabel, verdictMeaning, verdictVariant } from "@/lib/verdict";

type Result = components["schemas"]["InvestigationResult"];
type Evidence = components["schemas"]["Evidence"];

/** DOM id for an evidence card; derived from position, never from recorded text. */
export const evidenceAnchor = (index: number) => `evidence-${index}`;

function scrollTo(index: number) {
  const element = document.getElementById(evidenceAnchor(index));
  element?.scrollIntoView({ behavior: "smooth", block: "start" });
  element?.focus({ preventScroll: true });
}

function CitedEvidence({ result }: { result: Result }) {
  const ids = result.verdict.evidence_ids ?? [];
  if (!ids.length)
    return (
      <p className="text-sm text-muted-foreground">
        The verdict cites no execution evidence.
      </p>
    );
  return (
    <ul className="space-y-2">
      {ids.map((id) => {
        const index = result.evidence.findIndex((item) => item.id === id);
        const item: Evidence | undefined = result.evidence[index];
        if (!item)
          return (
            <li key={id} className="text-sm">
              <code className="break-all text-xs">{id}</code>{" "}
              <span className="text-muted-foreground">
                is cited but not included in the report.
              </span>
            </li>
          );
        const gaps = item.kind === "probe" ? probeGaps(item) : [];
        const observed = probeClaims(item).find(
          (row) => row.key === "vulnerability_observed",
        );
        return (
          <li
            key={id}
            className="flex flex-wrap items-center gap-2 rounded-md border p-2 text-sm"
          >
            <button
              type="button"
              onClick={() => scrollTo(index)}
              className="break-all text-left font-mono text-xs underline-offset-2 hover:underline"
            >
              {id}
            </button>
            <Badge variant="outline">{item.kind}</Badge>
            {item.kind === "probe" ? (
              <>
                <span className="text-xs text-muted-foreground">
                  vulnerability observed (self-reported):{" "}
                  <span className="font-mono text-foreground">
                    {recordedValue(observed?.value ?? null)}
                  </span>
                </span>
                {gaps.length ? (
                  <Badge variant="inconclusive">
                    {gaps.length} {gaps.length === 1 ? "gap" : "gaps"}
                  </Badge>
                ) : (
                  <Badge variant="outline">complete, source-verified</Badge>
                )}
              </>
            ) : (
              <span className="text-xs text-muted-foreground">
                workspace command; cannot support a definitive verdict alone
              </span>
            )}
          </li>
        );
      })}
    </ul>
  );
}

export function VerdictPanel({ result }: { result: Result }) {
  const { verdict } = result;
  const basis = evidenceBasis(result.evidence);
  const citations = verdict.citations ?? [];
  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <CardTitle>Verdict</CardTitle>
          <Badge
            variant={verdictVariant(verdict.label)}
            className="px-3 py-1 text-sm"
          >
            {verdictLabel(verdict.label)}
          </Badge>
        </div>
        <p className="text-xs text-muted-foreground">
          {verdictMeaning(verdict.label)}
        </p>
      </CardHeader>
      <CardContent className="space-y-5">
        <section aria-label="Verdict summary">
          <p className="prose-text text-sm leading-relaxed">
            {verdict.summary}
          </p>
        </section>
        <section className="space-y-2">
          <h4 className="text-sm font-semibold">Cited evidence</h4>
          <CitedEvidence result={result} />
        </section>
        {basis && (
          <p
            role="note"
            className="flex gap-2 rounded-md border border-amber-300/60 bg-amber-50/60 p-3 text-xs text-amber-950 dark:bg-amber-950/20 dark:text-amber-100"
          >
            <TriangleAlert className="h-4 w-4 shrink-0" aria-hidden="true" />
            <span>
              Probe claims in this report are parsed from probe output (recorded
              origin: {originSummary(basis)}). The harness records the process
              outcome, source verification and workspace digest; it does not
              independently verify target binding or oracle semantics.
            </span>
          </p>
        )}
        <section className="space-y-2">
          <h4 className="text-sm font-semibold">Source citations</h4>
          {citations.length ? (
            <div className="relative overflow-auto">
              <table className="data-table">
                <thead>
                  <tr>
                    <th scope="col">Path</th>
                    <th scope="col" className="text-right">
                      Lines
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {citations.map((citation, index) => (
                    <tr key={index}>
                      <td className="break-all font-mono">{citation.path}</td>
                      <td className="whitespace-nowrap text-right font-mono">
                        {citation.start_line === citation.end_line
                          ? citation.start_line
                          : `${citation.start_line}–${citation.end_line}`}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">
              No source citations recorded.
            </p>
          )}
        </section>
      </CardContent>
    </Card>
  );
}

export function Limitations({ limitations }: { limitations: string[] }) {
  return (
    <Card className="border-amber-300/60">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <TriangleAlert
            className="h-4 w-4 text-amber-600 dark:text-amber-400"
            aria-hidden="true"
          />
          Limitations
        </CardTitle>
        <p className="text-xs text-muted-foreground">
          What this report did not establish. Read these before acting on the
          verdict.
        </p>
      </CardHeader>
      <CardContent>
        {limitations.length ? (
          <ul className="list-disc space-y-2 pl-5 text-sm">
            {limitations.map((item, index) => (
              <li key={index} className="prose-text">
                {item}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted-foreground">
            The report recorded no limitations. An absent limitation is not
            evidence that a check passed.
          </p>
        )}
      </CardContent>
    </Card>
  );
}
