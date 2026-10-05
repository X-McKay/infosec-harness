import { CircleAlert } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import type { RunDetail } from "@/api/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { integer, money, seconds } from "@/lib/format";
import { asRecord, isRecord, type JsonRecord } from "@/lib/json";
import { executionProvenance, originSummary } from "@/lib/provenance";

function Json({ value }: { value: unknown }) {
  const rendered = useMemo(() => JSON.stringify(value, null, 2), [value]);
  return (
    <pre className="max-h-80 overflow-auto rounded-md bg-muted p-3 text-xs">
      {rendered}
    </pre>
  );
}

/** Serializes recorded JSON only while the disclosure is open. */
function JsonDetails({
  summary,
  value,
  defaultOpen = false,
  className,
  summaryClassName = "cursor-pointer text-sm font-medium",
}: {
  summary: ReactNode;
  value: unknown;
  defaultOpen?: boolean;
  className?: string;
  summaryClassName?: string;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <details
      className={className}
      open={open}
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary className={summaryClassName}>{summary}</summary>
      {open && (
        <div className="mt-3">
          <Json value={value} />
        </div>
      )}
    </details>
  );
}

/** Warns unless every recorded execution origin is controller-authored. */
export function EvidenceBasis({ executions }: { executions: unknown[] }) {
  const provenance = executionProvenance(executions);
  if (!provenance) return null;
  return provenance.verified ? (
    <p className="rounded-md border border-dashed p-3 text-xs text-muted-foreground">
      Evidence basis: every recorded probe observation, process and runner
      origin is controller-authored ({originSummary(provenance)}).
    </p>
  ) : (
    <p
      role="note"
      className="rounded-md border border-amber-300/60 bg-amber-50/60 p-3 text-xs text-amber-950 dark:bg-amber-950/20 dark:text-amber-100"
    >
      Evidence basis not verified: recorded origins are{" "}
      {originSummary(provenance)}. Only controller-authored origins count as
      verified; this view does not establish target binding or oracle
      authenticity.
    </p>
  );
}

export function FindingEvidence({ run }: { run: RunDetail }) {
  const evidence = asRecord(run.evidence);
  const manifest = isRecord(evidence.manifest) ? evidence.manifest : null;
  const executions = Array.isArray(evidence.executions)
    ? evidence.executions
    : [];
  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>Evidence</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <ManifestSummary manifest={manifest} />
          <EvidenceSection title="Context" value={evidence.context} />
          <EvidenceSection title="Executions" value={executions} />
          <JsonDetails summary="Raw evidence JSON" value={evidence} />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Agent executions</CardTitle>
        </CardHeader>
        <CardContent>
          {run.invocations.length ? (
            <div className="overflow-auto">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Agent</th>
                    <th>Model</th>
                    <th>Tools / skills</th>
                    <th>Tokens</th>
                    <th>Cost</th>
                    <th>Latency</th>
                  </tr>
                </thead>
                <tbody>
                  {run.invocations.map((inv, index) => (
                    <tr key={`${inv.agent}-${index}`}>
                      <td>{inv.agent || "-"}</td>
                      <td className="font-mono text-xs">
                        {inv.model_name || "-"}
                      </td>
                      <td className="text-xs">
                        {[...inv.tools_called, ...inv.skills_loaded].join(
                          ", ",
                        ) || "—"}
                      </td>
                      <td className="font-mono text-xs">
                        {integer(inv.input_tokens + inv.output_tokens)}
                      </td>
                      <td className="font-mono text-xs">
                        {money(inv.cost_usd)}
                      </td>
                      <td className="font-mono text-xs">
                        {seconds(inv.latency_s)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="empty">No agent invocation records are available.</p>
          )}
          <JsonDetails
            className="mt-4"
            summary="Raw execution JSON"
            value={run.invocations}
          />
        </CardContent>
      </Card>
    </>
  );
}

export function FindingPayloads({ run }: { run: RunDetail }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Finding and result payloads</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-4 lg:grid-cols-2">
        <JsonDetails summary="Raw finding JSON" value={run.finding} />
        <JsonDetails summary="Raw result JSON" value={run.result} />
      </CardContent>
    </Card>
  );
}

function manifestValue(manifest: JsonRecord, section: string, key: string) {
  const value = asRecord(manifest[section])[key];
  return typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
    ? String(value)
    : null;
}
function ManifestSummary({ manifest }: { manifest: JsonRecord | null }) {
  if (!manifest)
    return (
      <div className="rounded-md border border-dashed p-3 text-sm text-muted-foreground">
        No execution manifest identity was recorded.
      </div>
    );
  const fields = [
    ["Source mode", manifestValue(manifest, "source", "source_mode")],
    [
      "Requested revision",
      manifestValue(manifest, "source", "requested_revision"),
    ],
    ["Resolved commit", manifestValue(manifest, "source", "resolved_commit")],
    ["Content hash", manifestValue(manifest, "source", "content_hash")],
    ["Environment status", manifestValue(manifest, "environment", "status")],
    ["Environment scope", manifestValue(manifest, "environment", "scope")],
    ["Image", manifestValue(manifest, "environment", "image_tag")],
    [
      "Adapter contract",
      manifestValue(manifest, "environment", "adapter_contract_version"),
    ],
  ].filter((entry): entry is [string, string] => entry[1] != null);
  return (
    <section
      aria-labelledby="manifest-identity"
      className="rounded-md border bg-muted/20 p-3"
    >
      <div className="mb-3">
        <h2 id="manifest-identity" className="text-sm font-semibold">
          Execution identity
        </h2>
        {fields.length > 0 && (
          <p className="text-xs text-muted-foreground">
            Source and environment identity as recorded in this run's manifest.
            Recorded identity is not execution evidence.
          </p>
        )}
      </div>
      {fields.length ? (
        <dl className="grid gap-3 text-sm sm:grid-cols-2">
          {fields.map(([label, value]) => (
            <div key={label}>
              <dt className="text-xs text-muted-foreground">{label}</dt>
              <dd className="mt-1 break-all font-mono text-xs">{value}</dd>
            </div>
          ))}
        </dl>
      ) : (
        <p className="text-sm text-muted-foreground">
          Manifest present, but no readable identity fields were recorded.
        </p>
      )}
    </section>
  );
}
const SECTION_SUMMARY =
  "flex cursor-pointer items-center gap-2 text-sm font-medium";
function EvidenceSection({ title, value }: { title: string; value: unknown }) {
  const summary = (
    <>
      <CircleAlert className="h-4 w-4 text-primary" />
      {title}
    </>
  );
  return value == null ? (
    <details>
      <summary className={SECTION_SUMMARY}>{summary}</summary>
      <p className="mt-3 text-sm text-muted-foreground">
        No {title.toLowerCase()} evidence recorded.
      </p>
    </details>
  ) : (
    <JsonDetails
      summary={summary}
      summaryClassName={SECTION_SUMMARY}
      value={value}
      defaultOpen
    />
  );
}
