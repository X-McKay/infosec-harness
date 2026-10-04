import { CircleAlert } from "lucide-react";
import type { RunDetail } from "@/api/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { money, number, seconds } from "@/lib/format";

type JsonRecord = Record<string, unknown>;
function Json({ value }: { value: unknown }) {
  return (
    <pre className="max-h-80 overflow-auto rounded-md bg-muted p-3 text-xs">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}
function isRecord(value: unknown): value is JsonRecord {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}
export function FindingEvidence({ run }: { run: RunDetail }) {
  const evidence = isRecord(run.evidence) ? run.evidence : {};
  const manifest = isRecord(evidence.manifest) ? evidence.manifest : null;
  const context = evidence.context;
  const executions = list(evidence.executions);
  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>Evidence</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <ManifestSummary manifest={manifest} />
          <EvidenceSection title="Context" value={context} />
          <EvidenceSection title="Executions" value={executions} />
          <details>
            <summary className="cursor-pointer text-sm font-medium">
              Raw evidence JSON
            </summary>
            <div className="mt-3">
              <Json value={evidence} />
            </div>
          </details>
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
                    <tr key={`${String(inv.agent)}-${index}`}>
                      <td>{String(inv.agent || "-")}</td>
                      <td className="font-mono text-xs">
                        {String(inv.model_name || "-")}
                      </td>
                      <td className="text-xs">
                        {[...list(inv.tools_called), ...list(inv.skills_loaded)]
                          .map(String)
                          .join(", ") || "—"}
                      </td>
                      <td className="font-mono text-xs">
                        {number(
                          Number(inv.input_tokens || 0) +
                            Number(inv.output_tokens || 0),
                          0,
                        )}
                      </td>
                      <td className="font-mono text-xs">
                        {inv.cost_usd == null
                          ? "Unavailable"
                          : money(Number(inv.cost_usd))}
                      </td>
                      <td className="font-mono text-xs">
                        {inv.latency_s == null
                          ? "Unavailable"
                          : seconds(Number(inv.latency_s))}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="empty">No agent invocation records are available.</p>
          )}
          <details className="mt-4">
            <summary className="cursor-pointer text-sm font-medium">
              Raw execution JSON
            </summary>
            <div className="mt-3">
              <Json value={run.invocations} />
            </div>
          </details>
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
        <details>
          <summary className="cursor-pointer text-sm font-medium">
            Raw finding JSON
          </summary>
          <div className="mt-3">
            <Json value={run.finding} />
          </div>
        </details>
        <details>
          <summary className="cursor-pointer text-sm font-medium">
            Raw result JSON
          </summary>
          <div className="mt-3">
            <Json value={run.result} />
          </div>
        </details>
      </CardContent>
    </Card>
  );
}

function manifestValue(manifest: JsonRecord, section: string, key: string) {
  const value = isRecord(manifest[section])
    ? manifest[section][key]
    : undefined;
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
        <p className="text-xs text-muted-foreground">
          Safe source and environment metadata recorded with this run.
        </p>
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
function EvidenceSection({ title, value }: { title: string; value: unknown }) {
  return (
    <details open={value != null}>
      <summary className="flex cursor-pointer items-center gap-2 text-sm font-medium">
        <CircleAlert className="h-4 w-4 text-primary" />
        {title}
      </summary>
      <div className="mt-3">
        {value == null ? (
          <p className="text-sm text-muted-foreground">
            No {title.toLowerCase()} evidence recorded.
          </p>
        ) : (
          <Json value={value} />
        )}
      </div>
    </details>
  );
}
