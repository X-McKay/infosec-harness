import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { useState } from "react";
import { ArrowLeft, CircleAlert, Clock3 } from "lucide-react";
import { api, type RunDetail } from "@/api/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { QueryState, Freshness } from "@/components/QueryState";
import { money, number, seconds } from "@/lib/format";
import { verdictLabel, verdictVariant } from "@/lib/verdict";

type JsonRecord = Record<string, unknown>;
const VERDICTS = [
  "potentially_exploitable",
  "inconclusive",
  "likely_not_exploitable",
];
const ACTIVE = new Set([
  "pending",
  "accepted",
  "running",
  "preparing",
  "building",
  "probing",
  "triaging",
]);

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
function notFound(error: unknown) {
  return error instanceof Error && error.message.startsWith("404");
}

export function FindingDetail() {
  const { runId } = useParams({ from: "/runs/$runId" });
  const queryClient = useQueryClient();
  const query = useQuery<RunDetail>({
    queryKey: ["run", runId],
    queryFn: () => api.run(runId),
    refetchInterval: (current) =>
      current.state.data && ACTIVE.has(current.state.data.status)
        ? 2000
        : false,
  });
  const [reviewer, setReviewer] = useState("");
  const [decision, setDecision] = useState("confirm");
  const [overrideLabel, setOverrideLabel] = useState(VERDICTS[0]);
  const [reason, setReason] = useState("");
  const review = useMutation({
    mutationFn: () =>
      api.review(runId, {
        reviewer: reviewer.trim(),
        decision,
        reason,
        override_label: decision === "override" ? overrideLabel : null,
      }),
    onSuccess: () => {
      setReason("");
      void queryClient.invalidateQueries({ queryKey: ["run", runId] });
    },
  });
  const run = query.data;

  if (query.isPending) return <QueryState loading />;
  if (notFound(query.error))
    return (
      <div className="space-y-4">
        <Link
          to="/"
          search={{ verdict: "", batch_id: "", search: "", offset: 0 }}
          className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-4 w-4" /> Back to queue
        </Link>
        <Card>
          <CardContent className="space-y-2 pt-6">
            <h1>Finding not found</h1>
            <p className="text-sm text-muted-foreground">
              Run <code>{runId}</code> is not available in the current store.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  if (query.error && !run)
    return (
      <QueryState error={query.error} retry={() => void query.refetch()} />
    );
  if (!run) return null;

  const verdict = isRecord(run.result?.verdict) ? run.result.verdict : {};
  const evidence = isRecord(run.evidence) ? run.evidence : {};
  const manifest = isRecord(evidence.manifest) ? evidence.manifest : null;
  const context = evidence.context;
  const executions = list(evidence.executions);
  const telemetry = run.telemetry || {};
  const hasTelemetry =
    telemetry.cost_usd != null ||
    telemetry.total_tokens != null ||
    telemetry.wall_time_s != null;
  const events = run.events || [];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <Link
            to="/"
            search={{ verdict: "", batch_id: "", search: "", offset: 0 }}
            className="mb-4 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="h-4 w-4" /> Back to queue
          </Link>
          <p className="eyebrow">Finding detail</p>
          <h1>{run.title}</h1>
          <p className="mt-2 text-sm text-muted-foreground">
            {run.repo_url} · {run.revision} · {run.cwe || "No CWE recorded"}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline">{run.priority || "Unprioritized"}</Badge>
          <Badge variant={verdictVariant(run.verdict)}>
            {verdictLabel(run.verdict)}
          </Badge>
        </div>
      </div>
      <Freshness
        at={query.dataUpdatedAt}
        fetching={query.isFetching}
        stale={query.isError}
      />
      {query.isError && (
        <QueryState error={query.error} retry={() => void query.refetch()} />
      )}

      <div className="grid gap-5 lg:grid-cols-[1.5fr_1fr]">
        <Card>
          <CardHeader>
            <CardTitle>Recorded verdict</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <p>
              {String(
                verdict.rationale ||
                  run.inconclusive_reason ||
                  "No rationale recorded.",
              )}
            </p>
            {executions.length > 0 && (
              <p className="rounded-md border border-dashed p-3 text-xs text-muted-foreground">
                Evidence basis: probe observations use legacy self-reported
                markers. This adapter does not independently verify target
                binding or oracle authenticity.
              </p>
            )}
            <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
              <span>
                Confidence{" "}
                {run.confidence == null
                  ? "Unavailable"
                  : `${Math.round(run.confidence * 100)}%`}
              </span>
              <span>Environment {run.environment_scope || "Unavailable"}</span>
              <span>Phase {run.phase || run.status}</span>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Telemetry</CardTitle>
          </CardHeader>
          <CardContent className="grid grid-cols-3 gap-3 text-sm">
            <Metric
              label="Cost"
              value={
                telemetry.cost_usd == null
                  ? "Unavailable"
                  : money(telemetry.cost_usd)
              }
            />
            <Metric
              label="Tokens"
              value={
                telemetry.total_tokens == null
                  ? "Unavailable"
                  : number(telemetry.total_tokens, 0)
              }
            />
            <Metric
              label="Wall time"
              value={
                telemetry.wall_time_s == null
                  ? "Unavailable"
                  : seconds(telemetry.wall_time_s)
              }
            />
            {!hasTelemetry && (
              <p className="col-span-3 text-xs text-muted-foreground">
                Durable telemetry is not recorded for this run. Legacy aggregate
                fields are retained below for context.
              </p>
            )}
            {!hasTelemetry && (
              <p className="col-span-3 text-xs text-muted-foreground">
                Legacy aggregate: {money(run.cost_usd)} ·{" "}
                {number(run.total_tokens, 0)} tokens · {seconds(run.latency_s)}
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Analyst review</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="text-sm">
              Reviewer
              <input
                className="field mt-1 w-full"
                value={reviewer}
                onChange={(event) => setReviewer(event.target.value)}
                placeholder="Name or team"
              />
            </label>
            <label className="text-sm">
              Decision
              <select
                className="field mt-1 w-full"
                value={decision}
                onChange={(event) => setDecision(event.target.value)}
              >
                <option value="confirm">Confirm recorded verdict</option>
                <option value="override">Override verdict</option>
              </select>
            </label>
          </div>
          {decision === "override" && (
            <label className="block text-sm">
              Override verdict
              <select
                className="field mt-1 w-full"
                value={overrideLabel}
                onChange={(event) => setOverrideLabel(event.target.value)}
              >
                {VERDICTS.map((value) => (
                  <option key={value} value={value}>
                    {verdictLabel(value)}
                  </option>
                ))}
              </select>
            </label>
          )}
          <label className="block text-sm">
            Reason
            <textarea
              className="field mt-1 min-h-20 w-full"
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              placeholder="Explain the evidence for this review"
            />
          </label>
          {review.isError && (
            <p role="alert" className="text-sm text-destructive">
              Could not save review: {review.error.message}
            </p>
          )}
          <Button
            disabled={
              review.isPending ||
              !reviewer.trim() ||
              (decision === "override" && !reason.trim())
            }
            onClick={() => review.mutate()}
          >
            {review.isPending ? "Saving…" : "Save review"}
          </Button>
          {run.review && (
            <div className="rounded-md border bg-muted/30 p-3 text-sm">
              <p>
                <strong>Current review:</strong>{" "}
                {run.review.reviewer || "Unnamed reviewer"} ·{" "}
                {run.review.decision}
                {run.review.override_label
                  ? ` → ${verdictLabel(run.review.override_label)}`
                  : ""}
              </p>
              <p className="mt-1 text-muted-foreground">
                {run.review.reason || "No reason recorded."}
              </p>
            </div>
          )}
          {run.review_history?.length > 0 && (
            <div>
              <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Review history
              </p>
              <div className="space-y-2">
                {run.review_history.map((entry, index) => (
                  <div
                    key={`${entry.created_at}-${index}`}
                    className="border-l-2 pl-3 text-sm"
                  >
                    <p>
                      {entry.reviewer || "Unnamed reviewer"} · {entry.decision}
                      {entry.override_label
                        ? ` → ${verdictLabel(String(entry.override_label))}`
                        : ""}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {entry.reason || "No reason recorded."} ·{" "}
                      {new Date(entry.created_at).toLocaleString()}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

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
      <Card>
        <CardHeader>
          <CardTitle>Event timeline</CardTitle>
        </CardHeader>
        <CardContent>
          {events.length ? (
            <ol className="space-y-3">
              {events.map((event) => (
                <li key={event.id} className="flex gap-3 text-sm">
                  <Clock3 className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
                  <div>
                    <p className="font-medium">{event.phase}</p>
                    <p className="text-muted-foreground">{event.detail}</p>
                    <time className="text-xs text-muted-foreground">
                      {new Date(event.created_at).toLocaleString()}
                    </time>
                  </div>
                </li>
              ))}
            </ol>
          ) : (
            <p className="empty">No lifecycle events recorded.</p>
          )}
        </CardContent>
      </Card>
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
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="mt-1 font-medium tabular-nums">{value}</p>
    </div>
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
