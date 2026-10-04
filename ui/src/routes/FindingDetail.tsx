import { queries, queryKeys } from "@/api/queries";
import { ApiError } from "@/api/http";
import { runActive } from "@/lib/status";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams, useSearch } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { ArrowLeft } from "lucide-react";
import { api } from "@/api/client";
import { EventTimeline } from "@/components/findings/EventTimeline";
import {
  FindingEvidence,
  FindingPayloads,
} from "@/components/findings/FindingEvidence";
import { ReviewForm, REVIEW_VERDICTS } from "@/components/findings/ReviewForm";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { QueryState, Freshness } from "@/components/QueryState";
import { findingNeighbors, queueSearch } from "@/lib/search";
import { money, number, seconds } from "@/lib/format";
import { verdictLabel, verdictVariant } from "@/lib/verdict";

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
function notFound(error: unknown) {
  return error instanceof ApiError && error.status === 404;
}

export function FindingDetail() {
  const { runId } = useParams({ from: "/runs/$runId" });
  const search = useSearch({ from: "/runs/$runId" });
  const returnSearch = queueSearch(search);
  const queryClient = useQueryClient();
  const query = useQuery({
    ...queries.run(runId),
    refetchInterval: (current) =>
      current.state.data && runActive(current.state.data.status) ? 2000 : false,
  });
  const navigation = useQuery({
    queryKey: queryKeys.findingNeighbors(runId, returnSearch),
    queryFn: () => findingNeighbors(runId, returnSearch, api.runPage),
    enabled: search.from_queue && !!query.data,
  });
  const [reviewer, setReviewer] = useState("");
  const [decision, setDecision] = useState("confirm");
  const [overrideLabel, setOverrideLabel] = useState<
    (typeof REVIEW_VERDICTS)[number]
  >(REVIEW_VERDICTS[0]);
  const [reason, setReason] = useState("");
  useEffect(() => {
    setReason("");
    setDecision("confirm");
    setOverrideLabel(REVIEW_VERDICTS[0]);
  }, [runId]);
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
      void queryClient.invalidateQueries({ queryKey: queryKeys.run(runId) });
    },
  });
  const run = query.data;

  if (query.isPending) return <QueryState loading />;
  if (notFound(query.error))
    return (
      <div className="space-y-4">
        <Link
          to="/"
          search={returnSearch}
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
  const executions = Array.isArray(evidence.executions)
    ? evidence.executions
    : [];
  const telemetry = run.telemetry || {};
  const hasTelemetry =
    telemetry.cost_usd != null ||
    telemetry.total_tokens != null ||
    telemetry.wall_time_s != null;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <Link
            to="/"
            search={returnSearch}
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
      {search.from_queue && (
        <div
          className="flex flex-wrap items-center justify-between gap-3"
          aria-label="Finding navigation"
        >
          <p className="text-sm text-muted-foreground">
            {navigation.data?.position != null
              ? `Finding ${navigation.data.position} of ${navigation.data.total} matching the queue filters`
              : navigation.isPending
                ? "Loading queue position…"
                : "Queue results changed; return to the queue to select a finding."}
          </p>
          <div className="flex gap-2">
            {(["previous", "next"] as const).map((direction) => {
              const neighbor = navigation.data?.[direction];
              const label =
                direction === "previous" ? "Previous finding" : "Next finding";
              return neighbor ? (
                <Button key={direction} size="sm" variant="outline" asChild>
                  <Link
                    to="/runs/$runId"
                    params={{ runId: neighbor.id }}
                    search={{
                      ...returnSearch,
                      offset: neighbor.offset,
                      from_queue: true,
                    }}
                  >
                    {label}
                  </Link>
                </Button>
              ) : (
                <Button key={direction} size="sm" variant="outline" disabled>
                  {label}
                </Button>
              );
            })}
          </div>
          {navigation.isError && (
            <QueryState
              error={navigation.error}
              retry={() => void navigation.refetch()}
            />
          )}
        </div>
      )}
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

      <ReviewForm
        run={run}
        reviewer={reviewer}
        setReviewer={setReviewer}
        decision={decision}
        setDecision={setDecision}
        overrideLabel={overrideLabel}
        setOverrideLabel={setOverrideLabel}
        reason={reason}
        setReason={setReason}
        saving={review.isPending}
        error={review.isError ? review.error : null}
        onSave={() => review.mutate()}
      />
      <FindingEvidence run={run} />
      <EventTimeline events={run.events || []} />
      <FindingPayloads run={run} />
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
