import { queries } from "@/api/queries";
import { ApiError } from "@/api/http";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams, useSearch } from "@tanstack/react-router";
import { ArrowLeft } from "lucide-react";
import { EventTimeline } from "@/components/findings/EventTimeline";
import {
  EvidenceBasis,
  FindingEvidence,
  FindingPayloads,
} from "@/components/findings/FindingEvidence";
import { ReviewForm } from "@/components/findings/ReviewForm";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { QueryState, Freshness } from "@/components/QueryState";
import { queueSearch } from "@/lib/search";
import { integer, money, percent, seconds } from "@/lib/format";
import { asRecord, text } from "@/lib/json";
import { verdictLabel, verdictVariant } from "@/lib/verdict";

function notFound(error: unknown) {
  return error instanceof ApiError && error.status === 404;
}

export function FindingDetail() {
  const { runId } = useParams({ from: "/runs/$runId" });
  const search = useSearch({ from: "/runs/$runId" });
  const returnSearch = queueSearch(search);
  const query = useQuery(queries.run(runId));
  const navigation = useQuery({
    ...queries.findingNeighbors(runId, returnSearch),
    enabled: search.from_queue && !!query.data,
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

  const verdict = asRecord(run.result?.verdict);
  const executions = run.evidence?.executions ?? [];
  const telemetry = run.telemetry;
  const hasTelemetry =
    telemetry?.cost_usd != null ||
    telemetry?.total_tokens != null ||
    telemetry?.wall_time_s != null;

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
        <nav
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
        </nav>
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
              {text(verdict.rationale) ||
                run.inconclusive_reason ||
                "No rationale recorded."}
            </p>
            <EvidenceBasis executions={executions} />
            <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
              <span>Confidence {percent(run.confidence, 0)}</span>
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
            <Metric label="Cost" value={money(telemetry?.cost_usd)} />
            <Metric label="Tokens" value={integer(telemetry?.total_tokens)} />
            <Metric label="Wall time" value={seconds(telemetry?.wall_time_s)} />
            {!hasTelemetry && (
              <p className="col-span-3 text-xs text-muted-foreground">
                {telemetry
                  ? "Usage is not fully accounted for this run, so totals are unavailable."
                  : "No telemetry is recorded for this run."}
              </p>
            )}
            {!hasTelemetry && telemetry && (
              <p className="col-span-3 text-xs text-muted-foreground">
                Recorded calls (a lower bound):{" "}
                {money(telemetry.known_cost_usd)} ·{" "}
                {integer(telemetry.known_tokens)} tokens ·{" "}
                {seconds(telemetry.agent_time_s)} agent time
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      <ReviewForm key={run.id} run={run} />
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
