import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { api, type Batch } from "@/api/client";
import { QueryState, Freshness } from "@/components/QueryState";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { seconds } from "@/lib/format";
import { parseFindingDetailSearch } from "@/lib/search";
import {
  elapsedSeconds,
  phaseSummary,
  workflowActive,
  workflowCounts,
} from "@/lib/workflow";

function recordedTime(value: string | null | undefined) {
  return value && Number.isFinite(Date.parse(value))
    ? new Date(value).toLocaleString()
    : "Unavailable";
}

function BatchFindings({ batchId }: { batchId: string }) {
  const [offset, setOffset] = useState(0);
  const query = useQuery({
    queryKey: ["workflow-findings", batchId, offset],
    queryFn: () =>
      api.runPage({
        batch_id: batchId,
        offset,
        limit: 10,
        population: "operational",
      }),
    refetchInterval: (q) =>
      q.state.data?.items.some((r) => workflowActive(r.status)) ? 2000 : 10000,
  });
  const page = query.data;
  return (
    <div className="mt-4 border-t pt-4 space-y-3">
      <QueryState
        loading={query.isPending}
        error={query.error}
        retry={() => void query.refetch()}
      />
      <Freshness
        at={page?.as_of ?? query.dataUpdatedAt}
        fetching={query.isFetching}
        stale={query.isError}
      />
      {page?.items.map((run) => (
        <div
          key={run.id}
          className="flex flex-wrap items-start justify-between gap-3 rounded-md border p-3"
        >
          <div className="min-w-0">
            <Link
              to="/runs/$runId"
              params={{ runId: run.id }}
              search={parseFindingDetailSearch({
                batch_id: batchId,
                from_queue: true,
                offset: page.offset,
              })}
              className="font-medium hover:underline"
            >
              {run.title || run.fingerprint}
            </Link>
            <p className="text-xs text-muted-foreground mt-1">
              Recorded phase: {run.phase || "Unavailable"} · Elapsed:{" "}
              {seconds(
                elapsedSeconds(
                  run.telemetry?.accepted_at,
                  run.telemetry?.completed_at,
                  run.status,
                  query.dataUpdatedAt,
                ),
              )}
            </p>
          </div>
          <Badge variant="outline">{run.status}</Badge>
        </div>
      ))}
      {page?.items.length === 0 && (
        <p className="text-sm text-muted-foreground">
          No operational finding records for this batch.
        </p>
      )}
      {page && (
        <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-muted-foreground">
          <span>
            {page.total
              ? `${page.offset + 1}–${page.offset + page.items.length} of ${page.total} findings`
              : "0 findings"}
          </span>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={page.offset === 0 || query.isFetching}
              onClick={() => setOffset(Math.max(0, page.offset - page.limit))}
            >
              Previous findings
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={
                page.offset + page.limit >= page.total || query.isFetching
              }
              onClick={() => setOffset(page.offset + page.limit)}
            >
              Next findings
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

function WorkflowCard({
  batch,
  observedAt,
}: {
  batch: Batch;
  observedAt: number;
}) {
  const [expanded, setExpanded] = useState(false);
  const counts = workflowCounts(batch.status_counts ?? {});
  return (
    <Card>
      <CardContent className="pt-5">
        <div className="flex justify-between items-start gap-4">
          <div>
            <Link
              to="/"
              search={{
                batch_id: batch.id,
                verdict: "",
                search: "",
                offset: 0,
              }}
              className="font-medium hover:underline"
            >
              {batch.label || batch.id}
            </Link>
            <p className="text-xs text-muted-foreground mt-1">
              {batch.finding_count} findings · Created{" "}
              {recordedTime(batch.created_at)}
            </p>
          </div>
          <Badge variant="outline">{batch.status}</Badge>
        </div>
        <div className="mt-4 grid gap-2 text-sm sm:grid-cols-2">
          <p>
            Complete: {counts.complete} · Failed: {counts.failed} · Active:{" "}
            {counts.active}
          </p>
          <p>
            Needs info: {counts.needsInfo} · Cancelled: {counts.cancelled}
          </p>
          <p>
            Current recorded phases: {phaseSummary(batch.current_phases ?? {})}
          </p>
          <p>
            Elapsed:{" "}
            {seconds(
              elapsedSeconds(
                batch.started_at,
                batch.completed_at,
                batch.status,
                observedAt,
              ),
            )}
          </p>
          <p className="sm:col-span-2">
            Last recorded activity: {recordedTime(batch.last_activity_at)}
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          className="mt-4"
          aria-expanded={expanded}
          aria-controls={`batch-findings-${batch.id}`}
          onClick={() => setExpanded(!expanded)}
        >
          {expanded ? "Hide findings" : "Show findings"}
        </Button>
        {expanded && (
          <div id={`batch-findings-${batch.id}`}>
            <BatchFindings batchId={batch.id} />
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export function Workflows() {
  const query = useQuery({
    queryKey: ["batches"],
    queryFn: api.batches,
    refetchInterval: (q) =>
      q.state.data?.some((b) => workflowActive(b.status)) ? 2000 : 10000,
  });
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap justify-between items-end gap-3">
        <div>
          <p className="eyebrow">Execution</p>
          <h1>Workflows</h1>
          <p className="text-sm text-muted-foreground mt-2">
            Persisted finding status and recorded activity. Expand a batch to
            inspect its findings.
          </p>
        </div>
        <Button
          variant="outline"
          disabled={query.isFetching}
          onClick={() => void query.refetch()}
        >
          Refresh
        </Button>
      </div>
      <Freshness
        at={query.dataUpdatedAt}
        fetching={query.isFetching}
        stale={query.isError}
      />
      <QueryState
        loading={query.isPending}
        error={query.error}
        retry={() => void query.refetch()}
      />
      <div className="space-y-3">
        {query.data?.map((batch) => (
          <WorkflowCard
            key={batch.id}
            batch={batch}
            observedAt={query.dataUpdatedAt}
          />
        ))}
        {query.data?.length === 0 && (
          <p className="empty">
            No workflows yet. Submit a batch through the CLI or API.
          </p>
        )}
      </div>
    </div>
  );
}
