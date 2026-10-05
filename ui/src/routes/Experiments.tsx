import { EXPERIMENT_PAGE_SIZE, queries } from "@/api/queries";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { Button } from "@/components/ui/button";
import { Freshness, QueryState } from "@/components/QueryState";
import { ExperimentContent } from "@/components/evaluations/ExperimentReport";

export function Experiments() {
  const [offset, setOffset] = useState(0);
  const listQuery = useQuery(queries.experiments(offset));
  const page = listQuery.data;
  const experiments = page?.items || [];
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selected = selectedId
    ? experiments.find((item) => item.id === selectedId)
    : experiments[0];
  const detailQuery = useQuery(queries.experiment(selected?.id));

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="eyebrow">Controlled comparisons</p>
          <h1>Evaluations</h1>
          <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
            Inspect model, configuration, provenance, completion, efficacy,
            cost, and latency evidence. Missing measurements stay unavailable.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            disabled={listQuery.isFetching || detailQuery.isFetching}
            onClick={() => {
              void listQuery.refetch();
              if (selected) void detailQuery.refetch();
            }}
          >
            Refresh
          </Button>
          <Freshness
            at={listQuery.dataUpdatedAt}
            fetching={listQuery.isFetching}
            stale={listQuery.isError && !!experiments.length}
          />
        </div>
      </header>
      {!experiments.length && (
        <QueryState
          loading={listQuery.isPending}
          error={listQuery.error}
          retry={() => void listQuery.refetch()}
        />
      )}
      {!listQuery.isPending && !listQuery.isError && !experiments.length && (
        <div className="rounded-lg border p-6 text-sm text-muted-foreground">
          <p className="font-medium text-foreground">
            No operational evaluations in this database
          </p>
          <p className="mt-2">
            Evaluation results appear here when an evaluation writes to this
            API’s database. Accepted agent qualification evidence is committed
            under <code>evals/baselines/</code>; runtime observations are under{" "}
            <Link to="/qualification" className="text-primary underline">
              Qualification
            </Link>
            .
          </p>
          <p className="mt-2 text-xs">
            Use Refresh to check for new evaluations.
          </p>
        </div>
      )}
      {page && page.total > page.limit && (
        <div className="flex items-center justify-between gap-3 text-sm">
          <p className="text-muted-foreground">
            Experiments {page.offset + 1}–{page.offset + experiments.length} of{" "}
            {page.total}, newest first. Comparisons use this page only.
          </p>
          <div className="flex gap-2">
            <Button
              variant="outline"
              disabled={offset === 0 || listQuery.isFetching}
              onClick={() => {
                setSelectedId(null);
                setOffset(Math.max(0, offset - EXPERIMENT_PAGE_SIZE));
              }}
            >
              Newer
            </Button>
            <Button
              variant="outline"
              disabled={
                page.offset + experiments.length >= page.total ||
                listQuery.isFetching
              }
              onClick={() => {
                setSelectedId(null);
                setOffset(offset + EXPERIMENT_PAGE_SIZE);
              }}
            >
              Older
            </Button>
          </div>
        </div>
      )}
      {experiments.length > 0 && (
        <ExperimentContent
          experiments={experiments}
          selected={selected}
          setSelectedId={setSelectedId}
          detailQuery={detailQuery}
        />
      )}
    </div>
  );
}
