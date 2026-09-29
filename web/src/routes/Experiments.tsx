import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "@/api/client";
import { Freshness, QueryState } from "@/components/QueryState";
import {
  ExperimentContent,
  normalize,
  type ExperimentDetail,
} from "@/components/evaluations/ExperimentReport";

export function Experiments() {
  const listQuery = useQuery({
    queryKey: ["experiments"],
    queryFn: async () => (await api.experiments()).map(normalize),
  });
  const experiments = listQuery.data || [];
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selected = selectedId
    ? experiments.find((item) => item.id === selectedId)
    : experiments[0];
  const detailQuery = useQuery({
    queryKey: ["experiment", selected?.id],
    queryFn: async () =>
      api.experiment(selected!.id) as Promise<ExperimentDetail>,
    enabled: !!selected?.id,
  });

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="eyebrow">Controlled comparisons</p>
          <h1>Experiments</h1>
          <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
            Inspect model, configuration, provenance, completion, efficacy,
            cost, and latency evidence. Missing measurements stay unavailable.
          </p>
        </div>
        <Freshness
          at={listQuery.dataUpdatedAt}
          fetching={listQuery.isFetching}
          stale={listQuery.isError && !!experiments.length}
        />
      </header>
      {!experiments.length && (
        <QueryState
          loading={listQuery.isPending}
          error={listQuery.error}
          retry={() => void listQuery.refetch()}
        />
      )}
      {experiments.length > 0 && (
        <ExperimentContent
          experiments={experiments}
          selected={selected}
          setSelectedId={setSelectedId}
          detail={detailQuery.data}
          detailQuery={detailQuery}
        />
      )}
    </div>
  );
}
