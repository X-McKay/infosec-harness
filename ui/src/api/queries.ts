import { queryOptions, type QueryClient } from "@tanstack/react-query";
import { batchActive, experimentActive, runActive } from "../lib/status.ts";
import {
  findingNeighbors,
  findingPageQuery,
  type FindingSearch,
} from "../lib/search.ts";
import { api, type ReviewRequest } from "./client.ts";

/** Polling: fast only while recorded state is active; otherwise slow or manual refresh. */
export const ACTIVE_REFRESH_MS = 2000;
export const EVALUATION_REFRESH_MS = 10000;
export const IDLE_REFRESH_MS = 30000;
export const METRICS_REFRESH_MS = 60000;
export const EXPERIMENT_PAGE_SIZE = 25;

export const queryKeys = {
  runtime: ["runtime-status"] as const,
  config: ["config"] as const,
  batches: ["batches"] as const,
  experiments: (offset: number) => ["experiments", offset] as const,
  metrics: ["metrics"] as const,
  run: (id: string) => ["run", id] as const,
  runPage: (search: FindingSearch) => ["run-page", search] as const,
  findingNeighbors: (id: string, search: FindingSearch) =>
    ["finding-neighbors", id, search] as const,
  workflowFindings: (id: string, offset: number) =>
    ["workflow-findings", id, offset] as const,
  experiment: (id: string | undefined) => ["experiment", id] as const,
};

export const queries = {
  runtime: () =>
    queryOptions({
      queryKey: queryKeys.runtime,
      queryFn: api.runtimeStatus,
      refetchInterval: IDLE_REFRESH_MS,
    }),
  config: () =>
    queryOptions({ queryKey: queryKeys.config, queryFn: api.config }),
  // Polls only while a recorded batch is active; an idle list refreshes on demand.
  batches: () =>
    queryOptions({
      queryKey: queryKeys.batches,
      queryFn: api.batches,
      refetchInterval: (query) =>
        query.state.data?.some((batch) => batchActive(batch.status))
          ? ACTIVE_REFRESH_MS
          : false,
    }),
  // One page of headline summaries; full metrics are read per experiment.
  experiments: (offset = 0) =>
    queryOptions({
      queryKey: queryKeys.experiments(offset),
      queryFn: () => api.experiments({ offset, limit: EXPERIMENT_PAGE_SIZE }),
      refetchInterval: (query) =>
        query.state.data?.items.some((item) => experimentActive(item.status))
          ? EVALUATION_REFRESH_MS
          : false,
    }),
  experiment: (id: string | undefined) =>
    queryOptions({
      queryKey: queryKeys.experiment(id),
      queryFn: () => api.experiment(id!),
      enabled: !!id,
      refetchInterval: (query) =>
        experimentActive(query.state.data?.metrics.status)
          ? EVALUATION_REFRESH_MS
          : false,
    }),
  metrics: () =>
    queryOptions({
      queryKey: queryKeys.metrics,
      queryFn: api.metrics,
      refetchInterval: METRICS_REFRESH_MS,
    }),
  run: (id: string) =>
    queryOptions({
      queryKey: queryKeys.run(id),
      queryFn: () => api.run(id),
      refetchInterval: (query) =>
        query.state.data && runActive(query.state.data.status)
          ? ACTIVE_REFRESH_MS
          : false,
    }),
  runPage: (search: FindingSearch) =>
    queryOptions({
      queryKey: queryKeys.runPage(search),
      queryFn: () => api.runPage(findingPageQuery(search)),
      refetchInterval: (query) =>
        query.state.data?.items.some((run) => runActive(run.status))
          ? ACTIVE_REFRESH_MS
          : false,
    }),
  findingNeighbors: (id: string, search: FindingSearch) =>
    queryOptions({
      queryKey: queryKeys.findingNeighbors(id, search),
      queryFn: () => findingNeighbors(id, search, api.runPage),
    }),
  workflowFindings: (id: string, offset: number) =>
    queryOptions({
      queryKey: queryKeys.workflowFindings(id, offset),
      queryFn: () => api.runPage({ batch_id: id, offset, limit: 10 }),
      refetchInterval: (query) =>
        query.state.data?.items.some((run) => runActive(run.status))
          ? ACTIVE_REFRESH_MS
          : false,
    }),
};

export const mutations = {
  /** Scoped to one run: saving invalidates only that run's cached detail. */
  review: (queryClient: QueryClient, runId: string) => ({
    mutationKey: ["review", runId] as const,
    mutationFn: (body: ReviewRequest) => api.review(runId, body),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: queryKeys.run(runId) }),
  }),
};
