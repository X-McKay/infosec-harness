import { queryOptions } from "@tanstack/react-query";
import { api, type RunPageQuery } from "./client.ts";

// Keep keys and fetchers together; each view retains its existing polling policy.
export const queryKeys = {
  runtime: ["runtime-status"] as const,
  qualification: ["qualification"] as const,
  config: ["config"] as const,
  batches: ["batches"] as const,
  experiments: ["experiments"] as const,
  metrics: ["metrics", "operational"] as const,
  run: (id: string) => ["run", id] as const,
  runPage: (search: unknown) => ["run-page", search] as const,
  findingNeighbors: (id: string, search: unknown) =>
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
      refetchInterval: 30000,
    }),
  qualification: () =>
    queryOptions({
      queryKey: queryKeys.qualification,
      queryFn: api.qualification,
      refetchInterval: 30000,
    }),
  config: () =>
    queryOptions({ queryKey: queryKeys.config, queryFn: api.config }),
  batches: () =>
    queryOptions({ queryKey: queryKeys.batches, queryFn: api.batches }),
  experiments: () =>
    queryOptions({
      queryKey: queryKeys.experiments,
      queryFn: api.experiments,
      refetchInterval: 10000,
    }),
  metrics: () =>
    queryOptions({
      queryKey: queryKeys.metrics,
      queryFn: api.metrics,
      refetchInterval: 10000,
    }),
  run: (id: string) =>
    queryOptions({ queryKey: queryKeys.run(id), queryFn: () => api.run(id) }),
  runPage: (search: unknown, params: RunPageQuery) =>
    queryOptions({
      queryKey: queryKeys.runPage(search),
      queryFn: () => api.runPage(params),
    }),
  workflowFindings: (id: string, offset: number) =>
    queryOptions({
      queryKey: queryKeys.workflowFindings(id, offset),
      queryFn: () =>
        api.runPage({
          batch_id: id,
          offset,
          limit: 10,
          population: "operational",
        }),
    }),
  experiment: (id: string | undefined) =>
    queryOptions({
      queryKey: queryKeys.experiment(id),
      queryFn: () => api.experiment(id!),
      enabled: !!id,
    }),
};
