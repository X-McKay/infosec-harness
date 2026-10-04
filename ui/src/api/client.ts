import type { components, operations } from "./schema";

type Success<Operation extends keyof operations> =
  operations[Operation] extends {
    responses: { 200: { content: { "application/json": infer Response } } };
  }
    ? Response
    : never;
type Query<Operation extends keyof operations> = operations[Operation] extends {
  parameters: { query?: infer Parameters };
}
  ? NonNullable<Parameters>
  : never;
export type RunPageQuery = Query<"run_page_api_run_page_get">;
export type MetricsPopulation = NonNullable<
  Query<"metrics_api_metrics_get">["population"]
>;

export type RunSummary = components["schemas"]["RunSummary"];
export type RunDetail = components["schemas"]["RunDetail"];
export type Batch = components["schemas"]["BatchSummary"];
export type BatchDetail = components["schemas"]["BatchDetail"];
export type ExperimentSummary = components["schemas"]["ExperimentSummary"];
export type ExperimentDetail = components["schemas"]["ExperimentDetail"];
export type ExperimentCase = components["schemas"]["ExperimentCase"];

export type RuntimeStatus = components["schemas"]["RuntimeStatus"];
export type QualificationStatus = components["schemas"]["QualificationStatus"];

const BASE = "";

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
  });
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  return res.json() as Promise<T>;
}

export const api = {
  runtimeStatus: () =>
    req<Success<"runtime_status_api_runtime_status_get">>(
      "/api/runtime-status",
    ),
  qualification: () =>
    req<Success<"qualification_api_qualification_get">>("/api/qualification"),
  metrics: () =>
    req<Success<"metrics_api_metrics_get">>(
      "/api/metrics?population=operational",
    ),
  runPage: (params: RunPageQuery) =>
    req<Success<"run_page_api_run_page_get">>(
      `/api/run-page?${new URLSearchParams(
        Object.entries({ ...params, population: "operational" })
          .filter(([, v]) => v != null && v !== "")
          .map(([k, v]) => [k, String(v)]),
      )}`,
    ),
  experiment: (id: string) =>
    req<Success<"experiment_detail_api_experiments__experiment_id__get">>(
      `/api/experiments/${encodeURIComponent(id)}?population=operational`,
    ),
  batches: () =>
    req<Success<"batches_api_batches_get">>(
      "/api/batches?population=operational",
    ),
  batch: (id: string) =>
    req<Success<"batch_api_batches__batch_id__get">>(
      `/api/batches/${encodeURIComponent(id)}?population=operational`,
    ),
  runs: (params: Query<"runs_api_runs_get"> = {}) => {
    const q = new URLSearchParams(
      Object.entries({ ...params, population: "operational" })
        .filter(([, value]) => value != null && value !== "")
        .map(([key, value]) => [key, String(value)]),
    ).toString();
    return req<Success<"runs_api_runs_get">>(`/api/runs${q ? `?${q}` : ""}`);
  },
  run: (id: string) =>
    req<Success<"run_api_runs__run_id__get">>(
      `/api/runs/${encodeURIComponent(id)}?population=operational`,
    ),
  submit: (body: components["schemas"]["SubmitRequest"]) =>
    req<Success<"submit_api_batches_post">>("/api/batches", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  review: (id: string, body: components["schemas"]["ReviewRequest"]) =>
    req<Success<"review_api_runs__run_id__review_post">>(
      `/api/runs/${id}/review`,
      {
        method: "POST",
        body: JSON.stringify(body),
      },
    ),
  experiments: () =>
    req<Success<"experiments_api_experiments_get">>(
      "/api/experiments?population=operational",
    ),
  config: () => req<Success<"config_api_config_get">>("/api/config"),
};
