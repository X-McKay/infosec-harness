import { req } from "./http.ts";
import type { components, operations } from "./schema";

type Schemas = components["schemas"];
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

/** Callers never choose a population; every read below requests operational records. */
export type RunPageQuery = Omit<
  Query<"run_page_api_run_page_get">,
  "population"
>;
export type ExperimentPageQuery = Omit<
  Query<"experiments_api_experiments_get">,
  "population"
>;

export type RunDetail = Schemas["RunDetail"];
export type Batch = Schemas["BatchSummary"];
export type ExperimentSummary = Schemas["ExperimentSummary"];
export type ExperimentPage = Schemas["ExperimentPage"];
export type ExperimentDetail = Schemas["ExperimentDetail"];
export type ExperimentCase = Schemas["ExperimentCase"];
export type MetricsResponse = Schemas["MetricsResponse"];
export type Distribution = Schemas["Distribution"];
export type TrendPoint = Schemas["TrendPoint"];
export type StageMetric = Schemas["StageMetric"];
export type InvocationRecord = Schemas["InvocationRecord"];
export type ReviewRequest = Schemas["ReviewRequest"];
export type VerdictLabel = Schemas["VerdictLabel"];
export type RuntimeStatus = Schemas["RuntimeStatus"];
export type BrokerStatus = Schemas["BrokerStatus"];
export type ModelConnectivity = Schemas["ModelConnectivity"];

/** Builds an operational-population URL; a caller-supplied population is overridden. */
function operational(path: string, params: object = {}): string {
  const query = new URLSearchParams(
    Object.entries({ ...params, population: "operational" })
      .filter(([, value]) => value != null && value !== "")
      .map(([key, value]) => [key, String(value)]),
  );
  return `${path}?${query}`;
}
const segment = encodeURIComponent;

export const api = {
  runtimeStatus: () =>
    req<Success<"runtime_status_api_runtime_status_get">>(
      "/api/runtime-status",
    ),
  config: () => req<Success<"config_api_config_get">>("/api/config"),
  metrics: () =>
    req<Success<"metrics_api_metrics_get">>(operational("/api/metrics")),
  runPage: (params: RunPageQuery) =>
    req<Success<"run_page_api_run_page_get">>(
      operational("/api/run-page", params),
    ),
  run: (id: string) =>
    req<Success<"run_api_runs__run_id__get">>(
      operational(`/api/runs/${segment(id)}`),
    ),
  review: (id: string, body: ReviewRequest) =>
    req<Success<"review_api_runs__run_id__review_post">>(
      `/api/runs/${segment(id)}/review`,
      { method: "POST", body: JSON.stringify(body) },
    ),
  batches: () =>
    req<Success<"batches_api_batches_get">>(operational("/api/batches")),
  experiments: (params: ExperimentPageQuery = {}) =>
    req<Success<"experiments_api_experiments_get">>(
      operational("/api/experiments", params),
    ),
  experiment: (id: string) =>
    req<Success<"experiment_detail_api_experiments__experiment_id__get">>(
      operational(`/api/experiments/${segment(id)}`),
    ),
};
