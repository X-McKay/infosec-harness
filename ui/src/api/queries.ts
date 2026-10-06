/** Every request the UI makes: same-origin /api paths through req(). */
import { queryOptions, type QueryClient } from "@tanstack/react-query";
import { ApiError, req } from "./http.ts";
import type { components, operations } from "./schema";
import { eventsPath, normalizeEvents } from "../lib/events.ts";
import { runActive } from "../lib/status.ts";

type Finding = components["schemas"]["Finding"];
type RunState = components["schemas"]["RunState"];
type RunPage = components["schemas"]["RunPage"];
export type Health =
  operations["health_api_health_get"]["responses"][200]["content"]["application/json"];

export const LIST_REFRESH_MS = 5000;
export const ACTIVE_RUN_REFRESH_MS = 3000;
export const HEALTH_REFRESH_MS = 30000;

export const runsPath = (pageToken?: string) =>
  `/api/runs${pageToken ? `?page_token=${encodeURIComponent(pageToken)}` : ""}`;
export const runPath = (runId: string) =>
  `/api/runs/${encodeURIComponent(runId)}`;

/** Fast refresh only while the recorded status is active; terminal runs do not change. */
export function runRefreshInterval(status: string | undefined): number | false {
  return runActive(status) ? ACTIVE_RUN_REFRESH_MS : false;
}
/** A 404 is an answer, not a transient failure: never retried. */
export function retryUnlessNotFound(failureCount: number, error: Error) {
  return (
    !(error instanceof ApiError && error.status === 404) && failureCount < 1
  );
}

export const queryKeys = {
  health: ["health"] as const,
  runs: (pageToken: string) => ["runs", pageToken] as const,
  run: (runId: string) => ["run", runId] as const,
  events: (runId: string) => ["run-events", runId] as const,
};

export const queries = {
  health: () =>
    queryOptions({
      queryKey: queryKeys.health,
      queryFn: ({ signal }) => req<Health>("/api/health", { signal }),
      refetchInterval: HEALTH_REFRESH_MS,
    }),
  runs: (pageToken = "") =>
    queryOptions({
      queryKey: queryKeys.runs(pageToken),
      queryFn: ({ signal }) => req<RunPage>(runsPath(pageToken), { signal }),
      refetchInterval: LIST_REFRESH_MS,
    }),
  run: (runId: string) =>
    queryOptions({
      queryKey: queryKeys.run(runId),
      queryFn: ({ signal }) => req<RunState>(runPath(runId), { signal }),
      refetchInterval: (query) => runRefreshInterval(query.state.data?.status),
      retry: retryUnlessNotFound,
    }),
  events: (runId: string, active: boolean) =>
    queryOptions({
      queryKey: queryKeys.events(runId),
      queryFn: async ({ signal }) =>
        normalizeEvents(await req<unknown>(eventsPath(runId), { signal })),
      refetchInterval: active ? ACTIVE_RUN_REFRESH_MS : false,
      retry: retryUnlessNotFound,
    }),
};

export const mutations = {
  submit: (client: QueryClient) => ({
    mutationFn: (finding: Finding) =>
      req<RunState>("/api/runs", {
        method: "POST",
        body: JSON.stringify(finding),
      }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["runs"] }),
  }),
  cancel: (client: QueryClient, runId: string) => ({
    mutationFn: () =>
      req<Record<string, string>>(`${runPath(runId)}/cancel`, {
        method: "POST",
      }),
    onSuccess: () =>
      Promise.all([
        client.invalidateQueries({ queryKey: queryKeys.run(runId) }),
        client.invalidateQueries({ queryKey: queryKeys.events(runId) }),
        client.invalidateQueries({ queryKey: ["runs"] }),
      ]),
  }),
};
