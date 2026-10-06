/** Every request the UI makes: same-origin /api paths through req(). */
import { queryOptions, type QueryClient } from "@tanstack/react-query";
import { ApiError, req } from "./http.ts";
import type { components } from "./schema";
import { eventsPath, normalizeEvents } from "../lib/events.ts";
import { isRecord } from "../lib/json.ts";
import { runActive } from "../lib/status.ts";

type Finding = components["schemas"]["Finding"];
type RunState = components["schemas"]["RunState"];
type RunPage = components["schemas"]["RunPage"];
export type Health = components["schemas"]["Health"];

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

/**
 * GET /api/health. The API answers 503 with the same Health body when Temporal is unreachable;
 * that is a reported state, not a transport failure. Any other failure (including a 503 from a
 * proxy without that body) stays an error.
 */
export async function fetchHealth(signal?: AbortSignal): Promise<Health> {
  try {
    return await req<Health>("/api/health", { signal });
  } catch (error) {
    if (error instanceof ApiError && error.status === 503) {
      let body: unknown;
      try {
        body = JSON.parse(error.body);
      } catch {
        throw error;
      }
      if (isRecord(body) && body.status === "temporal_unavailable")
        return body as Health;
    }
    throw error;
  }
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
      queryFn: ({ signal }) => fetchHealth(signal),
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
