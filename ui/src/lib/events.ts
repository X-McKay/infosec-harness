/**
 * GET /api/runs/{id}/events: a bounded projection of the investigation's Temporal history.
 * Hand-typed until the endpoint is in openapi.json; replace with components["schemas"] types
 * after `just regenerate`. An API without the endpoint answers 404 and the timeline hides.
 */
import { ApiError } from "../api/http.ts";
import { isRecord } from "./json.ts";

export interface RunEvent {
  at: string;
  kind: string;
  name: string;
  detail: string;
}
export interface RunEvents {
  run_id: string;
  events: RunEvent[];
  truncated: boolean;
}

export const eventsPath = (runId: string) =>
  `/api/runs/${encodeURIComponent(runId)}/events`;

/** The endpoint is absent (or the run unknown to it): hide the section rather than fail. */
export function eventsUnavailable(error: unknown): boolean {
  return error instanceof ApiError && error.status === 404;
}

const str = (value: unknown) => (typeof value === "string" ? value : "");

/** Narrow the response; malformed entries are dropped and counted, never invented. */
export function normalizeEvents(
  value: unknown,
): RunEvents & { dropped: number } {
  const record = isRecord(value) ? value : {};
  const raw = Array.isArray(record.events) ? record.events : [];
  const events: RunEvent[] = [];
  for (const item of raw) {
    if (!isRecord(item) || (!str(item.kind) && !str(item.name))) continue;
    const detail = item.detail;
    events.push({
      at: str(item.at),
      kind: str(item.kind),
      name: str(item.name),
      detail:
        typeof detail === "string"
          ? detail
          : detail == null
            ? ""
            : JSON.stringify(detail),
    });
  }
  return {
    run_id: str(record.run_id),
    events,
    truncated: record.truncated === true,
    dropped: raw.length - events.length,
  };
}
