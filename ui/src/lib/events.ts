/**
 * GET /api/runs/{id}/events: a bounded projection of the investigation's Temporal history
 * (kinds, activity names and short labels; never payloads). Typed by the generated schema;
 * the response is still narrowed because event labels are untrusted text. An API that does
 * not know the run answers 404 and the timeline hides.
 */
import { ApiError } from "../api/http.ts";
import type { components } from "../api/schema";
import { isRecord } from "./json.ts";

export type RunEvent = components["schemas"]["RunEvent"];
export type RunEvents = components["schemas"]["RunEvents"];
export type RunEventKind = RunEvent["kind"];

export const RUN_EVENT_KINDS: readonly RunEventKind[] = [
  "workflow_started",
  "activity_scheduled",
  "activity_completed",
  "activity_failed",
  "activity_timed_out",
  "timer",
  "workflow_completed",
  "workflow_failed",
  "workflow_cancelled",
  "other",
];

/** Kinds that record something going wrong; shown with the failed badge. */
export const FAILURE_KINDS: ReadonlySet<RunEventKind> = new Set([
  "activity_failed",
  "activity_timed_out",
  "workflow_failed",
]);

export const eventsPath = (runId: string) =>
  `/api/runs/${encodeURIComponent(runId)}/events`;

/** The endpoint is absent (or the run unknown to it): hide the section rather than fail. */
export function eventsUnavailable(error: unknown): boolean {
  return error instanceof ApiError && error.status === 404;
}

export const eventKindLabel = (kind: RunEventKind) => kind.replaceAll("_", " ");

const isKind = (value: unknown): value is RunEventKind =>
  (RUN_EVENT_KINDS as readonly unknown[]).includes(value);

/**
 * Narrow the response; entries without a kind are dropped and counted, never invented. A kind
 * this UI does not know is shown as "other"; a non-text name or detail is omitted.
 */
export function normalizeEvents(
  value: unknown,
): RunEvents & { dropped: number } {
  const record = isRecord(value) ? value : {};
  const raw = Array.isArray(record.events) ? record.events : [];
  const events: RunEvent[] = [];
  for (const item of raw) {
    if (!isRecord(item) || typeof item.kind !== "string" || !item.kind)
      continue;
    events.push({
      at: typeof item.at === "string" ? item.at : "",
      kind: isKind(item.kind) ? item.kind : "other",
      name: typeof item.name === "string" && item.name ? item.name : null,
      detail: typeof item.detail === "string" ? item.detail : "",
    });
  }
  return {
    run_id: typeof record.run_id === "string" ? record.run_id : "",
    events,
    truncated: record.truncated === true,
    dropped: raw.length - events.length,
  };
}
