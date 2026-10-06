/**
 * Presentation of GET /api/health (contracts.Health). The API checks Temporal connectivity
 * only; a configured name is never measured execution evidence, and an unreported check is
 * "not_checked", never passed. The response is still narrowed: a malformed field is shown as
 * not reported rather than coerced.
 */
import type { components } from "../api/schema";
import { isRecord, text } from "./json.ts";

export type Health = components["schemas"]["Health"];
export type HealthStatus = Health["status"];

const STATUSES: readonly HealthStatus[] = [
  "control_plane_ready",
  "temporal_unavailable",
];

export type HealthPresentation = {
  status: HealthStatus | null;
  /** Whether the API reached Temporal; null when not reported. */
  temporal: boolean | null;
  /** The native OpenShell runtime; the API does not check it, so absence is not_checked. */
  runtime: string;
  generation: string | null;
  taskQueue: string | null;
  /** Ready only when the API says so and reports Temporal reachable. */
  ready: boolean;
};

export function healthPresentation(health: unknown): HealthPresentation {
  const record = isRecord(health) ? health : {};
  const status = (STATUSES as readonly unknown[]).includes(record.status)
    ? (record.status as HealthStatus)
    : null;
  const temporal =
    typeof record.temporal === "boolean" ? record.temporal : null;
  return {
    status,
    temporal,
    runtime: text(record.runtime) ?? "not_checked",
    generation: text(record.generation),
    taskQueue: text(record.task_queue),
    ready: status === "control_plane_ready" && temporal === true,
  };
}

export const temporalLabel = (temporal: boolean | null) =>
  temporal == null ? "Not reported" : temporal ? "reachable" : "unreachable";

export const readable = (value: string | null | undefined) =>
  value ? value.replaceAll("_", " ") : "Not reported";

/** API base the browser calls; the UI only ever requests same-origin /api paths. */
export function apiBase(origin: string): string {
  return `${origin.replace(/\/+$/, "")}/api`;
}
