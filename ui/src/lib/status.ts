import type { components } from "../api/schema";

export type RunStatus = components["schemas"]["RunState"]["status"];
export type StatusGroup =
  | "active"
  | "completed"
  | "failed"
  | "cancelled"
  | "unknown";
export const STATUS_FILTERS = [
  "active",
  "completed",
  "failed",
  "cancelled",
] as const satisfies readonly StatusGroup[];
export type StatusFilter = (typeof STATUS_FILTERS)[number];

/**
 * Two vocabularies reach the UI. `RunState.status` (GET /api/runs/{id}) is one of pending,
 * running, completed, failed or cancelled. `RunSummary.status` (GET /api/runs) is Temporal's
 * execution status lower-cased: running, completed, failed, canceled, terminated, timed_out,
 * continued_as_new, or unknown. The detail endpoint reports terminated and timed-out
 * executions as failed, so the list groups them the same way.
 */
const GROUPS: Readonly<Record<string, StatusGroup>> = {
  pending: "active",
  running: "active",
  completed: "completed",
  failed: "failed",
  terminated: "failed",
  timed_out: "failed",
  cancelled: "cancelled",
  canceled: "cancelled",
};

export function statusGroup(status: string | null | undefined): StatusGroup {
  return (status && GROUPS[status]) || "unknown";
}
/** Polling recognizes only the recorded active states; unknown states stop polling. */
export function runActive(status: string | null | undefined): boolean {
  return statusGroup(status) === "active";
}
export function terminal(status: string | null | undefined): boolean {
  const group = statusGroup(status);
  return group !== "active" && group !== "unknown";
}
export function statusLabel(status: string | null | undefined): string {
  if (!status) return "unknown";
  return status === "canceled" ? "cancelled" : status.replaceAll("_", " ");
}
export function statusVariant(
  status: string | null | undefined,
): "active" | "outline" | "failed" | "muted" {
  const group = statusGroup(status);
  if (group === "active") return "active";
  if (group === "failed") return "failed";
  if (group === "completed") return "outline";
  return "muted";
}
export const STATUS_FILTER_LABELS: Record<StatusFilter, string> = {
  active: "Active",
  completed: "Completed",
  failed: "Failed",
  cancelled: "Cancelled",
};
