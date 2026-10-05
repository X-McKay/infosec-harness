/**
 * One activity policy per recorded entity. The backend stores a run as pending or running
 * until it reaches a terminal value; batches and evaluations have their own lifecycles.
 */
const TERMINAL = new Set(["complete", "needs_info", "failed", "cancelled"]);
const ACTIVE_RUN = new Set(["pending", "running"]);

export function terminal(status: string): boolean {
  return TERMINAL.has(status);
}
/** Run polling recognizes only recorded active states; unknown states stop polling. */
export function runActive(status: string): boolean {
  return ACTIVE_RUN.has(status);
}
/** Unknown batch states (e.g. cancellation_requested) stay active so refreshes do not silently stop. */
export function batchActive(status: string): boolean {
  return !terminal(status);
}
/** Evaluations record running, truncated or complete; only running ones change. */
export function experimentActive(status: unknown): boolean {
  return status === "running";
}
