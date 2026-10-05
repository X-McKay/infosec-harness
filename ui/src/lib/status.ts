import type { components } from "../api/schema";

type RunStatus = components["schemas"]["RunStatus"];
type BatchStatus = components["schemas"]["BatchStatus"];
type ExperimentStatus = components["schemas"]["ExperimentStatus"];

/**
 * One activity policy per recorded entity, over the vocabularies the API publishes. The backend
 * stores a run as pending or running until it reaches a terminal value; batches and evaluations
 * have their own lifecycles.
 */
const TERMINAL: ReadonlySet<string> = new Set<RunStatus | BatchStatus>([
  "complete",
  "needs_info",
  "failed",
  "cancelled",
]);
const ACTIVE_RUN: ReadonlySet<string> = new Set<RunStatus>([
  "pending",
  "running",
]);
const ACTIVE_EXPERIMENT: ExperimentStatus = "running";

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
  return status === ACTIVE_EXPERIMENT;
}
