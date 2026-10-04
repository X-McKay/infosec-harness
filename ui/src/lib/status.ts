/** Finding polling deliberately recognizes only recorded active run states. */
const ACTIVE_RUN = new Set([
  "pending",
  "accepted",
  "running",
  "preparing",
  "building",
  "probing",
  "triaging",
]);
const TERMINAL_BATCH = new Set([
  "complete",
  "needs_info",
  "failed",
  "cancelled",
]);
export function runActive(status: string): boolean {
  return ACTIVE_RUN.has(status);
}
/** Unknown batch states remain active so refreshes do not silently stop. */
export function batchActive(status: string): boolean {
  return !TERMINAL_BATCH.has(status);
}
