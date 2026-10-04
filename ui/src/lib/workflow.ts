import { batchActive } from "./status.ts";
export const workflowActive = batchActive;

/** Missing terminal timestamps cannot become a continuously growing duration. */
export function elapsedSeconds(
  startedAt: string | null | undefined,
  completedAt: string | null | undefined,
  status: string,
  now: number,
): number | null {
  if (!startedAt || (!completedAt && !workflowActive(status))) return null;
  const start = Date.parse(startedAt);
  const end = completedAt ? Date.parse(completedAt) : now;
  return Number.isFinite(start) && Number.isFinite(end) && end >= start
    ? (end - start) / 1000
    : null;
}

export function workflowCounts(counts: Record<string, number>) {
  return {
    complete: counts.complete ?? 0,
    failed: counts.failed ?? 0,
    cancelled: counts.cancelled ?? 0,
    needsInfo: counts.needs_info ?? 0,
    active: Object.entries(counts)
      .filter(([status]) => workflowActive(status))
      .reduce((total, [, count]) => total + count, 0),
  };
}

export function phaseSummary(phases: Record<string, number>): string {
  const recorded = Object.entries(phases).filter(([, count]) => count > 0);
  return recorded.length
    ? recorded
        .map(([phase, count]) => `${phase.replaceAll("_", " ")}: ${count}`)
        .join(" · ")
    : "Unavailable";
}
