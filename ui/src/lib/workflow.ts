import { statusGroup, type StatusGroup } from "./status.ts";

/** Missing terminal timestamps cannot become a continuously growing duration. */
export function elapsedSeconds(
  startedAt: string | null | undefined,
  closedAt: string | null | undefined,
  active: boolean,
  now: number,
): number | null {
  if (!startedAt || (!closedAt && !active)) return null;
  const start = Date.parse(startedAt);
  const end = closedAt ? Date.parse(closedAt) : now;
  return Number.isFinite(start) && Number.isFinite(end) && end >= start
    ? (end - start) / 1000
    : null;
}

/** Status counts for a loaded page; unrecognized states stay visible as unknown. */
export function statusCounts(
  items: readonly { status: string }[],
): Record<StatusGroup, number> {
  const counts: Record<StatusGroup, number> = {
    active: 0,
    completed: 0,
    failed: 0,
    cancelled: 0,
    unknown: 0,
  };
  for (const item of items) counts[statusGroup(item.status)] += 1;
  return counts;
}

export function phaseLabel(phase: string | null | undefined): string {
  return phase ? phase.replaceAll("_", " ") : "Unavailable";
}
