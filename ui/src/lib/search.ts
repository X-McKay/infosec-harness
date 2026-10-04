/** URL filters shared by chart drill-downs and the findings queue. */
import type { RunPageQuery } from "@/api/client";

type Population = "operational";
type Metric = NonNullable<RunPageQuery["metric"]>;
const METRICS = new Set<Metric>([
  "total_tokens",
  "input_tokens",
  "output_tokens",
  "cost_usd",
  "wall_time_s",
]);

export type FindingSearch = {
  verdict: string;
  batch_id: string;
  search: string;
  offset: number;
  population?: Population;
  metric?: Metric;
  lower?: number;
  upper?: number;
  upper_inclusive?: boolean;
};

export function parseFindingSearch(
  search: Record<string, unknown>,
): FindingSearch {
  const metric = String(search.metric || "") as Metric;
  return {
    verdict: String(search.verdict || ""),
    batch_id: String(search.batch_id || ""),
    search: String(search.search || ""),
    offset: positiveOffset(search.offset),
    population: "operational",
    metric: METRICS.has(metric) ? metric : undefined,
    lower: finiteNumber(search.lower),
    upper: finiteNumber(search.upper),
    upper_inclusive:
      search.upper_inclusive === true || search.upper_inclusive === "true",
  };
}

function finiteNumber(value: unknown): number | undefined {
  if (value == null || value === "") return undefined;
  const number = Number(value);
  return Number.isFinite(number) ? number : undefined;
}
function positiveOffset(value: unknown): number {
  const number = finiteNumber(value);
  return number != null && Number.isSafeInteger(number)
    ? Math.max(0, number)
    : 0;
}

export type FindingDetailSearch = FindingSearch & { from_queue: boolean };
export function parseFindingDetailSearch(
  search: Record<string, unknown>,
): FindingDetailSearch {
  return {
    ...parseFindingSearch(search),
    from_queue: search.from_queue === true || search.from_queue === "true",
  };
}
export function queueSearch(search: FindingDetailSearch): FindingSearch {
  const { from_queue: _fromQueue, ...filters } = search;
  return filters;
}
export function findingPageQuery(search: FindingSearch): RunPageQuery {
  return {
    batch_id: search.batch_id || undefined,
    verdict: search.verdict || undefined,
    search: search.search || undefined,
    offset: search.offset,
    population: "operational",
    metric: search.metric,
    lower: search.lower,
    upper: search.upper,
    upper_inclusive: search.upper_inclusive,
  };
}

type NavigationPage = {
  items: { id: string }[];
  offset: number;
  limit: number;
  total: number;
};
export type FindingNeighbor = { id: string; offset: number };
export async function findingNeighbors(
  runId: string,
  search: FindingSearch,
  load: (query: RunPageQuery) => Promise<NavigationPage>,
): Promise<{
  position?: number;
  total: number;
  previous?: FindingNeighbor;
  next?: FindingNeighbor;
}> {
  const page = await load(findingPageQuery(search));
  const index = page.items.findIndex((item) => item.id === runId);
  if (index < 0) return { total: page.total };
  let previous =
    index > 0
      ? { id: page.items[index - 1].id, offset: page.offset }
      : undefined;
  let next =
    index + 1 < page.items.length
      ? { id: page.items[index + 1].id, offset: page.offset }
      : undefined;
  if (index === 0 && page.offset > 0) {
    const previousLimit = Math.min(page.limit, page.offset);
    const before = await load({
      ...findingPageQuery(search),
      offset: page.offset - previousLimit,
      limit: previousLimit,
    });
    const item = before.items.at(-1);
    if (item) previous = { id: item.id, offset: before.offset };
  }
  if (
    index === page.items.length - 1 &&
    page.offset + page.items.length < page.total
  ) {
    const after = await load({
      ...findingPageQuery(search),
      offset: page.offset + page.limit,
      limit: page.limit,
    });
    const item = after.items[0];
    if (item) next = { id: item.id, offset: after.offset };
  }
  return {
    position: page.offset + index + 1,
    total: page.total,
    previous,
    next,
  };
}
