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
    offset: Math.max(0, Number(search.offset) || 0),
    population: "operational",
    metric: METRICS.has(metric) ? metric : undefined,
    lower: search.lower == null ? undefined : Number(search.lower),
    upper: search.upper == null ? undefined : Number(search.upper),
    upper_inclusive:
      search.upper_inclusive === true || search.upper_inclusive === "true",
  };
}
