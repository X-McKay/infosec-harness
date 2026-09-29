/** URL filters shared by chart drill-downs and the findings queue. */
export type FindingSearch = {
  verdict: string;
  batch_id: string;
  search: string;
  offset: number;
  population?: string;
  metric?: string;
  lower?: number;
  upper?: number;
  upper_inclusive?: boolean;
};

export function parseFindingSearch(
  search: Record<string, unknown>,
): FindingSearch {
  return {
    verdict: String(search.verdict || ""),
    batch_id: String(search.batch_id || ""),
    search: String(search.search || ""),
    offset: Math.max(0, Number(search.offset) || 0),
    population: String(search.population || ""),
    metric: String(search.metric || ""),
    lower: search.lower == null ? undefined : Number(search.lower),
    upper: search.upper == null ? undefined : Number(search.upper),
    upper_inclusive:
      search.upper_inclusive === true || search.upper_inclusive === "true",
  };
}
