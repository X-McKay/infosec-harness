/**
 * Route state for the investigations list and its detail click-through.
 *
 * The API pages by an opaque `page_token` and offers no server-side filter, so the search
 * box and the status and verdict filters apply to the loaded page only.
 */
import type { components } from "../api/schema";
import { STATUS_FILTERS, statusGroup, type StatusFilter } from "./status.ts";
import { isVerdictLabel, type VerdictLabel } from "./verdict.ts";

/** RunSummary plus the optional fields a newer API reports; absent fields stay absent. */
export type RunListItem = components["schemas"]["RunSummary"] & {
  verdict?: string | null;
  cwe?: string | null;
  repo_url?: string | null;
};

export type InvestigationSearch = {
  q?: string;
  status?: StatusFilter;
  verdict?: VerdictLabel;
  /** Opaque API page token of the page being shown; absent for the first page. */
  page?: string;
};
export type DetailSearch = InvestigationSearch & { from_queue?: boolean };

const MAX_QUERY = 200;
const MAX_PAGE_TOKEN = 8192; // the API's page_token max_length

export function parseInvestigationSearch(
  search: Record<string, unknown>,
): InvestigationSearch {
  const parsed: InvestigationSearch = {};
  const q = typeof search.q === "string" ? search.q.trim() : "";
  if (q) parsed.q = q.slice(0, MAX_QUERY);
  if ((STATUS_FILTERS as readonly unknown[]).includes(search.status))
    parsed.status = search.status as StatusFilter;
  if (isVerdictLabel(search.verdict)) parsed.verdict = search.verdict;
  if (
    typeof search.page === "string" &&
    search.page &&
    search.page.length <= MAX_PAGE_TOKEN
  )
    parsed.page = search.page;
  return parsed;
}

export function parseDetailSearch(
  search: Record<string, unknown>,
): DetailSearch {
  const parsed: DetailSearch = parseInvestigationSearch(search);
  if (search.from_queue === true || search.from_queue === "true")
    parsed.from_queue = true;
  return parsed;
}

export function queueSearch(search: DetailSearch): InvestigationSearch {
  const { from_queue: _fromQueue, ...filters } = search;
  return filters;
}

export const hasFilters = (search: InvestigationSearch) =>
  !!(search.q || search.status || search.verdict);

/** Case-insensitive match over the title, id, CWE and repository; filters combine. */
export function filterRuns<T extends RunListItem>(
  items: readonly T[],
  search: InvestigationSearch,
): T[] {
  const needle = search.q?.toLowerCase();
  return items.filter(
    (item) =>
      (!search.status || statusGroup(item.status) === search.status) &&
      (!search.verdict || item.verdict === search.verdict) &&
      (!needle ||
        [item.title, item.id, item.cwe, item.repo_url].some(
          (field) =>
            typeof field === "string" && field.toLowerCase().includes(needle),
        )),
  );
}

/** Previous and next investigation within the filtered page; never guessed across pages. */
export function runNeighbors(
  runId: string,
  items: readonly { id: string }[],
): { position?: number; total: number; previous?: string; next?: string } {
  const index = items.findIndex((item) => item.id === runId);
  if (index < 0) return { total: items.length };
  return {
    position: index + 1,
    total: items.length,
    previous: items[index - 1]?.id,
    next: items[index + 1]?.id,
  };
}
