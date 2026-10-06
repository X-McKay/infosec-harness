/**
 * Route state for the investigations list and its detail click-through.
 *
 * The API pages by an opaque `page_token` and offers no server-side filter, so the search
 * box and the status and verdict filters apply to the loaded page only.
 */
import type { components } from "../api/schema";
import { STATUS_FILTERS, statusGroup, type StatusFilter } from "./status.ts";
import { isVerdictLabel, type VerdictLabel } from "./verdict.ts";
import { OUTCOME_LABELS, type Outcome } from "./evaluation.ts";
import { REPORT_KINDS, type ReportKind } from "./reports.ts";

/**
 * One row of GET /api/runs. `verdict` is null unless the API read the completed result in
 * time; `cwe` and `repo_url` come from the recorded finding and may be absent.
 */
export type RunListItem = components["schemas"]["RunSummary"];

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

/** `/reports?kind=`: the report-kind filter, kept in the URL like the list filters. */
export type ReportsSearch = { kind?: ReportKind };

export function parseReportsSearch(
  search: Record<string, unknown>,
): ReportsSearch {
  return REPORT_KINDS.includes(search.kind as ReportKind)
    ? { kind: search.kind as ReportKind }
    : {};
}

/** `/reports/$name?case=&outcome=&language=`: a cohort report's case-table filters. */
export type CaseFilters = {
  case?: string;
  outcome?: Outcome;
  language?: string;
};

const MAX_LANGUAGE = 64;

export function parseCaseFilters(search: Record<string, unknown>): CaseFilters {
  const parsed: CaseFilters = {};
  const needle = typeof search.case === "string" ? search.case.trim() : "";
  if (needle) parsed.case = needle.slice(0, MAX_QUERY);
  if (
    typeof search.outcome === "string" &&
    Object.hasOwn(OUTCOME_LABELS, search.outcome)
  )
    parsed.outcome = search.outcome as Outcome;
  if (
    typeof search.language === "string" &&
    search.language &&
    search.language.length <= MAX_LANGUAGE
  )
    parsed.language = search.language;
  return parsed;
}

/**
 * A route validator that owns its keys. TanStack Router merges a route's validated search over
 * the raw query string, so a key the parser rejects (`?status=bogus`) would otherwise survive
 * the merge with its raw value. Every owned key is set, to undefined when rejected.
 */
export function ownedSearch<T extends object>(
  keys: readonly (keyof T & string)[],
  parse: (search: Record<string, unknown>) => T,
): (search: Record<string, unknown>) => T {
  return (search) => {
    const owned = Object.fromEntries(keys.map((key) => [key, undefined]));
    return { ...owned, ...parse(search) } as T;
  };
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
