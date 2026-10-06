import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { Plus, Search } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { LIST_REFRESH_MS, queries } from "@/api/queries";
import { Freshness, QueryState } from "@/components/QueryState";
import { NewInvestigationForm } from "@/components/investigations/NewInvestigationForm";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { duration, shortLocation, timestamp } from "@/lib/format";
import { nextRowIndex, typingTarget } from "@/lib/keyboard";
import {
  filterRuns,
  hasFilters,
  type InvestigationSearch,
  type RunListItem,
} from "@/lib/search";
import {
  STATUS_FILTERS,
  STATUS_FILTER_LABELS,
  runActive,
  statusLabel,
  statusVariant,
} from "@/lib/status";
import { VERDICT_LABELS, verdictLabel, verdictVariant } from "@/lib/verdict";
import { elapsedSeconds, statusCounts } from "@/lib/workflow";
import { cn } from "@/lib/utils";

const ROW_LINK = "a[data-row-link]";

export function Investigations() {
  const search = useSearch({ from: "/" });
  const navigate = useNavigate({ from: "/" });
  const [creating, setCreating] = useState(false);
  // Tokens of the pages before this one, for Previous; the API pages forward only.
  const [previousPages, setPreviousPages] = useState<string[]>([]);
  const searchBox = useRef<HTMLInputElement>(null);
  // The URL keeps the trimmed query; the box keeps what was typed, so spaces between words
  // survive while typing. An outside change (Clear filters, history) resets the box.
  const [draft, setDraft] = useState(search.q ?? "");
  useEffect(() => {
    setDraft((current) =>
      current.trim() === (search.q ?? "") ? current : (search.q ?? ""),
    );
  }, [search.q]);
  const rowsRef = useRef<HTMLTableSectionElement>(null);
  const query = useQuery({
    ...queries.runs(search.page ?? ""),
    placeholderData: (previous) => previous,
  });
  const page = query.data;
  const items: RunListItem[] = page?.items ?? [];
  const visible = filterRuns(items, search);
  const counts = statusCounts(items);
  const filtered = hasFilters(search);

  const update = (patch: Partial<InvestigationSearch>, replace = false) =>
    void navigate({
      search: (current) => ({ ...current, ...patch }),
      replace,
    });
  const clearFilters = () =>
    update({ q: undefined, status: undefined, verdict: undefined });

  /**
   * "/" focuses the search box; j and k (and the arrow, Home and End keys once a row has
   * focus) move between rows; Enter opens the focused row's investigation through its link.
   */
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      if (target === searchBox.current) {
        if (event.key === "ArrowDown") {
          const first = rowsRef.current?.querySelector<HTMLElement>(ROW_LINK);
          if (first) {
            event.preventDefault();
            first.focus();
          }
        } else if (event.key === "Escape") searchBox.current?.blur();
        return;
      }
      if (typingTarget(event, target)) return;
      if (event.key === "/") {
        event.preventDefault();
        searchBox.current?.focus();
        return;
      }
      const links = [
        ...(rowsRef.current?.querySelectorAll<HTMLElement>(ROW_LINK) ?? []),
      ];
      const row = target?.closest("tr[data-run-row]");
      const current = row ? links.findIndex((link) => row.contains(link)) : -1;
      const next = nextRowIndex(event.key, current, links.length);
      if (next == null) return;
      event.preventDefault();
      links[next].focus();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const runLink = (run: RunListItem) => ({
    to: "/runs/$runId" as const,
    params: { runId: run.id },
    search: { ...search, from_queue: true },
  });

  return (
    <div className="space-y-5 md:space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="min-w-0">
          <p className="eyebrow">Triage workspace</p>
          <h1>Investigations</h1>
          <p className="mt-2 text-sm text-muted-foreground">
            This generation's investigations, read live from Temporal. Open one
            to see its verdict, the evidence behind it and its limitations.
          </p>
        </div>
        {!creating && (
          <Button onClick={() => setCreating(true)}>
            <Plus className="h-4 w-4" aria-hidden="true" /> New investigation
          </Button>
        )}
      </div>

      {creating && (
        <NewInvestigationForm
          onCancel={() => setCreating(false)}
          onCreated={(run) => {
            setCreating(false);
            void navigate({
              to: "/runs/$runId",
              params: { runId: run.id },
              search: {},
            });
          }}
        />
      )}

      <div
        className="grid grid-cols-4 gap-2 md:gap-3"
        role="group"
        aria-label="Status filter"
      >
        {STATUS_FILTERS.map((status) => {
          const selected = search.status === status;
          return (
            <button
              key={status}
              type="button"
              aria-pressed={selected}
              onClick={() => update({ status: selected ? undefined : status })}
              className={cn(
                "min-w-0 rounded-lg border bg-card p-2.5 text-left shadow-sm transition-colors hover:bg-muted/50 md:p-4",
                selected && "border-primary ring-1 ring-primary",
              )}
            >
              <span className="block truncate text-[11px] text-muted-foreground md:text-xs">
                {STATUS_FILTER_LABELS[status]}
              </span>
              <span className="mt-0.5 block text-xl font-semibold tabular-nums md:mt-1 md:text-2xl">
                {page ? counts[status] : "–"}
              </span>
            </button>
          );
        })}
      </div>

      <Card>
        <CardContent className="flex flex-wrap items-center gap-3 p-3 md:p-4">
          <label className="relative flex min-w-[220px] flex-1 items-center">
            <Search
              className="pointer-events-none absolute left-2.5 h-4 w-4 text-muted-foreground"
              aria-hidden="true"
            />
            <input
              ref={searchBox}
              type="search"
              className="field w-full pl-8"
              aria-label="Search investigations"
              aria-keyshortcuts="/"
              placeholder="Search title, id, CWE, repository…  ( / )"
              value={draft}
              onChange={(event) => {
                setDraft(event.target.value);
                update({ q: event.target.value.trim() || undefined }, true);
              }}
            />
          </label>
          <div
            className="flex flex-wrap gap-1"
            role="group"
            aria-label="Verdict filter"
          >
            {([undefined, ...VERDICT_LABELS] as const).map((value) => (
              <Button
                key={value ?? "all"}
                size="sm"
                variant={search.verdict === value ? "default" : "outline"}
                aria-pressed={search.verdict === value}
                onClick={() => update({ verdict: value })}
              >
                {value ? verdictLabel(value) : "All verdicts"}
              </Button>
            ))}
          </div>
          {filtered && (
            <Button size="sm" variant="ghost" onClick={clearFilters}>
              Clear filters
            </Button>
          )}
        </CardContent>
      </Card>

      <div className="flex flex-wrap items-center justify-between gap-3 text-sm">
        <div className="min-w-0 space-y-1">
          <p className="text-muted-foreground">
            {page
              ? filtered
                ? `${visible.length} of ${items.length} on this page match · filters apply to the loaded page`
                : `${items.length} on this page`
              : "Loading investigations…"}
          </p>
          <Freshness
            at={query.dataUpdatedAt}
            fetching={query.isFetching}
            stale={query.isError && !!page}
            live={LIST_REFRESH_MS}
          />
        </div>
        <div className="flex gap-2">
          {search.page && !previousPages.length && (
            <Button
              size="sm"
              variant="outline"
              onClick={() => update({ page: undefined })}
            >
              First page
            </Button>
          )}
          <Button
            size="sm"
            variant="outline"
            disabled={!previousPages.length || query.isFetching}
            onClick={() => {
              const previous = previousPages.at(-1);
              setPreviousPages(previousPages.slice(0, -1));
              update({ page: previous || undefined });
            }}
          >
            Previous
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={!page?.next_page_token || query.isFetching}
            onClick={() => {
              if (!page?.next_page_token) return;
              setPreviousPages([...previousPages, search.page ?? ""]);
              update({ page: page.next_page_token });
            }}
          >
            Next
          </Button>
        </div>
      </div>

      {!page && (
        <QueryState
          loading={query.isPending}
          error={query.error}
          retry={() => void query.refetch()}
        />
      )}
      {page && query.isError && (
        <QueryState error={query.error} retry={() => void query.refetch()} />
      )}
      {page && (
        <Card>
          <CardContent className="p-0">
            <Table className="table-fixed md:table-auto">
              <caption className="sr-only">
                Investigations on this page; select a title to open one. Press j
                or k to move between rows and Enter to open one.
              </caption>
              <TableHeader>
                <TableRow>
                  <TableHead className="hidden w-px md:table-cell">
                    Status
                  </TableHead>
                  <TableHead className="hidden w-px md:table-cell">
                    Verdict
                  </TableHead>
                  <TableHead>Investigation</TableHead>
                  <TableHead className="hidden w-px md:table-cell">
                    Started
                  </TableHead>
                  <TableHead className="w-20 text-right md:w-px">
                    Elapsed
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody ref={rowsRef}>
                {visible.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5} className="empty">
                      {items.length === 0 ? (
                        <>
                          No investigations yet.{" "}
                          <button
                            type="button"
                            className="text-primary underline underline-offset-2"
                            onClick={() => setCreating(true)}
                          >
                            Start one
                          </button>
                          .
                        </>
                      ) : (
                        <>
                          No investigations on this page match these filters.{" "}
                          <button
                            type="button"
                            className="text-primary underline underline-offset-2"
                            onClick={clearFilters}
                          >
                            Clear filters
                          </button>
                        </>
                      )}
                    </TableCell>
                  </TableRow>
                )}
                {visible.map((run) => {
                  const status = (
                    <Badge variant={statusVariant(run.status)}>
                      {statusLabel(run.status)}
                    </Badge>
                  );
                  const verdict = run.verdict ? (
                    <Badge variant={verdictVariant(run.verdict)}>
                      {verdictLabel(run.verdict)}
                    </Badge>
                  ) : null;
                  return (
                    <TableRow
                      key={run.id}
                      data-run-row=""
                      className="cursor-pointer focus-within:bg-muted/60"
                      onClick={(event) => {
                        if ((event.target as HTMLElement).closest("a, button"))
                          return;
                        void navigate(runLink(run));
                      }}
                    >
                      <TableCell className="hidden align-top md:table-cell">
                        {status}
                      </TableCell>
                      <TableCell className="hidden align-top md:table-cell">
                        {verdict ?? (
                          <span className="text-xs text-muted-foreground">
                            <span aria-hidden="true">—</span>
                            <span className="sr-only">No verdict</span>
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="min-w-0 align-top md:max-w-[560px]">
                        <Link
                          {...runLink(run)}
                          data-row-link=""
                          className="rounded-sm font-medium hover:underline"
                        >
                          {run.title}
                        </Link>
                        <div className="mt-1.5 flex flex-wrap items-center gap-1.5 md:hidden">
                          {status}
                          {verdict}
                          <span className="text-xs text-muted-foreground">
                            {timestamp(run.started_at)}
                          </span>
                        </div>
                        <p className="mt-1 truncate font-mono text-xs text-muted-foreground">
                          {run.id}
                        </p>
                        {(run.cwe || run.repo_url) && (
                          <p className="truncate text-xs text-muted-foreground">
                            {run.cwe}
                            {run.cwe && run.repo_url && " · "}
                            {run.repo_url && shortLocation(run.repo_url)}
                          </p>
                        )}
                      </TableCell>
                      <TableCell className="hidden whitespace-nowrap align-top text-xs text-muted-foreground md:table-cell">
                        {timestamp(run.started_at)}
                      </TableCell>
                      <TableCell className="whitespace-nowrap text-right align-top font-mono text-xs tabular-nums">
                        {duration(
                          elapsedSeconds(
                            run.started_at,
                            run.closed_at,
                            runActive(run.status),
                            query.dataUpdatedAt,
                          ),
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
      {page && visible.length > 0 && (
        <p className="hidden text-xs text-muted-foreground md:block">
          Keyboard: <kbd>j</kbd> / <kbd>k</kbd> or <kbd>↑</kbd> / <kbd>↓</kbd>{" "}
          move between rows · <kbd>Enter</kbd> opens · <kbd>/</kbd> searches
        </p>
      )}
      {page && counts.unknown > 0 && (
        <p className="text-xs text-muted-foreground">
          {counts.unknown} on this page {counts.unknown === 1 ? "has" : "have"}{" "}
          an unrecognized status and appear only when no status filter is set.
        </p>
      )}
    </div>
  );
}
