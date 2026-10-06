import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { Plus, Search } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { queries } from "@/api/queries";
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
import { duration, timestamp } from "@/lib/format";
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

export function Investigations() {
  const search = useSearch({ from: "/" });
  const navigate = useNavigate({ from: "/" });
  const [creating, setCreating] = useState(false);
  // Tokens of the pages before this one, for Previous; the API pages forward only.
  const [previousPages, setPreviousPages] = useState<string[]>([]);
  const searchBox = useRef<HTMLInputElement>(null);
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

  // "/" focuses the search box, as in most list views.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      if (
        event.key === "/" &&
        !event.metaKey &&
        !event.ctrlKey &&
        !target?.closest("input, textarea, select, [contenteditable]")
      ) {
        event.preventDefault();
        searchBox.current?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="eyebrow">Triage workspace</p>
          <h1>Investigations</h1>
          <p className="mt-2 text-sm text-muted-foreground">
            This generation's investigations, read live from Temporal. Open one
            to see its verdict, the evidence behind it and its limitations.
          </p>
        </div>
        <div className="flex flex-col items-end gap-2">
          {!creating && (
            <Button onClick={() => setCreating(true)}>
              <Plus className="h-4 w-4" aria-hidden="true" /> New investigation
            </Button>
          )}
          <Freshness
            at={query.dataUpdatedAt}
            fetching={query.isFetching}
            stale={query.isError && !!page}
          />
        </div>
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
        className="grid grid-cols-2 gap-3 md:grid-cols-4"
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
                "rounded-lg border bg-card p-4 text-left shadow-sm transition-colors hover:bg-muted/50",
                selected && "border-primary ring-1 ring-primary",
              )}
            >
              <span className="block text-xs text-muted-foreground">
                {STATUS_FILTER_LABELS[status]}
              </span>
              <span className="mt-1 block text-2xl font-semibold tabular-nums">
                {page ? counts[status] : "–"}
              </span>
            </button>
          );
        })}
      </div>

      <Card>
        <CardContent className="flex flex-wrap items-center gap-3 pt-4">
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
              placeholder="Search title, id, CWE, repository…  ( / )"
              value={search.q ?? ""}
              onChange={(event) =>
                update({ q: event.target.value || undefined }, true)
              }
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
        <p className="text-muted-foreground">
          {page
            ? filtered
              ? `${visible.length} of ${items.length} on this page match · filters apply to the loaded page`
              : `${items.length} on this page`
            : "Loading investigations…"}
        </p>
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
            <Table>
              <caption className="sr-only">
                Investigations on this page; select a title to open one
              </caption>
              <TableHeader>
                <TableRow>
                  <TableHead>Status</TableHead>
                  <TableHead>Verdict</TableHead>
                  <TableHead>Investigation</TableHead>
                  <TableHead>Started</TableHead>
                  <TableHead className="text-right">Elapsed</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
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
                {visible.map((run) => (
                  <TableRow
                    key={run.id}
                    className="cursor-pointer"
                    onClick={(event) => {
                      if ((event.target as HTMLElement).closest("a, button"))
                        return;
                      void navigate({
                        to: "/runs/$runId",
                        params: { runId: run.id },
                        search: { ...search, from_queue: true },
                      });
                    }}
                  >
                    <TableCell>
                      <Badge variant={statusVariant(run.status)}>
                        {statusLabel(run.status)}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {run.verdict ? (
                        <Badge variant={verdictVariant(run.verdict)}>
                          {verdictLabel(run.verdict)}
                        </Badge>
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell className="max-w-[520px]">
                      <Link
                        to="/runs/$runId"
                        params={{ runId: run.id }}
                        search={{ ...search, from_queue: true }}
                        className="font-medium hover:underline"
                      >
                        {run.title}
                      </Link>
                      <p className="mt-0.5 break-all text-xs text-muted-foreground">
                        <span className="font-mono">{run.id}</span>
                        {run.cwe && <> · {run.cwe}</>}
                        {run.repo_url && <> · {run.repo_url}</>}
                      </p>
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                      {timestamp(run.started_at)}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-right font-mono text-xs">
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
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
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
