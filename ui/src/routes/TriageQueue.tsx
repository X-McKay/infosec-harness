import { queries } from "@/api/queries";
import { runActive } from "@/lib/status";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { FormEvent, useEffect, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { QueryState, Freshness } from "@/components/QueryState";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { findingPageQuery } from "@/lib/search";
import { money } from "@/lib/format";
import { verdictLabel, verdictVariant } from "@/lib/verdict";

const VERDICTS = [
  "",
  "potentially_exploitable",
  "inconclusive",
  "likely_not_exploitable",
];
const PAGE_SIZE = 25;

export function TriageQueue() {
  const search = useSearch({ from: "/" });
  const navigate = useNavigate({ from: "/" });
  const [draft, setDraft] = useState(search.search);
  useEffect(() => setDraft(search.search), [search.search]);
  const query = useQuery({
    ...queries.runPage(search, findingPageQuery(search)),
    placeholderData: (previous) => previous,
    refetchInterval: (current) =>
      current.state.data?.items.some((run) => runActive(run.status))
        ? 2000
        : false,
  });
  const page = query.data;
  const offset = page?.offset ?? search.offset;
  const total = page?.total ?? 0;
  const hasPrevious = offset > 0;
  const hasNext = offset + (page?.limit ?? PAGE_SIZE) < total;
  const updateSearch = (patch: Partial<typeof search>) =>
    void navigate({ search: (current) => ({ ...current, ...patch }) });
  const submitSearch = (event: FormEvent) => {
    event.preventDefault();
    updateSearch({ search: draft.trim(), offset: 0 });
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="eyebrow">Review workspace</p>
          <h1>Triage queue</h1>
          <p className="mt-2 text-sm text-muted-foreground">
            Findings with server-side filters, pagination, and totals.
          </p>
        </div>
        <Freshness
          at={page?.as_of ?? query.dataUpdatedAt}
          fetching={query.isFetching}
          stale={query.isError && !!page}
        />
      </div>
      {search.metric && (
        <div className="flex flex-wrap items-center gap-3 rounded-lg border p-3 text-sm">
          <span>
            Population: operational ·{" "}
            {search.metric
              ? `${search.metric.replaceAll("_", " ")}: ${search.lower ?? "any"} to ${search.upper ?? "any"}${search.upper_inclusive ? " inclusive" : " exclusive"}`
              : "all measurements"}
          </span>
          <Button
            size="sm"
            variant="outline"
            onClick={() =>
              updateSearch({
                population: "operational",
                metric: undefined,
                lower: undefined,
                upper: undefined,
                upper_inclusive: false,
                offset: 0,
              })
            }
          >
            Clear chart filter
          </Button>
        </div>
      )}
      <Card>
        <CardContent className="flex flex-wrap items-center gap-3 pt-5">
          <form
            onSubmit={submitSearch}
            className="flex min-w-[240px] flex-1 gap-2"
          >
            <input
              className="field w-full"
              aria-label="Search findings"
              placeholder="Search title, CWE, repository…"
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
            />
            <Button type="submit" variant="outline">
              Search
            </Button>
          </form>
          <label className="text-sm text-muted-foreground">
            Batch
            <input
              className="field ml-2 w-40"
              aria-label="Filter by batch"
              placeholder="batch id"
              value={search.batch_id}
              onChange={(event) =>
                updateSearch({ batch_id: event.target.value, offset: 0 })
              }
            />
          </label>
          <div className="flex gap-1" aria-label="Verdict filter">
            {VERDICTS.map((value) => (
              <Button
                key={value || "all"}
                size="sm"
                variant={search.verdict === value ? "default" : "outline"}
                onClick={() => updateSearch({ verdict: value, offset: 0 })}
              >
                {value ? verdictLabel(value) : "All"}
              </Button>
            ))}
          </div>
        </CardContent>
      </Card>
      <div className="flex items-center justify-between gap-3 text-sm">
        <p className="text-muted-foreground">
          {page
            ? `Showing ${page.items.length ? offset + 1 : 0}–${Math.min(offset + page.items.length, total)} of ${total}`
            : "Loading findings…"}
        </p>
        <div className="flex gap-2">
          <Button
            size="sm"
            variant="outline"
            disabled={!hasPrevious || query.isFetching}
            onClick={() =>
              updateSearch({
                offset: Math.max(0, offset - (page?.limit ?? PAGE_SIZE)),
              })
            }
          >
            Previous
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={!hasNext || query.isFetching}
            onClick={() =>
              updateSearch({ offset: offset + (page?.limit ?? PAGE_SIZE) })
            }
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
              <TableHeader>
                <TableRow>
                  <TableHead>Priority</TableHead>
                  <TableHead>Verdict</TableHead>
                  <TableHead>Confidence</TableHead>
                  <TableHead>CWE</TableHead>
                  <TableHead>Finding</TableHead>
                  <TableHead>Repository</TableHead>
                  <TableHead className="text-right">Cost</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {page.items.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={7} className="empty">
                      No findings match these filters.
                    </TableCell>
                  </TableRow>
                )}
                {page.items.map((run) => {
                  const telemetryCost = run.telemetry?.cost_usd;
                  return (
                    <TableRow key={run.id}>
                      <TableCell>
                        <Badge variant="outline">{run.priority || "-"}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant={verdictVariant(run.verdict)}>
                          {verdictLabel(run.verdict)}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {run.confidence == null
                          ? "Unavailable"
                          : `${Math.round(run.confidence * 100)}%`}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {run.cwe || "-"}
                      </TableCell>
                      <TableCell>
                        <Link
                          to="/runs/$runId"
                          params={{ runId: run.id }}
                          search={{ ...search, from_queue: true }}
                          className="font-medium hover:underline"
                        >
                          {run.title}
                        </Link>
                        <p className="text-xs text-muted-foreground">
                          {run.status}
                        </p>
                      </TableCell>
                      <TableCell className="max-w-[220px] truncate text-xs text-muted-foreground">
                        {run.repo_url}
                      </TableCell>
                      <TableCell className="text-right font-mono text-xs">
                        {telemetryCost == null
                          ? "Unavailable"
                          : money(telemetryCost)}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
