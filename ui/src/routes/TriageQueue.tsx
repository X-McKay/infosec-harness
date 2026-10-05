import { queries } from "@/api/queries";
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
import { money, percent } from "@/lib/format";
import type { FindingSearch } from "@/lib/search";
import { VERDICT_LABELS, verdictLabel, verdictVariant } from "@/lib/verdict";

const VERDICT_FILTERS = ["", ...VERDICT_LABELS] as const;

export function TriageQueue() {
  const search = useSearch({ from: "/" });
  const navigate = useNavigate({ from: "/" });
  // Text filters are drafts until submitted, so typing never navigates per keystroke.
  const [draft, setDraft] = useState(search.search);
  const [batchDraft, setBatchDraft] = useState(search.batch_id);
  useEffect(() => setDraft(search.search), [search.search]);
  useEffect(() => setBatchDraft(search.batch_id), [search.batch_id]);
  const query = useQuery({
    ...queries.runPage(search),
    placeholderData: (previous) => previous,
  });
  const page = query.data;
  const offset = page?.offset ?? search.offset;
  const total = page?.total ?? 0;
  // The server chooses the page size; paging waits until it is known.
  const hasPrevious = !!page && offset > 0;
  const hasNext = !!page && offset + page.limit < total;
  const updateSearch = (patch: Partial<FindingSearch>) =>
    void navigate({ search: (current) => ({ ...current, ...patch }) });
  const submitFilters = (event: FormEvent) => {
    event.preventDefault();
    updateSearch({
      search: draft.trim(),
      batch_id: batchDraft.trim(),
      offset: 0,
    });
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
            Population: operational · {search.metric.replaceAll("_", " ")}:{" "}
            {search.lower ?? "any"} to {search.upper ?? "any"}
            {search.upper_inclusive ? " inclusive" : " exclusive"}
          </span>
          <Button
            size="sm"
            variant="outline"
            onClick={() =>
              updateSearch({
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
            onSubmit={submitFilters}
            className="flex min-w-[240px] flex-1 flex-wrap items-center gap-2"
          >
            <input
              className="field min-w-[200px] flex-1"
              aria-label="Search findings"
              placeholder="Search title, CWE, repository…"
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
            />
            <label className="text-sm text-muted-foreground">
              Batch
              <input
                className="field ml-2 w-40"
                placeholder="batch id"
                value={batchDraft}
                onChange={(event) => setBatchDraft(event.target.value)}
              />
            </label>
            <Button type="submit" variant="outline">
              Search
            </Button>
          </form>
          <div className="flex gap-1" role="group" aria-label="Verdict filter">
            {VERDICT_FILTERS.map((value) => (
              <Button
                key={value || "all"}
                size="sm"
                variant={search.verdict === value ? "default" : "outline"}
                aria-pressed={search.verdict === value}
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
              page && updateSearch({ offset: Math.max(0, offset - page.limit) })
            }
          >
            Previous
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={!hasNext || query.isFetching}
            onClick={() =>
              page && updateSearch({ offset: offset + page.limit })
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
                {page.items.map((run) => (
                  <TableRow key={run.id}>
                    <TableCell>
                      <Badge variant="outline">{run.priority || "-"}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant={verdictVariant(run.verdict)}>
                        {verdictLabel(run.verdict)}
                      </Badge>
                    </TableCell>
                    <TableCell>{percent(run.confidence, 0)}</TableCell>
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
                      {money(run.telemetry?.cost_usd)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
