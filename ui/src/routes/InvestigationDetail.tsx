import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams, useSearch } from "@tanstack/react-router";
import { ArrowLeft } from "lucide-react";
import { ApiError } from "@/api/http";
import { mutations, queries } from "@/api/queries";
import type { components } from "@/api/schema";
import { Freshness, QueryState } from "@/components/QueryState";
import { EventTimeline } from "@/components/investigations/EventTimeline";
import {
  EvidenceCard,
  OutputBlock,
} from "@/components/investigations/EvidenceCard";
import { RunIdentity } from "@/components/investigations/RunIdentity";
import {
  Limitations,
  VerdictPanel,
  evidenceAnchor,
} from "@/components/investigations/VerdictPanel";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { filterRuns, queueSearch, runNeighbors } from "@/lib/search";
import { runActive, statusLabel, statusVariant } from "@/lib/status";
import { verdictLabel, verdictVariant } from "@/lib/verdict";
import { phaseLabel } from "@/lib/workflow";

type RunState = components["schemas"]["RunState"];
type Evidence = components["schemas"]["Evidence"];

const notFound = (error: unknown) =>
  error instanceof ApiError && error.status === 404;

function BackLink({ search }: { search: ReturnType<typeof queueSearch> }) {
  return (
    <Link
      to="/"
      search={search}
      className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
    >
      <ArrowLeft className="h-4 w-4" aria-hidden="true" /> Back to
      investigations
    </Link>
  );
}

export function InvestigationDetail() {
  const { runId } = useParams({ from: "/runs/$runId" });
  const search = useSearch({ from: "/runs/$runId" });
  const returnSearch = queueSearch(search);
  const query = useQuery(queries.run(runId));
  const run = query.data;

  if (query.isPending) return <QueryState loading />;
  if (notFound(query.error))
    return (
      <div className="space-y-4">
        <BackLink search={returnSearch} />
        <Card>
          <CardContent className="space-y-2 pt-6">
            <h1>Investigation not found</h1>
            <p className="text-sm text-muted-foreground">
              <code className="break-all">{runId}</code> is not an investigation
              of this generation in Temporal.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  if (!run)
    return (
      <div className="space-y-4">
        <BackLink search={returnSearch} />
        <QueryState error={query.error} retry={() => void query.refetch()} />
      </div>
    );

  const active = runActive(run.status);
  const { finding, result } = run;
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 max-w-4xl">
          <div className="mb-4">
            <BackLink search={returnSearch} />
          </div>
          <p className="eyebrow">Investigation · {phaseLabel(run.phase)}</p>
          <h1>{finding.title}</h1>
          <p className="mt-2 break-all text-sm text-muted-foreground">
            {finding.repo_url} · {finding.revision} ·{" "}
            {finding.source_mode === "working_snapshot"
              ? "working snapshot"
              : "git revision"}
            {finding.cwe && <> · {finding.cwe}</>}
            {finding.file_path && <> · {finding.file_path}</>}
          </p>
          <p className="mt-1 break-all font-mono text-xs text-muted-foreground">
            {run.id}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant={statusVariant(run.status)}>
            {statusLabel(run.status)}
          </Badge>
          {result && (
            <Badge variant={verdictVariant(result.verdict.label)}>
              {verdictLabel(result.verdict.label)}
            </Badge>
          )}
          {active && <CancelButton runId={run.id} />}
        </div>
      </div>

      {search.from_queue && <Neighbors runId={run.id} search={returnSearch} />}

      <Freshness
        at={query.dataUpdatedAt}
        fetching={query.isFetching}
        stale={query.isError}
      />
      {query.isError && (
        <QueryState error={query.error} retry={() => void query.refetch()} />
      )}
      {run.error && (
        <div
          role="alert"
          className="rounded-lg border border-destructive/40 bg-destructive/5 p-4 text-sm"
        >
          <p className="font-medium">
            The investigation ended without a report ({statusLabel(run.status)}
            ).
          </p>
          {run.error !== run.status && (
            <p className="prose-text mt-1 text-muted-foreground">{run.error}</p>
          )}
        </div>
      )}

      {result ? (
        <>
          <div className="grid gap-5 xl:grid-cols-[1.6fr_1fr]">
            <VerdictPanel result={result} />
            <Limitations limitations={result.limitations ?? []} />
          </div>
          <EvidenceSection
            evidence={result.evidence}
            cited={result.verdict.evidence_ids ?? []}
            superseded={result.verdict.superseded_evidence_ids ?? []}
          />
          <EventTimeline runId={run.id} active={active} />
          <RunIdentity result={result} />
        </>
      ) : (
        <>
          <Progress run={run} />
          <EventTimeline runId={run.id} active={active} />
        </>
      )}
      <FindingCard run={run} />
    </div>
  );
}

function CancelButton({ runId }: { runId: string }) {
  const client = useQueryClient();
  const cancel = useMutation(mutations.cancel(client, runId));
  return (
    <div className="flex flex-col items-end gap-1">
      <Button
        size="sm"
        variant="outline"
        disabled={cancel.isPending || cancel.isSuccess}
        onClick={() => {
          if (window.confirm("Request cancellation of this investigation?"))
            cancel.mutate();
        }}
      >
        {cancel.isPending
          ? "Requesting cancellation…"
          : cancel.isSuccess
            ? "Cancellation requested"
            : "Cancel investigation"}
      </Button>
      {cancel.error && (
        <p role="alert" className="text-xs text-destructive">
          {cancel.error.message}
        </p>
      )}
    </div>
  );
}

function Neighbors({
  runId,
  search,
}: {
  runId: string;
  search: ReturnType<typeof queueSearch>;
}) {
  // Same query key as the list, so this is usually served from cache; no polling here.
  const list = useQuery({
    ...queries.runs(search.page ?? ""),
    refetchInterval: false,
  });
  const items = filterRuns(list.data?.items ?? [], search);
  const position = runNeighbors(runId, items);
  return (
    <nav
      className="flex flex-wrap items-center justify-between gap-3"
      aria-label="Investigation navigation"
    >
      <p className="text-sm text-muted-foreground">
        {position.position != null
          ? `Investigation ${position.position} of ${position.total} on this list page`
          : list.isPending
            ? "Loading list position…"
            : "This investigation is no longer on that list page."}
      </p>
      <div className="flex gap-2">
        {(["previous", "next"] as const).map((direction) => {
          const id = position[direction];
          const label = direction === "previous" ? "Previous" : "Next";
          return id ? (
            <Button key={direction} size="sm" variant="outline" asChild>
              <Link
                to="/runs/$runId"
                params={{ runId: id }}
                search={{ ...search, from_queue: true }}
              >
                {label}
              </Link>
            </Button>
          ) : (
            <Button key={direction} size="sm" variant="outline" disabled>
              {label}
            </Button>
          );
        })}
      </div>
    </nav>
  );
}

function Progress({ run }: { run: RunState }) {
  const active = runActive(run.status);
  return (
    <Card>
      <CardHeader>
        <CardTitle>{active ? "In progress" : "No report"}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 text-sm">
        <dl className="grid gap-3 sm:grid-cols-2">
          <div>
            <dt className="text-xs text-muted-foreground">Status</dt>
            <dd className="mt-1">{statusLabel(run.status)}</dd>
          </div>
          <div>
            <dt className="text-xs text-muted-foreground">Phase</dt>
            <dd className="mt-1">{phaseLabel(run.phase)}</dd>
          </div>
        </dl>
        <p className="text-muted-foreground">
          {active
            ? "The verdict, evidence and limitations appear when the investigation completes. This page refreshes every few seconds."
            : "This investigation produced no report, so there is no verdict or execution evidence to show."}
        </p>
      </CardContent>
    </Card>
  );
}

function EvidenceSection({
  evidence,
  cited,
  superseded,
}: {
  evidence: Evidence[];
  cited: string[];
  superseded: string[];
}) {
  const groups = [
    ["probe", "Probes"],
    ["command", "Workspace commands"],
  ] as const;
  return (
    <section aria-labelledby="evidence-heading" className="space-y-4">
      <div>
        <h2 id="evidence-heading" className="text-lg font-semibold">
          Execution evidence
        </h2>
        <p className="text-sm text-muted-foreground">
          Reports include only cited, superseded and contrary executions.
          Commands and output are untrusted text; a displayed exit code is not
          execution evidence on its own.
        </p>
      </div>
      {evidence.length === 0 && (
        <p className="empty rounded-lg border">
          The report contains no execution evidence.
        </p>
      )}
      {groups.map(([kind, title]) => {
        const items = evidence
          .map((item, index) => ({ item, index }))
          .filter(({ item }) => item.kind === kind);
        if (!items.length) return null;
        return (
          <div key={kind} className="space-y-3">
            <h3 className="text-sm font-semibold text-muted-foreground">
              {title} ({items.length})
            </h3>
            {items.map(({ item, index }) => (
              <EvidenceCard
                key={item.id}
                evidence={item}
                anchor={evidenceAnchor(index)}
                cited={cited.includes(item.id)}
                superseded={superseded.includes(item.id)}
              />
            ))}
          </div>
        );
      })}
    </section>
  );
}

function FindingCard({ run }: { run: RunState }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Finding as submitted</CardTitle>
        <p className="text-xs text-muted-foreground">
          Submitted text is untrusted input to the investigator.
        </p>
      </CardHeader>
      <CardContent>
        <OutputBlock
          label="Description"
          value={run.finding.description}
          defaultOpen
        />
      </CardContent>
    </Card>
  );
}
