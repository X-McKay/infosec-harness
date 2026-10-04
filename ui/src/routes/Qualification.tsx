import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type QualificationStatus } from "@/api/client";
import { Freshness, QueryState } from "@/components/QueryState";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

function StatusBadge({ status }: { status: QualificationStatus["status"] }) {
  return (
    <Badge
      variant={
        status === "passed"
          ? "safe"
          : status === "failed"
            ? "exploitable"
            : "outline"
      }
    >
      {status.replaceAll("_", " ")}
    </Badge>
  );
}

export function BrokerRuntimeMetadata() {
  const query = useQuery({
    queryKey: ["runtime-status"],
    queryFn: api.runtimeStatus,
    refetchInterval: 30000,
  });
  const runtime = query.data;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Runtime and broker observations</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <QueryState
          loading={query.isPending}
          error={query.error}
          retry={() => void query.refetch()}
        />
        {runtime && (
          <>
            <Freshness
              at={runtime.as_of}
              fetching={query.isFetching}
              stale={query.isError}
            />
            <dl className="grid gap-4 text-sm sm:grid-cols-2 lg:grid-cols-3">
              <div>
                <dt className="text-muted-foreground">Environment</dt>
                <dd>{runtime.environment}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">
                  Model mode / transport
                </dt>
                <dd>
                  {runtime.model_mode} / {runtime.assessment_transport}
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">
                  Database / Temporal mode
                </dt>
                <dd>
                  {runtime.database_backend} / {runtime.temporal_mode}
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">API source</dt>
                <dd className="break-all font-mono text-xs">
                  {runtime.api_source_commit || "Unavailable"}
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Broker observation</dt>
                <dd className="mt-1">
                  <StatusBadge status={runtime.broker.status} />
                  {runtime.broker.stale && <span className="ml-2">Stale</span>}
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Unresolved requests</dt>
                <dd>{runtime.broker.unresolved_requests ?? "Unavailable"}</dd>
              </div>
            </dl>
            <p className="text-sm text-muted-foreground">
              {runtime.broker.detail}
            </p>
            <p className="text-xs text-muted-foreground">
              Broker configured: {runtime.broker.configured ? "yes" : "no"}.
              Observation checked:{" "}
              {runtime.broker.checked_at
                ? new Date(runtime.broker.checked_at).toLocaleString()
                : "not checked"}
              .
            </p>
          </>
        )}
      </CardContent>
    </Card>
  );
}

export function Qualification() {
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: ["qualification"],
    queryFn: api.qualification,
    refetchInterval: 30000,
  });
  const data = query.data;
  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="eyebrow">Measured evidence</p>
          <h1>Qualification</h1>
          <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
            Component evidence retains its measured source and reuse status. An
            assembled matrix does not establish a fresh full-system run.
          </p>
        </div>
        <Button
          variant="outline"
          disabled={query.isFetching}
          onClick={() => {
            void query.refetch();
            void queryClient.refetchQueries({ queryKey: ["runtime-status"] });
          }}
        >
          Refresh
        </Button>
      </header>
      <QueryState
        loading={query.isPending}
        error={query.error}
        retry={() => void query.refetch()}
      />
      {data && (
        <>
          <Freshness
            at={data.as_of}
            fetching={query.isFetching}
            stale={query.isError}
          />
          <Card>
            <CardHeader>
              <CardTitle className="flex flex-wrap items-center gap-3">
                Component qualification <StatusBadge status={data.status} />
              </CardTitle>
              <p className="text-sm text-muted-foreground">{data.detail}</p>
              <p className="break-all font-mono text-xs text-muted-foreground">
                Candidate: {data.candidate_commit || "Unavailable"}
              </p>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-auto">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Agent / scope</th>
                      <th>Gate status</th>
                      <th>Evidence</th>
                      <th>Cases passed</th>
                      <th>Measured source</th>
                      <th>Basis</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.components.length ? (
                      data.components.map((row) => (
                        <tr key={`${row.agent}:${row.scope}`}>
                          <td>
                            <p className="font-medium">{row.agent}</p>
                            <p className="text-xs text-muted-foreground">
                              {row.scope}
                            </p>
                          </td>
                          <td>
                            <StatusBadge status={row.status} />
                          </td>
                          <td>{row.freshness}</td>
                          <td>
                            {row.passed_cases != null && row.cases != null
                              ? `${row.passed_cases} / ${row.cases}`
                              : "Unavailable"}
                          </td>
                          <td
                            className="font-mono text-xs"
                            title={row.measured_commit || undefined}
                          >
                            {row.measured_commit?.slice(0, 12) || "Unavailable"}
                          </td>
                          <td className="max-w-md text-sm">{row.reason}</td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan={6} className="empty">
                          No component qualification evidence is available.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
          {data.limitations.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Remaining scope and limitations</CardTitle>
              </CardHeader>
              <CardContent>
                <ul className="list-disc space-y-2 pl-5 text-sm text-muted-foreground">
                  {data.limitations.map((item, index) => (
                    <li key={index}>{item}</li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          )}
        </>
      )}
      <BrokerRuntimeMetadata />
    </div>
  );
}
