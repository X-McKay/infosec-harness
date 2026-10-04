import { queries, queryKeys } from "@/api/queries";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type QualificationStatus } from "@/api/client";
import { BrokerRuntimeMetadata } from "@/components/RuntimeIndicator";
import { componentTitle } from "@/lib/runtime";
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

export function Qualification() {
  const queryClient = useQueryClient();
  const query = useQuery({
    ...queries.qualification(),
  });
  const data = query.data;
  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="eyebrow">Measured evidence</p>
          <h1>Qualification</h1>
          <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
            Retained component evidence is tied to its measured source. The
            active model and transport profile has a separate qualification
            status.
          </p>
        </div>
        <Button
          variant="outline"
          disabled={query.isFetching}
          onClick={() => {
            void query.refetch();
            void queryClient.refetchQueries({ queryKey: queryKeys.runtime });
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
                Active model and transport profile
                <StatusBadge
                  status={data.active_profile_status || "not_checked"}
                />
              </CardTitle>
              <p className="text-sm text-muted-foreground">
                {data.active_profile_detail ||
                  "The active model and transport profile has not been checked."}
              </p>
            </CardHeader>
          </Card>
          {data.limitations.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Remaining qualification gaps</CardTitle>
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
          <Card>
            <CardHeader>
              <CardTitle className="flex flex-wrap items-center gap-3">
                {componentTitle(data.status)}{" "}
                <StatusBadge status={data.status} />
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
        </>
      )}
      <BrokerRuntimeMetadata />
    </div>
  );
}
