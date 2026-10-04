import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { api } from "@/api/client";
import { QueryState, Freshness } from "@/components/QueryState";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
const ACTIVE = new Set([
  "pending",
  "accepted",
  "running",
  "preparing",
  "building",
  "probing",
  "triaging",
]);
export function Workflows() {
  const query = useQuery({
    queryKey: ["batches"],
    queryFn: api.batches,
    refetchInterval: (q) =>
      q.state.data?.some((b) => ACTIVE.has(b.status)) ? 2000 : 10000,
  });
  return (
    <div className="space-y-6">
      <div>
        <p className="eyebrow">Execution</p>
        <h1>Workflows</h1>
        <p className="text-sm text-muted-foreground mt-2">
          Latest recorded batch status. Select a batch to inspect its finding
          records and per-run event history.
        </p>
      </div>
      <Freshness
        at={query.dataUpdatedAt}
        fetching={query.isFetching}
        stale={query.isError}
      />
      <QueryState
        loading={query.isPending}
        error={query.error}
        retry={() => void query.refetch()}
      />
      <div className="space-y-3">
        {query.data?.map((b) => (
          <Card key={b.id}>
            <CardContent className="pt-5 flex justify-between items-center gap-4">
              <div>
                <Link
                  to="/"
                  search={{
                    batch_id: b.id,
                    verdict: "",
                    search: "",
                    offset: 0,
                  }}
                  className="font-medium hover:underline"
                >
                  {b.label || b.id}
                </Link>
                <p className="text-xs text-muted-foreground mt-1">
                  {b.finding_count} findings ·{" "}
                  {new Date(b.created_at).toLocaleString()}
                </p>
              </div>
              <Badge variant="outline">{b.status}</Badge>
            </CardContent>
          </Card>
        ))}
        {query.data?.length === 0 && (
          <p className="empty">
            No workflows yet. Submit a batch through the CLI or API.
          </p>
        )}
      </div>
    </div>
  );
}
