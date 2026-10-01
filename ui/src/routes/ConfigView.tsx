import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { QueryState, Freshness } from "@/components/QueryState";

export function ConfigView() {
  const query = useQuery({ queryKey: ["config"], queryFn: api.config });
  const config = query.data;
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="eyebrow">Runtime identity</p>
          <h1>Configuration</h1>
          <p className="mt-2 text-sm text-muted-foreground">
            Resolved agent configuration from the API. Values are read-only and
            redacted at the service boundary.
          </p>
        </div>
        {config && (
          <Badge variant="outline">model mode: {config.model_mode}</Badge>
        )}
      </div>
      <Freshness
        at={query.dataUpdatedAt}
        fetching={query.isFetching}
        stale={query.isError && !!config}
      />
      <QueryState
        loading={query.isPending}
        error={query.error}
        retry={() => void query.refetch()}
      />
      {config && (
        <Card>
          <CardHeader>
            <CardTitle>Agents</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-auto">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Agent</th>
                    <th>Tier</th>
                    <th>Resolved model</th>
                    <th>Config hash</th>
                  </tr>
                </thead>
                <tbody>
                  {config.agents.length ? (
                    config.agents.map((agent) => (
                      <tr key={agent.name}>
                        <td className="font-medium">{agent.name}</td>
                        <td>
                          <Badge variant="outline">
                            {agent.model_tier || "Unavailable"}
                          </Badge>
                        </td>
                        <td className="font-mono text-xs">
                          {agent.resolved_model || "Unavailable"}
                        </td>
                        <td className="max-w-[360px] truncate font-mono text-xs">
                          {agent.config_hash || "Unavailable"}
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={4} className="empty">
                        The API returned no agent configurations.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
      {config && (
        <p className="text-xs text-muted-foreground">
          A successful response confirms only that the configuration endpoint
          responded. It does not prove provider credentials, model availability,
          or sandbox isolation.
        </p>
      )}
    </div>
  );
}
