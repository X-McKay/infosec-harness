import { timestamp } from "@/lib/format";
import { queries } from "@/api/queries";
import { useQuery } from "@tanstack/react-query";
import { Freshness, QueryState } from "@/components/QueryState";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  brokerPresentation,
  connectivityPresentation,
  modelNames,
} from "@/lib/runtime";

export function RuntimeIndicator() {
  const query = useQuery({
    ...queries.runtime(),
  });
  const runtime = query.data;
  const broker = runtime ? brokerPresentation(runtime.broker) : null;
  const connectivity = connectivityPresentation(runtime?.model_connectivity);
  return (
    <div className="mb-3 space-y-1 text-xs text-muted-foreground" role="status">
      {runtime ? (
        <>
          <p className="font-medium text-foreground">{runtime.environment}</p>
          <p>Model mode: {runtime.model_mode}</p>
          <p className="break-words">
            Models: {modelNames(runtime.model_names)}
          </p>
          <p>Transport: {runtime.assessment_transport}</p>
          <p>Model connectivity: {connectivity.label}</p>
          <p>
            Broker: {broker?.label}
            {broker?.stale ? " · observation stale" : ""}
          </p>
          {query.isError && <p>Refresh failed · last known runtime</p>}
        </>
      ) : (
        <p>{query.isPending ? "Loading runtime…" : "Runtime unavailable"}</p>
      )}
    </div>
  );
}

export function BrokerRuntimeMetadata() {
  const query = useQuery({
    ...queries.runtime(),
  });
  const runtime = query.data;
  const broker = runtime ? brokerPresentation(runtime.broker) : null;
  const connectivity = connectivityPresentation(runtime?.model_connectivity);
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
                  <Badge
                    variant={
                      runtime.broker.configured &&
                      runtime.broker.status === "passed"
                        ? "safe"
                        : "outline"
                    }
                  >
                    {broker?.label}
                  </Badge>
                  {broker?.stale && <span className="ml-2">Stale</span>}
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Unresolved requests</dt>
                <dd>
                  {runtime.broker.configured
                    ? (broker?.unresolved ?? "Unavailable")
                    : "Not applicable"}
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Configured models</dt>
                <dd className="break-words">
                  {modelNames(runtime.model_names)}
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">
                  Last measured model connectivity
                </dt>
                <dd>{connectivity.label}</dd>
                <dd className="text-xs text-muted-foreground">
                  {connectivity.checkedAt
                    ? timestamp(connectivity.checkedAt)
                    : "No check recorded"}
                </dd>
              </div>
            </dl>
            <p className="text-sm text-muted-foreground">
              {connectivity.detail}
            </p>
            <p className="text-sm text-muted-foreground">
              {runtime.broker.configured
                ? runtime.broker.detail
                : "Credential broker is not enabled for this runtime."}
            </p>
            <p className="text-xs text-muted-foreground">
              Broker configured: {runtime.broker.configured ? "yes" : "no"}.
              Observation checked:{" "}
              {runtime.broker.configured && runtime.broker.checked_at
                ? timestamp(runtime.broker.checked_at)
                : "not checked"}
              .
            </p>
          </>
        )}
      </CardContent>
    </Card>
  );
}
