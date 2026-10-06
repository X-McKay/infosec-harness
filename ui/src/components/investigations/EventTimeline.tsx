import { useQuery } from "@tanstack/react-query";
import { Clock3 } from "lucide-react";
import { queries } from "@/api/queries";
import { QueryState } from "@/components/QueryState";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { timestamp } from "@/lib/format";
import { FAILURE_KINDS, eventKindLabel, eventsUnavailable } from "@/lib/events";

/** Temporal history projection; hidden entirely when the API answers 404 for this run. */
export function EventTimeline({
  runId,
  active,
}: {
  runId: string;
  active: boolean;
}) {
  const query = useQuery(queries.events(runId, active));
  if (eventsUnavailable(query.error)) return null;
  const data = query.data;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Event timeline</CardTitle>
        <p className="text-xs text-muted-foreground">
          Workflow history as recorded by Temporal. Event details are recorded
          text, not verified findings.
        </p>
      </CardHeader>
      <CardContent className="space-y-3">
        <QueryState
          loading={query.isPending}
          error={data ? null : query.error}
          retry={() => void query.refetch()}
        />
        {data && query.isError && (
          <p role="status" className="text-xs text-muted-foreground">
            Refresh failed · showing the last loaded events
          </p>
        )}
        {data &&
          (data.events.length ? (
            <ol className="space-y-3">
              {data.events.map((event, index) => (
                <li key={index} className="flex gap-3 text-sm">
                  <Clock3
                    className="mt-0.5 h-4 w-4 shrink-0 text-primary"
                    aria-hidden="true"
                  />
                  <div className="min-w-0 space-y-1">
                    <p className="flex flex-wrap items-center gap-2">
                      <span className="break-all font-medium">
                        {event.name ?? eventKindLabel(event.kind)}
                      </span>
                      {event.name && (
                        <Badge
                          variant={
                            FAILURE_KINDS.has(event.kind) ? "failed" : "outline"
                          }
                          className="font-normal"
                        >
                          {eventKindLabel(event.kind)}
                        </Badge>
                      )}
                    </p>
                    {event.detail && (
                      <p className="prose-text text-muted-foreground">
                        {event.detail}
                      </p>
                    )}
                    <time className="block text-xs text-muted-foreground">
                      {timestamp(event.at)}
                    </time>
                  </div>
                </li>
              ))}
            </ol>
          ) : (
            <p className="empty">No events recorded yet.</p>
          ))}
        {data?.truncated && (
          <p className="text-xs text-muted-foreground">
            The API bounded this timeline; not every recorded event is shown.
          </p>
        )}
        {!!data?.dropped && (
          <p className="text-xs text-muted-foreground">
            {data.dropped} malformed{" "}
            {data.dropped === 1 ? "event was" : "events were"} not shown.
          </p>
        )}
      </CardContent>
    </Card>
  );
}
