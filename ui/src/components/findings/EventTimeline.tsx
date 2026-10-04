import { timestamp } from "@/lib/format";
import { Clock3 } from "lucide-react";
import type { RunDetail } from "@/api/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export function EventTimeline({ events }: { events: RunDetail["events"] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Event timeline</CardTitle>
      </CardHeader>
      <CardContent>
        {events.length ? (
          <ol className="space-y-3">
            {events.map((event) => (
              <li key={event.id} className="flex gap-3 text-sm">
                <Clock3 className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
                <div>
                  <p className="font-medium">{event.phase}</p>
                  <p className="text-muted-foreground">{event.detail}</p>
                  <time className="text-xs text-muted-foreground">
                    {timestamp(event.created_at)}
                  </time>
                </div>
              </li>
            ))}
          </ol>
        ) : (
          <p className="empty">No lifecycle events recorded.</p>
        )}
      </CardContent>
    </Card>
  );
}
