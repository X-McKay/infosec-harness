import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { queries } from "@/api/queries";
import { Freshness, QueryState } from "@/components/QueryState";
import { ThemeSelect } from "@/components/ThemeProvider";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { apiBase, healthPresentation, readable } from "@/lib/runtime";

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-1 break-all text-sm">{children}</dd>
    </div>
  );
}

export function Runtime() {
  const query = useQuery(queries.health());
  const health = query.data ? healthPresentation(query.data) : null;
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="eyebrow">Runtime identity</p>
          <h1>Runtime</h1>
          <p className="mt-2 max-w-3xl text-sm text-muted-foreground">
            What the API reports about the control plane serving this view.
            Values are read-only; the UI holds no configuration of its own.
          </p>
        </div>
        {health?.generation && (
          <Badge variant="outline">generation {health.generation}</Badge>
        )}
      </div>
      <Freshness
        at={query.dataUpdatedAt}
        fetching={query.isFetching}
        stale={query.isError && !!health}
      />
      <QueryState
        loading={query.isPending}
        error={query.error}
        retry={() => void query.refetch()}
      />
      <div className="grid gap-5 lg:grid-cols-2">
        {health && (
          <Card>
            <CardHeader>
              <CardTitle>API health</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="grid gap-4 sm:grid-cols-2">
                <Row label="Status">{readable(health.status)}</Row>
                <Row label="Temporal">{readable(health.temporal)}</Row>
                <Row label="Generation">
                  <span className="font-mono">
                    {health.generation ?? "Not reported"}
                  </span>
                </Row>
                <Row label="Task queue">
                  <span className="font-mono">
                    {health.taskQueue ?? "Not reported"}
                  </span>
                </Row>
                <Row label="Native OpenShell runtime">
                  <Badge
                    variant={
                      health.runtime === "not_checked" ? "muted" : "outline"
                    }
                  >
                    {readable(health.runtime)}
                  </Badge>
                </Row>
                {health.other.map(([key, value]) => (
                  <Row key={key} label={key.replaceAll("_", " ")}>
                    {value}
                  </Row>
                ))}
              </dl>
              <p className="mt-4 text-xs text-muted-foreground">
                A healthy response confirms only that the API reached the
                Temporal control plane. It does not establish model
                availability, provider credentials or sandbox isolation; run{" "}
                <code>./dev qualify</code> for measured boundary evidence.
              </p>
            </CardContent>
          </Card>
        )}
        <Card>
          <CardHeader>
            <CardTitle>This interface</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <dl className="grid gap-4 sm:grid-cols-2">
              <Row label="API base">
                <span className="font-mono">
                  {apiBase(window.location.origin)}
                </span>
              </Row>
              <Row label="Refresh">
                List 5 s · active investigation 3 s · health 30 s
              </Row>
            </dl>
            <label className="form-label max-w-[12rem]">
              Appearance
              <ThemeSelect className="field" />
            </label>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
