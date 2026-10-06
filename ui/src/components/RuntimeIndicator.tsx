import { useQuery } from "@tanstack/react-query";
import { queries } from "@/api/queries";
import { healthPresentation, readable } from "@/lib/runtime";
import { cn } from "@/lib/utils";

/** Sidebar summary of GET /api/health: what the API reports, nothing inferred beyond it. */
export function RuntimeIndicator() {
  const query = useQuery(queries.health());
  const health = query.data ? healthPresentation(query.data) : null;
  const reachable = !!health && !query.isError;
  return (
    <div className="mb-3 space-y-1 text-xs text-muted-foreground" role="status">
      <p className="flex items-center gap-2 font-medium text-foreground">
        <span
          aria-hidden="true"
          className={cn(
            "inline-block h-2 w-2 rounded-full",
            reachable
              ? "bg-emerald-500"
              : query.isPending
                ? "bg-muted-foreground"
                : "bg-red-500",
          )}
        />
        {reachable
          ? health.status
            ? readable(health.status)
            : "API responding"
          : query.isPending
            ? "Checking API…"
            : "API unavailable"}
      </p>
      {health && (
        <>
          {health.temporal && <p>Temporal: {readable(health.temporal)}</p>}
          {health.generation && <p>Generation {health.generation}</p>}
          {health.taskQueue && (
            <p className="break-all">Queue {health.taskQueue}</p>
          )}
          <p>Native runtime: {readable(health.runtime)}</p>
          {query.isError && <p>Refresh failed · last known health</p>}
        </>
      )}
    </div>
  );
}
