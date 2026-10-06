import { useQuery } from "@tanstack/react-query";
import { ChevronDown } from "lucide-react";
import { useState } from "react";
import { queries } from "@/api/queries";
import { healthPresentation, readable, temporalLabel } from "@/lib/runtime";
import { cn } from "@/lib/utils";

/**
 * Shell summary of GET /api/health: what the API reports, nothing inferred beyond it. The
 * sidebar shows every line; the phone header shows the summary line and keeps the rest behind
 * a disclosure button.
 */
export function RuntimeIndicator() {
  const query = useQuery(queries.health());
  const [open, setOpen] = useState(false);
  const health = query.data ? healthPresentation(query.data) : null;
  // Green only while the latest answer reports a ready control plane with Temporal reachable.
  const ready = !!health?.ready && !query.isError;
  return (
    <div className="flex min-w-0 items-start gap-1 text-xs text-muted-foreground md:mb-3">
      <div className="min-w-0 space-y-1 md:flex-1" role="status">
        <p className="flex items-center gap-2 font-medium text-foreground">
          <span
            aria-hidden="true"
            className={cn(
              "inline-block h-2 w-2 shrink-0 rounded-full",
              ready
                ? "bg-emerald-500"
                : query.isPending
                  ? "bg-muted-foreground"
                  : "bg-red-500",
            )}
          />
          <span className="truncate">
            {health && !query.isError
              ? health.status
                ? readable(health.status)
                : "API responding"
              : query.isPending
                ? "Checking API…"
                : "API unavailable"}
          </span>
        </p>
        {health && (
          <div
            id="runtime-details"
            className={cn("space-y-1", open ? "block" : "hidden md:block")}
          >
            <p>Temporal: {temporalLabel(health.temporal)}</p>
            {health.generation && <p>Generation {health.generation}</p>}
            {health.taskQueue && (
              <p className="break-all">Queue {health.taskQueue}</p>
            )}
            <p>Native runtime: {readable(health.runtime)}</p>
            {query.isError && <p>Refresh failed · last known health</p>}
          </div>
        )}
      </div>
      {health && (
        <button
          type="button"
          className="-my-1 inline-flex h-6 w-6 shrink-0 items-center justify-center rounded text-muted-foreground hover:bg-muted hover:text-foreground md:hidden"
          aria-expanded={open}
          aria-controls="runtime-details"
          aria-label="Runtime details"
          onClick={() => setOpen((value) => !value)}
        >
          <ChevronDown
            className={cn("h-4 w-4 transition-transform", open && "rotate-180")}
            aria-hidden="true"
          />
        </button>
      )}
    </div>
  );
}
