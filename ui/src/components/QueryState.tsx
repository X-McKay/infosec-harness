import { timestamp } from "@/lib/format";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export function QueryState({
  loading,
  error,
  retry,
}: {
  loading?: boolean;
  error?: Error | null;
  retry?: () => void;
}) {
  if (error)
    return (
      <div
        role="alert"
        className="space-y-3 rounded-lg border border-destructive/40 bg-destructive/5 p-5"
      >
        <p>Could not load this view. {error.message}</p>
        {retry && (
          <Button variant="outline" onClick={retry}>
            Try again
          </Button>
        )}
      </div>
    );
  if (loading)
    return (
      <div role="status" className="space-y-3 py-8">
        <p className="text-muted-foreground">Loading current data…</p>
        <div className="h-24 animate-pulse rounded-lg bg-muted" />
      </div>
    );
  return null;
}

/** "5 s", "1 min": a refresh interval as a reader says it. */
export function intervalLabel(ms: number): string {
  const seconds = Math.round(ms / 1000);
  return seconds < 60 ? `${seconds} s` : `${Math.round(seconds / 60)} min`;
}

/**
 * When the view last loaded and whether it refreshes itself. `live` is the view's refresh
 * interval in milliseconds, or false when nothing refreshes it (a finished investigation, a
 * finished report). Only a failed refresh is announced; routine refetches stay silent.
 */
export function Freshness({
  at,
  fetching,
  stale,
  live,
  className,
}: {
  at?: number | string;
  fetching?: boolean;
  stale?: boolean;
  live?: number | false;
  className?: string;
}) {
  return (
    <p
      className={cn(
        "flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground",
        className,
      )}
    >
      {!!live && (
        <span
          className={cn(
            "inline-flex items-center gap-1.5 rounded-md border px-1.5 py-0.5 font-medium",
            stale
              ? "border-amber-600/50 text-amber-800 dark:border-amber-400/50 dark:text-amber-300"
              : "border-emerald-600/40 text-emerald-800 dark:border-emerald-400/40 dark:text-emerald-300",
          )}
          data-live={stale ? "stale" : "live"}
        >
          <span
            aria-hidden="true"
            className={cn(
              "h-1.5 w-1.5 rounded-full",
              stale ? "bg-amber-500" : "live-dot bg-emerald-500",
            )}
          />
          <span>{stale ? "Retrying" : "Live"}</span>
          <span className="font-normal">· every {intervalLabel(live)}</span>
        </span>
      )}
      {/* Present but out of the flow while empty, so the flex gap never indents the line. */}
      <span role="status" className={stale ? undefined : "sr-only"}>
        {stale ? "Refresh failed · showing last known data" : ""}
      </span>
      <span>
        {!stale && fetching ? "Refreshing · " : ""}
        {at ? `Updated ${timestamp(at, "time")}` : "Waiting for data"}
      </span>
    </p>
  );
}
