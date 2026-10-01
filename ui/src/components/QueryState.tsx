import { Button } from "@/components/ui/button";
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
        className="rounded-lg border border-destructive/40 bg-destructive/5 p-5 space-y-3"
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
      <div role="status" className="animate-pulse space-y-3 py-8">
        <p className="text-muted-foreground">Loading current data…</p>
        <div className="h-24 rounded-lg bg-muted" />
      </div>
    );
  return null;
}
export function Freshness({
  at,
  fetching,
  stale,
}: {
  at?: number | string;
  fetching?: boolean;
  stale?: boolean;
}) {
  return (
    <p className="text-xs text-muted-foreground" role="status">
      {stale
        ? "Refresh failed · showing last known data · "
        : fetching
          ? "Refreshing · "
          : ""}
      {at ? `Updated ${new Date(at).toLocaleTimeString()}` : "Waiting for data"}
    </p>
  );
}
