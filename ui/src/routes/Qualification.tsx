import { queries } from "@/api/queries";
import { useQuery } from "@tanstack/react-query";
import { BrokerRuntimeMetadata } from "@/components/RuntimeIndicator";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

/**
 * Only what this deployment can observe: its runtime profile, broker measurement and model
 * connectivity receipt. Component qualification is reviewed evidence committed with the change
 * that produced it, never a service measurement, so it is not presented here.
 */
export function Qualification() {
  const query = useQuery(queries.runtime());
  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="eyebrow">Measured evidence</p>
          <h1>Qualification</h1>
          <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
            Runtime and broker observations this deployment can verify. Nothing
            here is inferred from configuration alone.
          </p>
        </div>
        <Button
          variant="outline"
          disabled={query.isFetching}
          onClick={() => void query.refetch()}
        >
          Refresh
        </Button>
      </header>
      <BrokerRuntimeMetadata />
      <Card>
        <CardHeader>
          <CardTitle>Agent qualification</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          Accepted agent evaluation results are committed under{" "}
          <code>evals/baselines/</code> and reviewed with the change that
          produced them. The service does not measure them, so it reports no
          per-agent qualification status.
        </CardContent>
      </Card>
    </div>
  );
}
