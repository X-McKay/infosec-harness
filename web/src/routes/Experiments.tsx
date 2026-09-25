import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

export function Experiments() {
  const { data: experiments = [] } = useQuery({ queryKey: ["experiments"], queryFn: api.experiments });
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Experiments</h1>
      <p className="text-sm text-muted-foreground">
        Each row is a dataset × agent-config × repetitions run of <code>harness eval run</code>.
        Compare accuracy, cost, and cache-hit to choose the best-fit model per agent.
      </p>
      <Card><CardHeader><CardTitle>Eval runs</CardTitle></CardHeader><CardContent className="p-0">
        <Table>
          <TableHeader><TableRow>
            <TableHead>Agent</TableHead><TableHead>Dataset</TableHead><TableHead>Config</TableHead>
            <TableHead className="text-right">Accuracy</TableHead><TableHead className="text-right">$/case</TableHead>
            <TableHead className="text-right">Cache hit</TableHead><TableHead className="text-right">Reps</TableHead>
          </TableRow></TableHeader>
          <TableBody>
            {experiments.length === 0 && <TableRow><TableCell colSpan={7} className="text-muted-foreground">No experiments yet.</TableCell></TableRow>}
            {experiments.map((e) => {
              const m = (e.metrics || {}) as Record<string, number>;
              return (
                <TableRow key={String(e.id)}>
                  <TableCell className="font-medium">{String(e.agent)}</TableCell>
                  <TableCell className="text-xs">{String(e.dataset)}@{String(e.dataset_version)}</TableCell>
                  <TableCell className="font-mono text-xs">{String((e as Record<string, unknown>).config_hash ?? "").slice(0, 8) || "-"}</TableCell>
                  <TableCell className="text-right">{m.accuracy != null ? `${(m.accuracy * 100).toFixed(0)}%` : "-"}</TableCell>
                  <TableCell className="text-right font-mono text-xs">${(m.cost_usd_per_case ?? 0).toFixed(4)}</TableCell>
                  <TableCell className="text-right">{m.cache_hit_ratio != null ? `${(m.cache_hit_ratio * 100).toFixed(0)}%` : "-"}</TableCell>
                  <TableCell className="text-right">{String(e.repetitions)}</TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </CardContent></Card>
    </div>
  );
}
