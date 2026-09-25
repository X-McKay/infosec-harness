import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { useState } from "react";
import { api } from "@/api/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { verdictLabel, verdictVariant } from "@/lib/verdict";
import { ArrowLeft } from "lucide-react";

function J({ value }: { value: unknown }) {
  return <pre className="text-xs bg-muted rounded-md p-3 overflow-auto max-h-96">{JSON.stringify(value, null, 2)}</pre>;
}

export function FindingDetail() {
  const { runId } = useParams({ from: "/runs/$runId" });
  const qc = useQueryClient();
  const { data: run, isLoading } = useQuery({ queryKey: ["run", runId], queryFn: () => api.run(runId) });
  const [reason, setReason] = useState("");
  const review = useMutation({
    mutationFn: (body: { decision: string; override_label?: string }) =>
      api.review(runId, { reviewer: "analyst", reason, ...body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["run", runId] }),
  });

  if (isLoading || !run) return <div>Loading…</div>;
  const verdict = (run.result?.verdict ?? {}) as Record<string, unknown>;
  const invocations = run.invocations || [];
  const totalCost = invocations.reduce((s, i) => s + (Number(i.cost_usd) || 0), 0);

  return (
    <div className="space-y-4">
      <Link to="/" className="text-sm text-muted-foreground hover:text-foreground inline-flex items-center gap-1">
        <ArrowLeft className="h-4 w-4" /> Back to queue
      </Link>
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">{run.title}</h1>
        <div className="flex items-center gap-2">
          <Badge variant="outline">{run.priority || "-"}</Badge>
          <Badge variant={verdictVariant(run.verdict)}>{verdictLabel(run.verdict)}</Badge>
        </div>
      </div>

      <div className="grid md:grid-cols-3 gap-4">
        <Card className="md:col-span-2">
          <CardHeader><CardTitle>Verdict</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-sm">
            <p>{String(verdict.rationale ?? "")}</p>
            <div className="text-muted-foreground text-xs">
              confidence {run.confidence != null ? `${Math.round(run.confidence * 100)}%` : "-"}
              {" · "}environment {run.environment_scope}
              {run.early_exit ? ` · early exit: ${run.early_exit}` : ""}
              {run.inconclusive_reason ? ` · ${run.inconclusive_reason}` : ""}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Review</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {run.review ? (
              <div className="text-sm">
                <Badge variant="outline">{run.review.decision}</Badge>
                {run.review.override_label && <span className="ml-2">{verdictLabel(run.review.override_label)}</span>}
                <p className="text-muted-foreground text-xs mt-1">{run.review.reason}</p>
              </div>
            ) : (
              <>
                <textarea className="w-full text-sm rounded-md border bg-background p-2" rows={2}
                  placeholder="Reason (optional)" value={reason} onChange={(e) => setReason(e.target.value)} />
                <div className="flex gap-2">
                  <Button size="sm" onClick={() => review.mutate({ decision: "confirm" })}>Confirm</Button>
                  <Button size="sm" variant="outline"
                    onClick={() => review.mutate({ decision: "override", override_label: "likely_not_exploitable" })}>
                    Override → not exploitable
                  </Button>
                </div>
              </>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader><CardTitle>Agent trace · ${totalCost.toFixed(4)} · {run.total_tokens} tokens · {run.cache_read_tokens} cached</CardTitle></CardHeader>
        <CardContent className="p-0">
          <table className="w-full text-sm">
            <thead className="text-muted-foreground border-b"><tr>
              <th className="text-left p-2">Agent</th><th className="text-left p-2">Model</th>
              <th className="text-right p-2">In/Out</th><th className="text-right p-2">Cache</th>
              <th className="text-right p-2">Cost</th><th className="text-right p-2">Latency</th>
            </tr></thead>
            <tbody>
              {invocations.map((i, n) => (
                <tr key={n} className="border-b last:border-0">
                  <td className="p-2 font-medium">{String(i.agent)}</td>
                  <td className="p-2 font-mono text-xs">{String(i.model_name)}</td>
                  <td className="p-2 text-right font-mono text-xs">{String(i.input_tokens)}/{String(i.output_tokens)}</td>
                  <td className="p-2 text-right font-mono text-xs">{String(i.cache_read_tokens)}</td>
                  <td className="p-2 text-right font-mono text-xs">${Number(i.cost_usd || 0).toFixed(4)}</td>
                  <td className="p-2 text-right font-mono text-xs">{Number(i.latency_s).toFixed(2)}s</td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>

      <div className="grid md:grid-cols-2 gap-4">
        <Card><CardHeader><CardTitle>Finding</CardTitle></CardHeader><CardContent><J value={run.finding} /></CardContent></Card>
        <Card><CardHeader><CardTitle>Result</CardTitle></CardHeader><CardContent><J value={run.result} /></CardContent></Card>
      </div>
    </div>
  );
}
