import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { api } from "@/api/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { verdictLabel, verdictVariant } from "@/lib/verdict";

const VERDICTS = ["", "potentially_exploitable", "inconclusive", "likely_not_exploitable"];

export function TriageQueue() {
  const [verdict, setVerdict] = useState("");
  const { data: runs = [], isLoading } = useQuery({
    queryKey: ["runs", verdict],
    queryFn: () => api.runs(verdict ? { verdict } : {}),
  });

  const counts = runs.reduce((acc, r) => {
    const k = r.verdict || r.status; acc[k] = (acc[k] || 0) + 1; return acc;
  }, {} as Record<string, number>);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Triage queue</h1>
        <div className="flex gap-2">
          {VERDICTS.map((v) => (
            <Button key={v || "all"} size="sm" variant={verdict === v ? "default" : "outline"}
              onClick={() => setVerdict(v)}>
              {v ? verdictLabel(v) : "all"}
            </Button>
          ))}
        </div>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {(["potentially_exploitable", "inconclusive", "likely_not_exploitable"] as const).map((v) => (
          <Card key={v}><CardContent className="pt-4">
            <div className="text-2xl font-semibold">{counts[v] || 0}</div>
            <div className="text-xs text-muted-foreground">{verdictLabel(v)}</div>
          </CardContent></Card>
        ))}
        <Card><CardContent className="pt-4">
          <div className="text-2xl font-semibold">{runs.length}</div>
          <div className="text-xs text-muted-foreground">total findings</div>
        </CardContent></Card>
      </div>
      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Priority</TableHead><TableHead>Verdict</TableHead>
                <TableHead>Confidence</TableHead><TableHead>CWE</TableHead>
                <TableHead>Finding</TableHead><TableHead>Repo</TableHead>
                <TableHead className="text-right">Cost</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading && <TableRow><TableCell colSpan={7}>Loading…</TableCell></TableRow>}
              {!isLoading && runs.length === 0 && (
                <TableRow><TableCell colSpan={7} className="text-muted-foreground">No findings yet. Submit a batch via the API or CLI.</TableCell></TableRow>
              )}
              {runs.map((r) => (
                <TableRow key={r.id}>
                  <TableCell><Badge variant="outline">{r.priority || "-"}</Badge></TableCell>
                  <TableCell><Badge variant={verdictVariant(r.verdict)}>{verdictLabel(r.verdict)}</Badge></TableCell>
                  <TableCell>{r.confidence != null ? `${Math.round(r.confidence * 100)}%` : "-"}</TableCell>
                  <TableCell className="font-mono text-xs">{r.cwe || "-"}</TableCell>
                  <TableCell>
                    <Link to="/runs/$runId" params={{ runId: r.id }} className="hover:underline">{r.title}</Link>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground truncate max-w-[180px]">{r.repo_url}</TableCell>
                  <TableCell className="text-right font-mono text-xs">${r.cost_usd.toFixed(4)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
