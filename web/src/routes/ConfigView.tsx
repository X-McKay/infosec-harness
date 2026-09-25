import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

export function ConfigView() {
  const { data } = useQuery({ queryKey: ["config"], queryFn: api.config });
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <h1 className="text-2xl font-semibold">Configuration</h1>
        {data && <Badge variant="outline">model mode: {data.model_mode}</Badge>}
      </div>
      <Card><CardHeader><CardTitle>Agents</CardTitle></CardHeader><CardContent className="p-0">
        <Table>
          <TableHeader><TableRow>
            <TableHead>Agent</TableHead><TableHead>Tier</TableHead>
            <TableHead>Resolved model</TableHead><TableHead>Config hash</TableHead>
          </TableRow></TableHeader>
          <TableBody>
            {(data?.agents || []).map((a) => (
              <TableRow key={a.name}>
                <TableCell className="font-medium">{a.name}</TableCell>
                <TableCell><Badge variant="outline">{a.model_tier}</Badge></TableCell>
                <TableCell className="font-mono text-xs">{a.resolved_model}</TableCell>
                <TableCell className="font-mono text-xs">{a.config_hash}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent></Card>
    </div>
  );
}
