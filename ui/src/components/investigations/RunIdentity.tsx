import type { components } from "@/api/schema";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { number } from "@/lib/format";

type Result = components["schemas"]["InvestigationResult"];

/** Well-known usage counters first, in a stable order; the rest alphabetically. */
const USAGE_ORDER = ["requests", "tool_calls", "input_tokens", "output_tokens"];
function usageRows(usage: Result["usage"]): [string, number | null][] {
  return Object.entries(usage ?? {}).sort(([a], [b]) => {
    const ia = USAGE_ORDER.indexOf(a);
    const ib = USAGE_ORDER.indexOf(b);
    if (ia >= 0 || ib >= 0)
      return (
        (ia < 0 ? USAGE_ORDER.length : ia) - (ib < 0 ? USAGE_ORDER.length : ib)
      );
    return a.localeCompare(b);
  });
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-1 break-all font-mono text-xs">{value}</dd>
    </div>
  );
}

export function RunIdentity({ result }: { result: Result }) {
  const identity = result.worker_identity;
  const usage = usageRows(result.usage);
  const dependencies = Object.entries(identity?.dependencies ?? {}).sort(
    ([a], [b]) => a.localeCompare(b),
  );
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Model and worker identity</CardTitle>
          <p className="text-xs text-muted-foreground">
            Recorded identity of the worker that produced this report. A
            recorded name or digest is not execution evidence.
          </p>
        </CardHeader>
        <CardContent className="space-y-4">
          <dl className="grid gap-4 sm:grid-cols-2">
            <Field label="Model" value={result.model || "Unavailable"} />
            <Field label="Source digest" value={result.source_digest} />
            {identity ? (
              <>
                <Field
                  label="Worker fingerprint"
                  value={identity.fingerprint}
                />
                <Field label="Code SHA-256" value={identity.code_sha256} />
                <Field label="Config SHA-256" value={identity.config_sha256} />
              </>
            ) : (
              <Field label="Worker identity" value="Not recorded" />
            )}
          </dl>
          {dependencies.length > 0 && (
            <details>
              <summary className="cursor-pointer text-xs font-medium">
                Dependencies ({dependencies.length})
              </summary>
              <div className="relative mt-2 max-h-72 overflow-auto">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th scope="col">Package</th>
                      <th scope="col">Version</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dependencies.map(([name, version]) => (
                      <tr key={name}>
                        <td className="font-mono">{name}</td>
                        <td className="break-all font-mono">{version}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </details>
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Usage</CardTitle>
          <p className="text-xs text-muted-foreground">
            Model usage recorded for this investigation.
          </p>
        </CardHeader>
        <CardContent>
          {usage.length ? (
            <table className="data-table">
              <tbody>
                {usage.map(([key, value]) => (
                  <tr key={key}>
                    <th scope="row" className="font-normal">
                      {key.replaceAll("_", " ")}
                    </th>
                    <td className="text-right font-mono tabular-nums">
                      {number(value, 4)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="text-sm text-muted-foreground">No usage recorded.</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
