import { isRecord } from "@/lib/json";

const MAX_DEPTH = 8;
const MAX_ITEMS = 200;
const MAX_STRING = 4000;

/**
 * Read-only view of an untrusted JSON document. Keys and values render only as React text;
 * nothing becomes a link, attribute or markup. Depth, breadth and string length are bounded.
 */
export function JsonTree({
  value,
  label = "document",
}: {
  value: unknown;
  label?: string;
}) {
  return (
    <div className="overflow-auto rounded-md border bg-muted/30 p-3 font-mono text-xs leading-relaxed">
      <Node name={label} value={value} depth={0} open />
    </div>
  );
}

function Scalar({ value }: { value: unknown }) {
  if (value === null)
    return <span className="text-muted-foreground">null</span>;
  if (typeof value === "string") {
    const shown =
      value.length > MAX_STRING ? `${value.slice(0, MAX_STRING)}…` : value;
    return (
      <span className="whitespace-pre-wrap break-all text-emerald-700 dark:text-emerald-400">
        "{shown}"
        {value.length > MAX_STRING && (
          <span className="text-muted-foreground">
            {" "}
            ({value.length} characters)
          </span>
        )}
      </span>
    );
  }
  if (typeof value === "number" || typeof value === "boolean")
    return <span className="text-primary">{String(value)}</span>;
  return <span className="text-muted-foreground">{typeof value}</span>;
}

function Node({
  name,
  value,
  depth,
  open,
}: {
  name: string;
  value: unknown;
  depth: number;
  open?: boolean;
}) {
  const container = Array.isArray(value) || isRecord(value);
  if (!container)
    return (
      <div>
        <span className="text-muted-foreground">{name}: </span>
        <Scalar value={value} />
      </div>
    );
  const entries: [string, unknown][] = Array.isArray(value)
    ? value.map((item, index) => [String(index), item])
    : Object.entries(value as Record<string, unknown>);
  const summary = Array.isArray(value)
    ? `[${entries.length}]`
    : `{${entries.length}}`;
  if (depth >= MAX_DEPTH)
    return (
      <div>
        <span className="text-muted-foreground">
          {name}: {summary} (nested too deeply to display)
        </span>
      </div>
    );
  return (
    <details open={open || depth < 1}>
      <summary className="cursor-pointer">
        <span className="text-muted-foreground">{name}</span> {summary}
      </summary>
      <div className="ml-4 border-l pl-3">
        {entries.slice(0, MAX_ITEMS).map(([key, item]) => (
          <Node key={key} name={key} value={item} depth={depth + 1} />
        ))}
        {entries.length > MAX_ITEMS && (
          <p className="text-muted-foreground">
            … {entries.length - MAX_ITEMS} more not shown
          </p>
        )}
      </div>
    </details>
  );
}
