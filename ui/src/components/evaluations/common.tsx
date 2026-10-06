import type { ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { OUTCOME_LABELS, type GateRow, type Outcome } from "@/lib/evaluation";
import type { GateStatus, ReportKind } from "@/lib/reports";
import { cn } from "@/lib/utils";

/** `not_checked` is drawn as a dashed neutral badge: it never reads as success. */
export function GateBadge({
  status,
  compact,
  label,
}: {
  status: GateStatus;
  compact?: boolean;
  label?: string;
}) {
  const text =
    status === "not_checked"
      ? "not checked"
      : status === "passed"
        ? "passed"
        : "failed";
  return (
    <Badge
      variant={
        status === "passed"
          ? "safe"
          : status === "failed"
            ? "exploitable"
            : "outline"
      }
      className={cn(
        "whitespace-nowrap",
        status === "not_checked" &&
          "border-dashed font-medium text-muted-foreground",
        compact && "px-2 text-[11px]",
      )}
    >
      {label ? `${label} · ${text}` : text}
    </Badge>
  );
}

/** Report and check states as recorded. Only `passed` is green; anything unknown is neutral. */
export function StatusBadge({ status }: { status: string | null | undefined }) {
  const value = status || "unknown";
  const variant =
    value === "passed"
      ? "safe"
      : value === "failed"
        ? "exploitable"
        : value === "running" || value === "cancelled" || value === "starting"
          ? "inconclusive"
          : "outline";
  return (
    <Badge
      variant={variant}
      className={cn(
        "whitespace-nowrap",
        (value === "not_checked" || value === "unknown") &&
          "border-dashed font-medium text-muted-foreground",
      )}
    >
      {value.replaceAll("_", " ")}
    </Badge>
  );
}

const KIND_LABELS: Record<ReportKind, string> = {
  model: "cohort",
  diagnostic: "diagnostic",
  openshell: "qualification",
  replay: "replay",
  unknown: "unknown",
};
export const kindLabel = (kind: ReportKind) => KIND_LABELS[kind];

export function KindBadge({ kind }: { kind: ReportKind }) {
  return (
    <Badge
      variant="outline"
      className={cn(
        "whitespace-nowrap font-medium",
        kind === "model" && "border-primary/40 text-primary",
      )}
    >
      {KIND_LABELS[kind]}
    </Badge>
  );
}

const OUTCOME_STYLE: Record<Outcome, string> = {
  correct_positive:
    "border-transparent bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
  correct_negative:
    "border-transparent bg-sky-500/15 text-sky-700 dark:text-sky-400",
  unsafe_negative:
    "border-transparent bg-red-500/15 text-red-700 dark:text-red-400",
  false_positive:
    "border-transparent bg-orange-500/15 text-orange-700 dark:text-orange-400",
  inconclusive:
    "border-transparent bg-amber-500/15 text-amber-700 dark:text-amber-400",
  error: "border-red-500/40 text-red-700 dark:text-red-400",
  not_run: "border-dashed text-muted-foreground",
};

export function OutcomeBadge({ outcome }: { outcome: Outcome }) {
  return (
    <Badge
      variant="outline"
      className={cn("whitespace-nowrap", OUTCOME_STYLE[outcome])}
    >
      {OUTCOME_LABELS[outcome]}
    </Badge>
  );
}

export function Tile({
  label,
  value,
  detail,
  tone,
}: {
  label: string;
  value: ReactNode;
  detail?: ReactNode;
  tone?: "good" | "bad";
}) {
  return (
    <Card>
      <CardContent className="pt-4">
        <p className="text-xs text-muted-foreground">{label}</p>
        <p
          className={cn(
            "mt-1 text-xl font-semibold tabular-nums",
            tone === "bad" && "text-red-700 dark:text-red-400",
            tone === "good" && "text-emerald-700 dark:text-emerald-400",
          )}
        >
          {value}
        </p>
        {detail && (
          <p className="mt-1 text-xs text-muted-foreground">{detail}</p>
        )}
      </CardContent>
    </Card>
  );
}

export function Field({
  label,
  children,
  mono,
  className,
}: {
  label: string;
  children: ReactNode;
  mono?: boolean;
  className?: string;
}) {
  return (
    <div className={className}>
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className={cn(mono ? "break-all font-mono text-xs" : "break-words")}>
        {children}
      </dd>
    </div>
  );
}

export function Limitations({
  items,
  title = "Limitations",
}: {
  items: string[];
  title?: string;
}) {
  if (!items.length) return null;
  return (
    <div className="rounded-md border border-amber-300/60 bg-amber-50/60 p-3 text-xs text-amber-950 dark:border-amber-500/30 dark:bg-amber-950/20 dark:text-amber-100">
      <p className="font-medium">{title}</p>
      <ul className="mt-1 list-disc space-y-0.5 pl-4">
        {items.map((item, index) => (
          <li key={index}>{item}</li>
        ))}
      </ul>
    </div>
  );
}

export function GateTable({
  rows,
  caption,
}: {
  rows: GateRow[];
  caption: string;
}) {
  return (
    <div className="relative overflow-auto">
      <table className="data-table">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            <th scope="col">Gate</th>
            <th scope="col">State</th>
            <th scope="col">Evidence</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.key}>
              <th
                scope="row"
                className="whitespace-nowrap font-medium text-foreground"
              >
                {row.label}
              </th>
              <td>
                <GateBadge status={row.status} />
              </td>
              <td className="text-muted-foreground">{row.detail}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Section({
  title,
  description,
  children,
  action,
  className,
}: {
  title: string;
  description?: ReactNode;
  children: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <Card className={cn("min-w-0", className)}>
      <CardHeader>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="space-y-1.5">
            <CardTitle>{title}</CardTitle>
            {description && (
              <p className="text-xs text-muted-foreground">{description}</p>
            )}
          </div>
          {action}
        </div>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>;
}

export const bytes = (value: number | null | undefined) => {
  if (value == null) return "Unavailable";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} kB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
};
