/**
 * Presentation of GET /api/health. Only what the API reports is shown; a configured name is
 * never measured execution evidence, and an unreported check is "not_checked", never passed.
 */
import { isRecord, text } from "./json.ts";

export type HealthPresentation = {
  /** The API answered 200, which it does only after reaching the Temporal control plane. */
  status: string | null;
  temporal: string | null;
  /** The native OpenShell runtime; the API does not check it, so absence is not_checked. */
  runtime: string;
  generation: string | null;
  taskQueue: string | null;
  /** Any other reported string fields, sorted by key. */
  other: [string, string][];
};

const KNOWN = new Set([
  "status",
  "temporal",
  "runtime",
  "generation",
  "task_queue",
]);

export function healthPresentation(health: unknown): HealthPresentation {
  const record = isRecord(health) ? health : {};
  return {
    status: text(record.status),
    temporal: text(record.temporal),
    runtime: text(record.runtime) ?? "not_checked",
    generation: text(record.generation),
    taskQueue: text(record.task_queue),
    other: Object.entries(record)
      .filter(
        (entry): entry is [string, string] =>
          !KNOWN.has(entry[0]) && typeof entry[1] === "string",
      )
      .sort(([a], [b]) => a.localeCompare(b)),
  };
}

export const readable = (value: string | null | undefined) =>
  value ? value.replaceAll("_", " ") : "Not reported";

/** API base the browser calls; the UI only ever requests same-origin /api paths. */
export function apiBase(origin: string): string {
  return `${origin.replace(/\/+$/, "")}/api`;
}
