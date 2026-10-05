/**
 * Execution evidence basis, derived from the origins persisted with each probe execution
 * (`ProbeExecution.origins`, written from the controller's execution record).
 * Fails closed: the notice warns unless every origin is recorded and controller-authored.
 */
import { isRecord, text } from "./json.ts";

const VERIFIED_ORIGINS = new Set(["controller"]);
export const PROVENANCE_FIELDS = ["observations", "process", "runner"] as const;
export type ProvenanceField = (typeof PROVENANCE_FIELDS)[number];

export type ExecutionProvenance = {
  verified: boolean;
  /** Distinct recorded origins per field; null means no origin was recorded. */
  origins: Record<ProvenanceField, (string | null)[]>;
};

/** The recorded origin of one section of one execution, or null when none was recorded. */
function recordedOrigin(execution: unknown, field: ProvenanceField) {
  const origins = isRecord(execution) ? execution.origins : null;
  const section = isRecord(origins) ? origins[field] : null;
  return isRecord(section) ? text(section.origin) : null;
}

export function executionProvenance(
  executions: readonly unknown[],
): ExecutionProvenance | null {
  if (!executions.length) return null;
  const origins = Object.fromEntries(
    PROVENANCE_FIELDS.map((field) => [
      field,
      [...new Set(executions.map((item) => recordedOrigin(item, field)))],
    ]),
  ) as ExecutionProvenance["origins"];
  const verified = PROVENANCE_FIELDS.every((field) =>
    origins[field].every(
      (origin) => origin != null && VERIFIED_ORIGINS.has(origin),
    ),
  );
  return { verified, origins };
}

export function originSummary(provenance: ExecutionProvenance): string {
  return PROVENANCE_FIELDS.map(
    (field) =>
      `${field}: ${provenance.origins[field]
        .map((origin) => (origin ?? "not recorded").replaceAll("_", " "))
        .join(", ")}`,
  ).join(" · ");
}
