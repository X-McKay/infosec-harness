/**
 * Execution evidence basis, derived from the origins recorded with each probe execution.
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

export function executionProvenance(
  executions: readonly unknown[],
): ExecutionProvenance | null {
  if (!executions.length) return null;
  const seen: Record<ProvenanceField, Set<string | null>> = {
    observations: new Set(),
    process: new Set(),
    runner: new Set(),
  };
  for (const execution of executions) {
    const record = isRecord(execution) ? execution : {};
    for (const field of PROVENANCE_FIELDS) {
      const section = record[field];
      seen[field].add(isRecord(section) ? text(section.origin) : null);
    }
  }
  const origins = {
    observations: [...seen.observations],
    process: [...seen.process],
    runner: [...seen.runner],
  };
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
