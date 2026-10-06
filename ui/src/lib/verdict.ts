import type { components } from "../api/schema";

export type VerdictLabel = components["schemas"]["Verdict"]["label"];

export const VERDICT_LABELS = [
  "potentially_exploitable",
  "inconclusive",
  "likely_not_exploitable",
] as const satisfies readonly VerdictLabel[];

export function isVerdictLabel(value: unknown): value is VerdictLabel {
  return (VERDICT_LABELS as readonly unknown[]).includes(value);
}

export function verdictVariant(
  v: string | null | undefined,
): "exploitable" | "safe" | "inconclusive" | "outline" {
  if (v === "potentially_exploitable") return "exploitable";
  if (v === "likely_not_exploitable") return "safe";
  if (v === "inconclusive") return "inconclusive";
  return "outline";
}
export const verdictLabel = (v: string | null | undefined) =>
  v ? v.replace(/_/g, " ") : "No verdict";

/**
 * What a label means under the harness admission rule (contracts.definitive_support, applied
 * again when the workflow finalizes): a definitive label needs source citations and a cited,
 * complete, source-verified probe whose self-reported observation matches it, with no
 * contrary probe. Otherwise the workflow downgrades the proposal to inconclusive.
 */
export function verdictMeaning(v: string | null | undefined): string {
  if (v === "potentially_exploitable")
    return "Admitted with source citations and a cited, complete, source-verified probe whose self-reported observations show the vulnerability, with no unreconciled contrary probe.";
  if (v === "likely_not_exploitable")
    return "Admitted with source citations and a cited, complete, source-verified probe whose self-reported observations do not show the vulnerability, with no unreconciled contrary probe.";
  if (v === "inconclusive")
    return "The evidence did not meet the rule for a definitive verdict, or the investigator did not propose one. The limitations say what was not established.";
  return "No verdict has been reported for this investigation.";
}
