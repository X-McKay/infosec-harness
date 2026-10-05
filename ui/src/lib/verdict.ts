import type { VerdictLabel } from "../api/client.ts";

export const VERDICT_LABELS = [
  "potentially_exploitable",
  "inconclusive",
  "likely_not_exploitable",
] as const satisfies readonly VerdictLabel[];

export function verdictVariant(
  v: string | null,
): "exploitable" | "safe" | "inconclusive" | "outline" {
  if (v === "potentially_exploitable") return "exploitable";
  if (v === "likely_not_exploitable") return "safe";
  if (v === "inconclusive") return "inconclusive";
  return "outline";
}
export const verdictLabel = (v: string | null) =>
  v ? v.replace(/_/g, " ") : "No verdict";
