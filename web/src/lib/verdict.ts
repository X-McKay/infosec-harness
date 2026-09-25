export function verdictVariant(v: string | null): "exploitable" | "safe" | "inconclusive" | "outline" {
  if (v === "potentially_exploitable") return "exploitable";
  if (v === "likely_not_exploitable") return "safe";
  if (v === "inconclusive") return "inconclusive";
  return "outline";
}
export const verdictLabel = (v: string | null) => (v ? v.replace(/_/g, " ") : "pending");
export const priorityRank: Record<string, number> = { P1: 1, P2: 2, P3: 3, P4: 4 };
