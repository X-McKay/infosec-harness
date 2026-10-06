/**
 * Presentation of recorded probe observations (contracts.Evidence.observations).
 *
 * The five probe claims are parsed from the probe's own final `HARNESS_PROBE` stdout line
 * and tagged `origin: "self_reported"` (agents/evidence.py); they are claims, not oracles.
 * `source_verified` and `workspace_digest` come from the OpenShell receipt, and
 * `report_excerpted` from report bounding (contracts.Evidence.excerpt). Fails closed: a
 * missing or non-boolean claim is "not recorded", never true.
 */
import type { components } from "../api/schema";
import { text } from "./json.ts";

type Evidence = components["schemas"]["Evidence"];
type Observations = NonNullable<Evidence["observations"]>;

export const PREREQUISITES = [
  "target_reached",
  "oracle_valid",
  "positive_control",
  "negative_control",
] as const;
export const PROBE_CLAIMS = [
  ...PREREQUISITES,
  "vulnerability_observed",
] as const;
export type ProbeClaim = (typeof PROBE_CLAIMS)[number];
const CLAIM_LABELS: Record<ProbeClaim, string> = {
  target_reached: "Target reached",
  oracle_valid: "Oracle valid",
  positive_control: "Positive control",
  negative_control: "Negative control",
  vulnerability_observed: "Vulnerability observed",
};
/** Observation keys this module presents explicitly; anything else is listed as recorded. */
const PRESENTED = new Set<string>([
  ...PROBE_CLAIMS,
  "origin",
  "source_verified",
  "workspace_digest",
  "report_excerpted",
]);

const observationsOf = (evidence: Pick<Evidence, "observations">) =>
  (evidence.observations ?? {}) as Observations;
const recordedBoolean = (value: unknown): boolean | null =>
  typeof value === "boolean" ? value : null;

export type ClaimRow = {
  key: ProbeClaim;
  label: string;
  /** null when the claim was not recorded or was not a boolean. */
  value: boolean | null;
};
export function probeClaims(
  evidence: Pick<Evidence, "observations">,
): ClaimRow[] {
  const observations = observationsOf(evidence);
  return PROBE_CLAIMS.map((key) => ({
    key,
    label: CLAIM_LABELS[key],
    value: recordedBoolean(observations[key]),
  }));
}
export function claimOrigin(
  evidence: Pick<Evidence, "observations">,
): string | null {
  return text(observationsOf(evidence).origin);
}
export function sourceVerified(
  evidence: Pick<Evidence, "observations">,
): boolean | null {
  return recordedBoolean(observationsOf(evidence).source_verified);
}
export function workspaceDigest(
  evidence: Pick<Evidence, "observations">,
): string | null {
  return text(observationsOf(evidence).workspace_digest);
}
export function reportExcerpted(
  evidence: Pick<Evidence, "observations">,
): boolean {
  return observationsOf(evidence).report_excerpted === true;
}
/** Other recorded observations (for example integrity or timeout feedback), as text. */
export function otherObservations(
  evidence: Pick<Evidence, "observations">,
): [string, string][] {
  return Object.entries(observationsOf(evidence))
    .filter(([key]) => !PRESENTED.has(key))
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => [key, value === null ? "null" : String(value)]);
}
export const recordedValue = (value: boolean | null) =>
  value == null ? "not recorded" : String(value);

/**
 * Why the recorded values do not form a complete, source-verified probe, in the order of
 * contracts.Evidence.complete_verified_probe. An empty list means the recorded values meet
 * it; it does not make the self-reported claims true.
 */
export function probeGaps(
  evidence: Pick<
    Evidence,
    "kind" | "exit_code" | "timed_out" | "output_truncated" | "observations"
  >,
): string[] {
  if (evidence.kind !== "probe") return ["not a probe"];
  const observations = observationsOf(evidence);
  const gaps: string[] = [];
  if (evidence.exit_code !== 0)
    gaps.push(
      evidence.exit_code == null
        ? "no exit code recorded"
        : `exit code ${evidence.exit_code}`,
    );
  if (evidence.timed_out) gaps.push("timed out");
  if (evidence.output_truncated) gaps.push("output truncated");
  if (!workspaceDigest(evidence)) gaps.push("no workspace digest");
  if (observations.source_verified !== true) gaps.push("not source-verified");
  for (const key of PREREQUISITES)
    if (observations[key] !== true)
      gaps.push(`${CLAIM_LABELS[key].toLowerCase()} not true`);
  if (recordedBoolean(observations.vulnerability_observed) == null)
    gaps.push("vulnerability observation not recorded");
  return gaps;
}

/** The final stdout line when it carries the probe prefix (agents/evidence.final_probe_line). */
export function finalProbeLine(stdout: string): string | null {
  const lines = stdout.replace(/[\r\n]+$/, "").split(/\r\n|\r|\n/);
  const last = lines.at(-1) ?? "";
  return last.startsWith("HARNESS_PROBE ") ? last : null;
}

export type EvidenceBasis = {
  probes: number;
  /** Distinct recorded claim origins across probes; null means none was recorded. */
  origins: (string | null)[];
};
/** Basis notice for the report's probes; null when the report contains no probe. */
export function evidenceBasis(
  evidence: readonly Evidence[],
): EvidenceBasis | null {
  const probes = evidence.filter((item) => item.kind === "probe");
  if (!probes.length) return null;
  return {
    probes: probes.length,
    origins: [...new Set(probes.map(claimOrigin))],
  };
}
export function originSummary(basis: EvidenceBasis): string {
  return basis.origins
    .map((origin) => (origin ?? "not recorded").replaceAll("_", " "))
    .join(", ");
}
