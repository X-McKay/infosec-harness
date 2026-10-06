/**
 * Pure interpretation of cohort reports. Each helper mirrors how `evals/cohort.py` computes
 * the recorded value, so the UI never derives a more favourable reading than the harness:
 * absent evidence stays `not_checked` or `null`, never passed or zero.
 */
import { integer, percent } from "./format.ts";
import type {
  CapacityPreflight,
  CohortCase,
  CohortReport,
  GateStatus,
} from "./reports.ts";

export type GateRow = {
  key: string;
  label: string;
  status: GateStatus;
  detail: string;
};

const GATE_ORDER = ["complete_corpus", "task_success_rate", "unsafe_negatives"];
const GATE_LABELS: Record<string, string> = {
  complete_corpus: "Complete corpus",
  task_success_rate: "Task success rate",
  unsafe_negatives: "Unsafe negatives",
};
const humanize = (key: string) =>
  key.replaceAll("_", " ").replace(/^./, (first) => first.toUpperCase());

/**
 * The three release gates in policy order, then any additional recorded gate. A gate absent
 * from the report is `not_checked`. The detail states the measurement against the policy.
 */
export function gateRows(report: CohortReport): GateRow[] {
  const keys = [
    ...GATE_ORDER,
    ...Object.keys(report.gates).filter((key) => !GATE_ORDER.includes(key)),
  ];
  const success = successFraction(report);
  const minimum =
    report.release_policy.minimum_task_success_rate ?? report.threshold;
  const maximum = report.release_policy.maximum_unsafe_negatives;
  const unsafe = report.unsafe_negatives ?? unsafeNegativeCount(report.cases);
  const diagnostic =
    report.kind === "diagnostic"
      ? " A diagnostic subset never qualifies; its gates stay not_checked."
      : "";
  return keys.map((key) => {
    const status = report.gates[key] ?? "not_checked";
    let detail = "";
    if (key === "complete_corpus")
      detail = `${integer(success.completed)} of ${integer(success.planned)} planned cases completed.`;
    else if (key === "task_success_rate")
      detail = `${success.correct} / ${success.planned} correct (${percent(success.rate)}); policy minimum ${percent(minimum)}.`;
    else if (key === "unsafe_negatives")
      detail = `${integer(unsafe)} recorded; policy maximum ${integer(maximum)}.`;
    if (status === "not_checked")
      detail += ` Not evaluated: ${
        report.status === "running"
          ? "the cohort is still running."
          : "gates are evaluated only over the complete corpus."
      }${diagnostic}`;
    return {
      key,
      label: GATE_LABELS[key] ?? humanize(key),
      status,
      detail: detail.trim(),
    };
  });
}

export type SuccessFraction = {
  correct: number;
  completed: number;
  planned: number;
  rate: number | null;
};

/**
 * Correct cases over planned cases, as `cohort.py` computes `task_success_rate`: an unstarted
 * or failed case counts against the rate rather than leaving the denominator.
 */
export function successFraction(report: CohortReport): SuccessFraction {
  const planned = report.planned ?? report.cases.length;
  const completed =
    report.completed ??
    report.cases.filter((item) => item.status === "completed").length;
  const correct = report.cases.filter(
    (item) => caseOutcome(item).correct,
  ).length;
  return {
    correct,
    completed,
    planned,
    rate: report.task_success_rate ?? (planned ? correct / planned : null),
  };
}

/** A vulnerable case predicted not exploitable: the error the policy forbids. */
export const isUnsafeNegative = (item: CohortCase) =>
  item.expected === "potentially_exploitable" &&
  item.predicted === "likely_not_exploitable";

export const unsafeNegativeCount = (cases: CohortCase[]) =>
  cases.filter(isUnsafeNegative).length;

export type Outcome =
  | "correct_positive"
  | "correct_negative"
  | "unsafe_negative"
  | "false_positive"
  | "inconclusive"
  | "error"
  | "not_run";

export const OUTCOME_LABELS: Record<Outcome, string> = {
  correct_positive: "Correct positive",
  correct_negative: "Correct negative",
  unsafe_negative: "Unsafe negative",
  false_positive: "False positive",
  inconclusive: "Inconclusive",
  error: "Error",
  not_run: "Not run",
};

/**
 * Outcome by expected label. A correct negative (fixed case judged not exploitable) is kept
 * apart from an inconclusive answer, which is never correct for this corpus.
 */
export function caseOutcome(item: CohortCase): {
  outcome: Outcome;
  correct: boolean;
} {
  if (item.status === "failed") return { outcome: "error", correct: false };
  if (item.status !== "completed" || !item.predicted || !item.expected)
    return { outcome: "not_run", correct: false };
  if (item.predicted === "inconclusive")
    return { outcome: "inconclusive", correct: false };
  if (item.predicted === item.expected)
    return {
      outcome:
        item.expected === "potentially_exploitable"
          ? "correct_positive"
          : "correct_negative",
      correct: true,
    };
  return {
    outcome: isUnsafeNegative(item) ? "unsafe_negative" : "false_positive",
    correct: false,
  };
}

export type CaseMetrics = {
  duration: number | null;
  requests: number | null;
  toolCalls: number | null;
  inputTokens: number | null;
  outputTokens: number | null;
  tokens: number | null;
  nativeCompleted: number | null;
  nativeUnknown: number | null;
  nativeOps: number | null;
};

/**
 * Per-case measurements. Native operations count only when the receipts were `observed`;
 * a `not_checked` observation is unknown, never zero. Unknown intents are included in the
 * total because they may have reached native dispatch.
 */
export function caseMetrics(item: CohortCase): CaseMetrics {
  const usage = item.usage;
  const input = usage.input_tokens ?? null;
  const output = usage.output_tokens ?? null;
  const tokens =
    usage.total_tokens ??
    (input != null && output != null ? input + output : null);
  const native =
    item.native_operations?.status === "observed"
      ? item.native_operations.total
      : null;
  return {
    duration: item.duration_seconds,
    requests: usage.requests ?? null,
    toolCalls: usage.tool_calls ?? null,
    inputTokens: input,
    outputTokens: output,
    tokens,
    nativeCompleted: native?.completed ?? null,
    nativeUnknown: native?.unknown ?? null,
    nativeOps: native ? native.completed + native.unknown : null,
  };
}

/** Finite values of one measurement across cases; missing measurements are left out. */
export function measured(
  cases: CohortCase[],
  key: keyof CaseMetrics,
): number[] {
  return cases
    .map((item) => caseMetrics(item)[key])
    .filter((value): value is number => value != null);
}

/** Nearest-rank percentile (the smallest value with at least q of the sample at or below). */
export function percentile(values: number[], quantile: number): number | null {
  if (!values.length) return null;
  const ordered = [...values].sort((a, b) => a - b);
  const rank = Math.ceil(ordered.length * quantile);
  return ordered[Math.min(ordered.length, Math.max(1, rank)) - 1];
}

export const sum = (values: number[]) =>
  values.reduce((total, value) => total + value, 0);

export type Bin = { lower: number; upper: number; count: number };

/** Equal-width bins over [min, max]; the final bin includes its upper edge. */
export function histogram(values: number[], bins = 10): Bin[] {
  if (!values.length) return [];
  const low = Math.min(...values);
  const high = Math.max(...values);
  if (low === high) return [{ lower: low, upper: high, count: values.length }];
  const width = (high - low) / bins;
  const result = Array.from({ length: bins }, (_, index) => ({
    lower: low + index * width,
    upper: index === bins - 1 ? high : low + (index + 1) * width,
    count: 0,
  }));
  for (const value of values)
    result[Math.min(bins - 1, Math.floor((value - low) / width))].count++;
  return result;
}

const LANGUAGES = new Set([
  "c",
  "cpp",
  "csharp",
  "go",
  "java",
  "javascript",
  "kotlin",
  "perl",
  "php",
  "python",
  "ruby",
  "rust",
  "typescript",
]);

export type CaseName = {
  language: string;
  topic: string;
  variant: "vulnerable" | "fixed" | null;
  pair: string;
};

/**
 * `<language->?<cwe-topic>-(vulnerable|fixed)`; no language prefix means Python. A case
 * without a variant suffix (e.g. `unreachable`) stands alone as its own topic.
 */
export function parseCaseName(name: string): CaseName {
  const match = /^(.*)-(vulnerable|fixed)$/.exec(name);
  const pair = match ? match[1] : name;
  const variant = match ? (match[2] as "vulnerable" | "fixed") : null;
  const [first, ...rest] = pair.split("-");
  const prefixed = rest.length > 0 && LANGUAGES.has(first);
  return {
    language: prefixed ? first : "python",
    topic: prefixed ? rest.join("-") : pair,
    variant,
    pair,
  };
}

export type Breakdown = {
  key: string;
  planned: number;
  completed: number;
  correct: number;
  correctNegatives: number;
  unsafeNegatives: number;
  inconclusive: number;
  errors: number;
  rate: number | null;
};

/** Pass rate per language or per CWE topic, over planned cases like the cohort rate. */
export function breakdown(
  cases: CohortCase[],
  by: "language" | "topic",
): Breakdown[] {
  const groups = new Map<string, Breakdown>();
  for (const item of cases) {
    const key = parseCaseName(item.name)[by];
    const row = groups.get(key) ?? {
      key,
      planned: 0,
      completed: 0,
      correct: 0,
      correctNegatives: 0,
      unsafeNegatives: 0,
      inconclusive: 0,
      errors: 0,
      rate: null,
    };
    const { outcome, correct } = caseOutcome(item);
    row.planned++;
    if (item.status === "completed") row.completed++;
    if (correct) row.correct++;
    if (outcome === "correct_negative") row.correctNegatives++;
    if (outcome === "unsafe_negative") row.unsafeNegatives++;
    if (outcome === "inconclusive") row.inconclusive++;
    if (outcome === "error") row.errors++;
    groups.set(key, row);
  }
  return [...groups.values()]
    .map((row) => ({ ...row, rate: row.correct / row.planned }))
    .sort((a, b) => a.key.localeCompare(b.key));
}

export type PairRow = {
  pair: string;
  language: string;
  topic: string;
  vulnerable: CohortCase | null;
  fixed: CohortCase | null;
  /** Both halves correct: the finding is detected and its fix is recognised. */
  bothCorrect: boolean;
};

/** Vulnerable/fixed cases side by side; unpaired cases keep their own row. */
export function pairRows(cases: CohortCase[]): PairRow[] {
  const rows = new Map<string, PairRow>();
  const single: PairRow[] = [];
  for (const item of cases) {
    const name = parseCaseName(item.name);
    const base = {
      pair: name.pair,
      language: name.language,
      topic: name.topic,
      vulnerable: null,
      fixed: null,
      bothCorrect: false,
    };
    if (!name.variant) {
      // An unpaired case is placed by its expected label.
      single.push({
        ...base,
        [item.expected === "potentially_exploitable" ? "vulnerable" : "fixed"]:
          item,
      });
      continue;
    }
    const row = rows.get(name.pair) ?? base;
    row[name.variant] = item;
    rows.set(name.pair, row);
  }
  return [...rows.values(), ...single].map((row) => ({
    ...row,
    bothCorrect:
      !!row.vulnerable &&
      !!row.fixed &&
      caseOutcome(row.vulnerable).correct &&
      caseOutcome(row.fixed).correct,
  }));
}

// Mirrors `AGENT_FAILURES` and the markers `agent_level` scans for in evals/cohort.py.
const AGENT_FAILURES = new Set([
  "UsageLimitExceeded",
  "UnexpectedModelBehavior",
  "ModelExecutorError",
]);
const NATIVE_TYPES = new Set([
  "OpenShellError",
  "ExecutionUnknown",
  "UnsafeSnapshotMetadata",
]);
const NATIVE_MARKERS = ["cleanup", "executionunknown", "openshellerror"];

export type FailureClass =
  | "agent_model"
  | "native_dispatch"
  | "timeout"
  | "cancelled"
  | "identity"
  | "other";

export const FAILURE_LABELS: Record<FailureClass, string> = {
  agent_model: "Agent / model",
  native_dispatch: "Native dispatch or cleanup",
  timeout: "Timeout",
  cancelled: "Cancelled",
  identity: "Identity mismatch",
  other: "Other",
};

/**
 * Classifies a failed case by its recorded error type and cause chain. Native/unknown
 * dispatch wins over everything: it is the class that leaves external work uncertain.
 */
export function failureClass(item: CohortCase): FailureClass | null {
  if (item.status !== "failed" && !item.error_type) return null;
  const chain = item.failure_chain;
  const types = [item.error_type ?? "", ...chain.map((link) => link.type)];
  const words = chain.map((link) => link.message.toLowerCase()).join(" ");
  if (
    types.some((type) => NATIVE_TYPES.has(type)) ||
    NATIVE_MARKERS.some((marker) => words.includes(marker))
  )
    return "native_dispatch";
  if (types.some((type) => type === "TimeoutError")) return "timeout";
  if (types.some((type) => type === "CancelledError")) return "cancelled";
  if (words.includes("worker/model identity")) return "identity";
  if (
    chain.length > 1 &&
    chain.slice(1).every((link) => AGENT_FAILURES.has(link.type))
  )
    return "agent_model";
  if (types.some((type) => AGENT_FAILURES.has(type))) return "agent_model";
  return "other";
}

export function failureSummary(
  cases: CohortCase[],
): { kind: FailureClass; count: number; errorTypes: string[] }[] {
  const groups = new Map<FailureClass, Set<string>>();
  const counts = new Map<FailureClass, number>();
  for (const item of cases) {
    const kind = failureClass(item);
    if (!kind) continue;
    counts.set(kind, (counts.get(kind) ?? 0) + 1);
    const types = groups.get(kind) ?? new Set<string>();
    types.add(item.error_type ?? "Unknown");
    groups.set(kind, types);
  }
  return [...counts.entries()]
    .map(([kind, count]) => ({
      kind,
      count,
      errorTypes: [...(groups.get(kind) ?? [])].sort(),
    }))
    .sort((a, b) => b.count - a.count || a.kind.localeCompare(b.kind));
}

export type Headroom = {
  status: GateStatus;
  retained: number | null;
  quota: number | null;
  headroom: number | null;
  required: number | null;
  /** Fraction of the quota already retained when observed. */
  utilization: number | null;
  /** Headroom left after the planned cases' ceiling, when both are known. */
  margin: number | null;
  summary: string;
};

/** Plain reading of the capacity pre-flight; an unobserved ledger is never "sufficient". */
export function headroomSummary(
  budget: CapacityPreflight | null | undefined,
): Headroom {
  if (!budget)
    return {
      status: "not_checked",
      retained: null,
      quota: null,
      headroom: null,
      required: null,
      utilization: null,
      margin: null,
      summary: "No capacity pre-flight was recorded in this report.",
    };
  const { retained, quota, required_headroom: required } = budget;
  const headroom =
    budget.headroom ??
    (retained != null && quota != null ? quota - retained : null);
  const margin =
    headroom != null && required != null ? headroom - required : null;
  const observed = `${integer(retained)} of ${integer(quota)} admissions retained; ${integer(headroom)} free against ${integer(required)} required`;
  const summary =
    budget.status === "passed"
      ? `${observed}. Sufficient for the planned cases at one observation.`
      : budget.status === "failed"
        ? retained != null
          ? `${observed}. Insufficient: no case was started.`
          : `${budget.reason ?? "The occupancy observation failed"}${budget.error_type ? ` (${budget.error_type})` : ""}. No case was started.`
        : `Not checked: ${budget.reason ?? "no read-only occupancy observation was recorded"}.`;
  return {
    status: budget.status,
    retained,
    quota,
    headroom,
    required,
    utilization: retained != null && quota ? retained / quota : null,
    margin,
    summary,
  };
}

export type CaseSortKey =
  | "name"
  | "expected"
  | "predicted"
  | "outcome"
  | "status"
  | "duration"
  | "requests"
  | "toolCalls"
  | "tokens"
  | "nativeOps"
  | "error";

/** Stable sort; a missing measurement sorts last in either direction. */
export function sortCases(
  cases: CohortCase[],
  key: CaseSortKey,
  descending = false,
): CohortCase[] {
  const value = (item: CohortCase): string | number | null => {
    switch (key) {
      case "name":
        return item.name;
      case "expected":
        return item.expected;
      case "predicted":
        return item.predicted;
      case "outcome":
        return caseOutcome(item).outcome;
      case "status":
        return item.status;
      case "error":
        return item.error_type;
      default:
        return caseMetrics(item)[key];
    }
  };
  return cases
    .map((item, index) => ({ item, index, value: value(item) }))
    .sort((a, b) => {
      if (a.value == null || b.value == null)
        return a.value == null && b.value == null
          ? a.index - b.index
          : a.value == null
            ? 1
            : -1;
      const order =
        typeof a.value === "number" && typeof b.value === "number"
          ? a.value - b.value
          : String(a.value).localeCompare(String(b.value));
      return (descending ? -order : order) || a.index - b.index;
    })
    .map((entry) => entry.item);
}
