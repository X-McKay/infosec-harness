/**
 * Report documents written by `harness eval`, `harness qualify` and `harness replay`, as served
 * by `GET /api/reports` and `GET /api/reports/{name}`.
 *
 * Hand-typed until the API schema is regenerated; the integrator maps these to generated
 * `components["schemas"]` names. Every parser tolerates absent or malformed fields: a missing
 * measurement stays `null` (rendered "Unavailable") and a missing gate stays `not_checked`.
 * Every string here is untrusted report content and is rendered only as React text.
 */
import { asRecord, isRecord, numeric, text, type JsonRecord } from "./json.ts";

export type ReportKind =
  | "model"
  | "diagnostic"
  | "openshell"
  | "replay"
  | "unknown";
export const REPORT_KINDS: ReportKind[] = [
  "model",
  "diagnostic",
  "openshell",
  "replay",
  "unknown",
];

/** One row of `GET /api/reports` (newest first). */
export type ReportSummary = {
  name: string;
  kind: ReportKind;
  status: string | null;
  started_at: string | null;
  finished_at: string | null;
  commit: string | null;
  model: string | null;
  planned: number | null;
  completed: number | null;
  task_success_rate: number | null;
  unsafe_negatives: number | null;
  gates: Record<string, GateStatus>;
  bytes: number | null;
};

/** Release gates have exactly three states; anything else is missing evidence. */
export type GateStatus = "passed" | "failed" | "not_checked";
export type Verdict =
  | "potentially_exploitable"
  | "likely_not_exploitable"
  | "inconclusive";
export type CaseStatus = "unstarted" | "starting" | "completed" | "failed";
export type OperationCount = { completed: number; unknown: number };

export type NativeOperations = {
  status: string;
  categories: Record<string, OperationCount>;
  total: OperationCount | null;
  limitations: string[];
};

export type FailureLink = { type: string; message: string };

export type ReceiptSummary = {
  status: string;
  count: number | null;
  error_type: string | null;
  items: {
    operation_id: string;
    exit_code: number | null;
    output_truncated: boolean;
  }[];
};

export type WorkerIdentity = {
  fingerprint: string | null;
  code_sha256: string | null;
  config_sha256: string | null;
  dependencies: Record<string, string>;
};

export type CohortCase = {
  name: string;
  expected: Verdict | null;
  status: CaseStatus | "unknown";
  workflow_id: string | null;
  started_at: string | null;
  finished_at: string | null;
  duration_seconds: number | null;
  predicted: Verdict | null;
  passed: boolean | null;
  source_digest: string | null;
  usage: Record<string, number>;
  limitations: string[];
  worker_identity: WorkerIdentity | null;
  error_type: string | null;
  failure_chain: FailureLink[];
  cancellation: string | null;
  receipts: ReceiptSummary | null;
  native_operations: NativeOperations | null;
};

export type CapacityPreflight = {
  status: GateStatus;
  planned_cases: number | null;
  per_case_ceiling: number | null;
  required_headroom: number | null;
  retained: number | null;
  quota: number | null;
  headroom: number | null;
  observed_at_ms: number | null;
  reason: string | null;
  error_type: string | null;
  source: string | null;
  limitations: string[];
};

export type OperationEstimate = {
  status: string;
  completed_case_samples: number | null;
  planned_cases: number | null;
  observed_totals: OperationCount | null;
  observed_attempt_range_per_case: [number, number] | null;
  estimated_cohort_attempt_range: [number, number] | null;
  unobserved_cases: number | null;
  limitations: string[];
};

export type Limits = {
  max_requests: number | null;
  max_tool_calls: number | null;
  total_tokens: number | null;
  timeout_seconds: number | null;
  command_timeout_seconds: number | null;
};

/** A `harness eval` report: the full corpus (`cohort`) or a `--case` subset (`diagnostic`). */
export type CohortReport = {
  version: number | null;
  kind: "cohort" | "diagnostic" | "unknown";
  commit: string | null;
  generation: string | null;
  model: string | null;
  task_queue: string | null;
  owned_worker: boolean | null;
  worker_identity: WorkerIdentity | null;
  dataset_sha256: string | null;
  runtime_config_sha256: string | null;
  limits: Limits;
  native_operation_budget: CapacityPreflight | null;
  started_at: string | null;
  finished_at: string | null;
  status: string | null;
  error_type: string | null;
  gates: Record<string, GateStatus>;
  threshold: number | null;
  release_policy: {
    minimum_task_success_rate: number | null;
    maximum_unsafe_negatives: number | null;
  };
  release_policy_sha256: string | null;
  completed: number | null;
  planned: number | null;
  task_success_rate: number | null;
  unsafe_negatives: number | null;
  native_operation_estimate: OperationEstimate | null;
  cases: CohortCase[];
};

export type QualificationProfile = {
  name: string;
  checks: Record<string, string>;
};

/** A `harness qualify` report (`openshell-*.json`): native boundaries, no model calls. */
export type QualificationReport = {
  version: number | null;
  status: string | null;
  run_id: string | null;
  config_sha256: string | null;
  model_calls: number | null;
  model_quality: string | null;
  cleanup: string | null;
  error_type: string | null;
  cleanup_error_type: string | null;
  profiles: QualificationProfile[];
};

export type ReplayHistory = {
  workflow_id: string | null;
  status: string | null;
  history_events: number | null;
  history_sha256: string | null;
  verdict: string | null;
  failure_chain: FailureLink[];
};

/** A `harness replay` report: one (or, tolerated, several) zero-dispatch history replays. */
export type ReplayReport = {
  status: string | null;
  histories: ReplayHistory[];
};

export type ReportDocument =
  | { shape: "cohort"; report: CohortReport }
  | { shape: "qualification"; report: QualificationReport }
  | { shape: "replay"; report: ReplayReport }
  | { shape: "unknown"; report: unknown };

const REPORT_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*\.json$/;
const WORKFLOW_ID = /^investigate-v[0-9]+-[a-z0-9-]+$/;

/** Only a validated name becomes part of a URL or route. */
export const isReportName = (value: unknown): value is string =>
  typeof value === "string" && value.length <= 255 && REPORT_NAME.test(value);
export const isWorkflowId = (value: unknown): value is string =>
  typeof value === "string" && value.length <= 200 && WORKFLOW_ID.test(value);

export const reportPath = (name: string) =>
  isReportName(name) ? `/reports/${encodeURIComponent(name)}` : null;
export const runPath = (workflowId: string | null | undefined) =>
  isWorkflowId(workflowId) ? `/runs/${workflowId}` : null;
export const reportApiPath = (name: string) =>
  isReportName(name) ? `/api/reports/${encodeURIComponent(name)}` : null;

export const shortHash = (value: string | null | undefined, length = 12) =>
  value ? value.slice(0, length) : null;

const VERDICTS = new Set<string>([
  "potentially_exploitable",
  "likely_not_exploitable",
  "inconclusive",
]);
const CASE_STATUSES = new Set<string>([
  "unstarted",
  "starting",
  "completed",
  "failed",
]);

export const gateStatus = (value: unknown): GateStatus =>
  value === "passed" || value === "failed" ? value : "not_checked";
const verdict = (value: unknown): Verdict | null =>
  typeof value === "string" && VERDICTS.has(value) ? (value as Verdict) : null;
const bool = (value: unknown): boolean | null =>
  typeof value === "boolean" ? value : null;
const strings = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
const gates = (value: unknown): Record<string, GateStatus> =>
  Object.fromEntries(
    Object.entries(asRecord(value)).map(([key, status]) => [
      key,
      gateStatus(status),
    ]),
  );
const range = (value: unknown): [number, number] | null => {
  if (!Array.isArray(value) || value.length !== 2) return null;
  const [low, high] = value.map(numeric);
  return low != null && high != null ? [low, high] : null;
};

function count(value: unknown): OperationCount | null {
  const record = asRecord(value);
  const completed = numeric(record.completed);
  const unknown = numeric(record.unknown);
  return completed == null && unknown == null
    ? null
    : { completed: completed ?? 0, unknown: unknown ?? 0 };
}

export function parseReportSummary(value: unknown): ReportSummary | null {
  const record = asRecord(value);
  const name = text(record.name);
  if (!name) return null;
  const kind = text(record.kind);
  return {
    name,
    kind: REPORT_KINDS.includes(kind as ReportKind)
      ? (kind as ReportKind)
      : "unknown",
    status: text(record.status),
    started_at: text(record.started_at),
    finished_at: text(record.finished_at),
    commit: text(record.commit),
    model: text(record.model),
    planned: numeric(record.planned),
    completed: numeric(record.completed),
    task_success_rate: numeric(record.task_success_rate),
    unsafe_negatives: numeric(record.unsafe_negatives),
    gates: gates(record.gates),
    bytes: numeric(record.bytes),
  };
}

/** Malformed rows are dropped; the API's newest-first order is kept. */
export function parseReportSummaries(value: unknown): ReportSummary[] {
  const items = Array.isArray(value)
    ? value
    : Array.isArray(asRecord(value).items)
      ? (asRecord(value).items as unknown[])
      : [];
  return items
    .map(parseReportSummary)
    .filter((item): item is ReportSummary => item != null);
}

export function parseWorkerIdentity(value: unknown): WorkerIdentity | null {
  if (!isRecord(value)) return null;
  return {
    fingerprint: text(value.fingerprint),
    code_sha256: text(value.code_sha256),
    config_sha256: text(value.config_sha256),
    dependencies: Object.fromEntries(
      Object.entries(asRecord(value.dependencies)).filter(
        (entry): entry is [string, string] => typeof entry[1] === "string",
      ),
    ),
  };
}

export function parseFailureChain(value: unknown): FailureLink[] {
  return (Array.isArray(value) ? value : []).filter(isRecord).map((link) => ({
    type: text(link.type) ?? "Unknown",
    message: typeof link.message === "string" ? link.message : "",
  }));
}

function parseNativeOperations(value: unknown): NativeOperations | null {
  if (!isRecord(value)) return null;
  const categories: Record<string, OperationCount> = {};
  for (const [key, row] of Object.entries(asRecord(value.categories))) {
    const parsed = count(row);
    if (parsed) categories[key] = parsed;
  }
  return {
    status: text(value.status) ?? "not_checked",
    categories,
    total: count(value.total),
    limitations: strings(value.limitations),
  };
}

function parseReceipts(value: unknown): ReceiptSummary | null {
  if (!isRecord(value)) return null;
  return {
    status: text(value.status) ?? "not_checked",
    count: numeric(value.count),
    error_type: text(value.error_type),
    items: (Array.isArray(value.items) ? value.items : [])
      .filter(isRecord)
      .map((item) => ({
        operation_id: text(item.operation_id) ?? "unknown",
        exit_code: numeric(item.exit_code),
        output_truncated: item.output_truncated === true,
      })),
  };
}

export function parseCase(value: unknown): CohortCase {
  const record = asRecord(value);
  const status = text(record.status);
  const usage: Record<string, number> = {};
  for (const [key, amount] of Object.entries(asRecord(record.usage))) {
    const parsed = numeric(amount);
    if (parsed != null) usage[key] = parsed;
  }
  return {
    name: text(record.name) ?? "unnamed",
    expected: verdict(record.expected),
    status:
      status && CASE_STATUSES.has(status) ? (status as CaseStatus) : "unknown",
    workflow_id: text(record.workflow_id),
    started_at: text(record.started_at),
    finished_at: text(record.finished_at),
    duration_seconds: numeric(record.duration_seconds),
    predicted: verdict(record.predicted),
    passed: bool(record.passed),
    source_digest: text(record.source_digest),
    usage,
    limitations: strings(record.limitations),
    worker_identity: parseWorkerIdentity(record.worker_identity),
    error_type: text(record.error_type),
    failure_chain: parseFailureChain(record.failure_chain),
    cancellation: text(record.cancellation),
    receipts: parseReceipts(record.receipts),
    native_operations: parseNativeOperations(record.native_operations),
  };
}

function parseCapacity(value: unknown): CapacityPreflight | null {
  if (!isRecord(value)) return null;
  return {
    status: gateStatus(value.status),
    planned_cases: numeric(value.planned_cases),
    per_case_ceiling: numeric(value.per_case_ceiling),
    required_headroom: numeric(value.required_headroom),
    retained: numeric(value.retained),
    quota: numeric(value.quota),
    headroom: numeric(value.headroom),
    observed_at_ms: numeric(value.observed_at_ms),
    reason: text(value.reason),
    error_type: text(value.error_type),
    source: text(value.source),
    limitations: strings(value.limitations),
  };
}

function parseEstimate(value: unknown): OperationEstimate | null {
  if (!isRecord(value)) return null;
  return {
    status: text(value.status) ?? "not_checked",
    completed_case_samples: numeric(value.completed_case_samples),
    planned_cases: numeric(value.planned_cases),
    observed_totals: count(value.observed_totals),
    observed_attempt_range_per_case: range(
      value.observed_attempt_range_per_case,
    ),
    estimated_cohort_attempt_range: range(value.estimated_cohort_attempt_range),
    unobserved_cases: numeric(value.unobserved_cases),
    limitations: strings(value.limitations),
  };
}

export function parseCohortReport(value: unknown): CohortReport {
  const record = asRecord(value);
  const limits = asRecord(record.limits);
  const policy = asRecord(record.release_policy);
  const kind = text(record.kind);
  return {
    version: numeric(record.version),
    kind: kind === "cohort" || kind === "diagnostic" ? kind : "unknown",
    commit: text(record.commit),
    generation: text(record.generation),
    model: text(record.model),
    task_queue: text(record.task_queue),
    owned_worker: bool(record.owned_worker),
    worker_identity: parseWorkerIdentity(record.worker_identity),
    dataset_sha256: text(record.dataset_sha256),
    runtime_config_sha256: text(record.runtime_config_sha256),
    limits: {
      max_requests: numeric(limits.max_requests),
      max_tool_calls: numeric(limits.max_tool_calls),
      total_tokens: numeric(limits.total_tokens),
      timeout_seconds: numeric(limits.timeout_seconds),
      command_timeout_seconds: numeric(limits.command_timeout_seconds),
    },
    native_operation_budget: parseCapacity(record.native_operation_budget),
    started_at: text(record.started_at),
    finished_at: text(record.finished_at),
    status: text(record.status),
    error_type: text(record.error_type),
    gates: gates(record.gates),
    threshold: numeric(record.threshold),
    release_policy: {
      minimum_task_success_rate: numeric(policy.minimum_task_success_rate),
      maximum_unsafe_negatives: numeric(policy.maximum_unsafe_negatives),
    },
    release_policy_sha256: text(record.release_policy_sha256),
    completed: numeric(record.completed),
    planned: numeric(record.planned),
    task_success_rate: numeric(record.task_success_rate),
    unsafe_negatives: numeric(record.unsafe_negatives),
    native_operation_estimate: parseEstimate(record.native_operation_estimate),
    cases: (Array.isArray(record.cases) ? record.cases : []).map(parseCase),
  };
}

export function parseQualificationReport(value: unknown): QualificationReport {
  const record = asRecord(value);
  return {
    version: numeric(record.version),
    status: text(record.status),
    run_id: text(record.run_id),
    config_sha256: text(record.config_sha256),
    model_calls: numeric(record.model_calls),
    model_quality: text(record.model_quality),
    cleanup: text(record.cleanup),
    error_type: text(record.error_type),
    cleanup_error_type: text(record.cleanup_error_type),
    profiles: Object.entries(asRecord(record.profiles)).map(([name, row]) => ({
      name,
      checks: Object.fromEntries(
        Object.entries(asRecord(row)).map(([check, status]) => [
          check,
          typeof status === "string" ? status : "not_checked",
        ]),
      ),
    })),
  };
}

function parseReplayHistory(value: JsonRecord): ReplayHistory {
  return {
    workflow_id: text(value.workflow_id),
    status: text(value.status),
    history_events: numeric(value.history_events),
    history_sha256: text(value.history_sha256),
    verdict: text(value.verdict),
    failure_chain: parseFailureChain(value.failure_chain),
  };
}

export function parseReplayReport(value: unknown): ReplayReport {
  const record = asRecord(value);
  const histories = Array.isArray(record.histories)
    ? record.histories.filter(isRecord).map(parseReplayHistory)
    : [parseReplayHistory(record)];
  return { status: text(record.status), histories };
}

/** Classifies a document by its fields, not by its file name or self-declared kind alone. */
export function parseReportDocument(value: unknown): ReportDocument {
  if (!isRecord(value)) return { shape: "unknown", report: value };
  if (
    Array.isArray(value.cases) &&
    (value.kind === "cohort" || value.kind === "diagnostic")
  )
    return { shape: "cohort", report: parseCohortReport(value) };
  if (isRecord(value.profiles) && "model_calls" in value)
    return { shape: "qualification", report: parseQualificationReport(value) };
  if ("history_events" in value || Array.isArray(value.histories))
    return { shape: "replay", report: parseReplayReport(value) };
  return { shape: "unknown", report: value };
}
