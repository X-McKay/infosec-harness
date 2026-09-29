import type { components } from "./schema";
export type RunSummary = {
  id: string;
  batch_id: string;
  fingerprint: string;
  title: string;
  repo_url: string;
  revision: string;
  cwe: string | null;
  severity: string;
  status: string;
  verdict: string | null;
  confidence: number | null;
  inconclusive_reason: string | null;
  priority: string | null;
  priority_score: number | null;
  environment_scope: string;
  phase: string;
  telemetry: {
    cost_usd?: number | null;
    total_tokens?: number | null;
    wall_time_s?: number | null;
    cost_coverage?: number | null;
  } | null;
  early_exit: string | null;
  cost_usd: number | null;
  total_tokens: number;
  cache_read_tokens: number;
  latency_s: number;
  created_at: string;
};
export type RunDetail = RunSummary & {
  evidence: Record<string, unknown> | null;
  events: Array<{
    id: string;
    phase: string;
    detail: string;
    created_at: string;
  }>;
  review_history: Array<{
    reviewer: string;
    decision: string;
    override_label?: string | null;
    reason: string;
    created_at: string;
  }>;
  finding: Record<string, unknown>;
  result: Record<string, unknown>;
  invocations: Array<Record<string, unknown>>;
  review: null | {
    reviewer: string;
    decision: string;
    override_label: string | null;
    reason: string;
    created_at: string;
  };
};
export type Batch = {
  id: string;
  status: string;
  label: string;
  source_kind: string;
  finding_count: number;
  created_at: string;
};

const BASE = "";

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
  });
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  return res.json() as Promise<T>;
}

export const api = {
  metrics: (population = "operational") =>
    req<components["schemas"]["MetricsResponse"]>(
      `/api/metrics?population=${population}`,
    ),
  runPage: (params: {
    batch_id?: string;
    verdict?: string;
    search?: string;
    offset?: number;
    population?: string;
    metric?: string;
    lower?: number;
    upper?: number;
    upper_inclusive?: boolean;
  }) =>
    req<{
      items: RunSummary[];
      total: number;
      offset: number;
      limit: number;
      as_of: string;
    }>(
      `/api/run-page?${new URLSearchParams(
        Object.entries(params)
          .filter(([, v]) => v !== undefined && v !== "")
          .map(([k, v]) => [k, String(v)]),
      )}`,
    ),
  experiment: (id: string) =>
    req<{
      id: string;
      agent: string;
      metrics: Record<string, unknown>;
      cases: Array<{
        case_name: string;
        repetition: number;
        passed: boolean;
        latency_s: number;
        cost_usd: number;
        scores: Record<string, unknown>;
      }>;
    }>(`/api/experiments/${id}`),
  batches: () => req<Batch[]>("/api/batches"),
  runs: (params: { batch_id?: string; verdict?: string } = {}) => {
    const q = new URLSearchParams(params as Record<string, string>).toString();
    return req<RunSummary[]>(`/api/runs${q ? `?${q}` : ""}`);
  },
  run: (id: string) => req<RunDetail>(`/api/runs/${id}`),
  submit: (body: { findings: unknown[]; label?: string; mode?: string }) =>
    req<{ batch_id: string }>("/api/batches", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  review: (
    id: string,
    body: {
      reviewer: string;
      decision: string;
      override_label?: string | null;
      reason?: string;
    },
  ) =>
    req<{ ok: boolean }>(`/api/runs/${id}/review`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  experiments: () => req<Array<Record<string, unknown>>>("/api/experiments"),
  config: () =>
    req<{
      model_mode: string;
      agents: Array<{
        name: string;
        model_tier: string;
        config_hash: string;
        resolved_model: string;
      }>;
    }>("/api/config"),
};
