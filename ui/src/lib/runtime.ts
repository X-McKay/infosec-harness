/** Presentation only: configured identity is never measured execution evidence. */
export type Measurement = {
  status: "not_checked" | "passed" | "failed";
  checked_at?: string | null;
  detail: string;
};

export function brokerPresentation(broker: {
  configured: boolean;
  status: string;
  stale: boolean;
  unresolved_requests?: number | null;
}) {
  return {
    label: broker.configured
      ? broker.status.replaceAll("_", " ")
      : "Not enabled",
    stale: broker.configured && broker.stale,
    unresolved: broker.configured ? (broker.unresolved_requests ?? null) : null,
  };
}

export function modelNames(names: string[] | undefined) {
  return names?.length
    ? names.join(", ")
    : "Configured model names unavailable";
}

export function connectivityPresentation(measurement: Measurement | undefined) {
  if (!measurement || !measurement.checked_at) {
    return {
      status: "not_checked" as const,
      label: "Not checked",
      checkedAt: null,
      detail:
        measurement?.detail ||
        "No measured model connectivity observation is available.",
    };
  }
  return {
    status: measurement.status,
    label: measurement.status.replaceAll("_", " "),
    checkedAt: measurement.checked_at,
    detail: measurement.detail,
  };
}

export function componentTitle(status: string) {
  return status === "passed"
    ? "Component evidence passed"
    : "Component evidence";
}
