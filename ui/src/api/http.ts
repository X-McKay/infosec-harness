function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

const MAX_MESSAGE_LENGTH = 240;
const STATUS_MESSAGES: Record<number, string> = {
  400: "The request was rejected.",
  401: "Authentication is required.",
  403: "Access is not permitted.",
  404: "Not found.",
  409: "The request conflicts with the current state.",
  413: "The request is too large.",
  422: "The request did not pass validation.",
  429: "Too many requests; try again shortly.",
  502: "The API is unavailable.",
  503: "The API is unavailable.",
  504: "The API did not respond in time.",
};

/** HTTP failure; `message` is a short display string, `body` keeps the raw response. */
export class ApiError extends Error {
  readonly status: number;
  readonly body: string;
  constructor(status: number, body: string) {
    super(errorMessage(status, body));
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

/** Uses the API's JSON `detail` when present, otherwise a generic message by status. */
export function errorMessage(status: number, body: string): string {
  const message =
    responseDetail(body) ??
    STATUS_MESSAGES[status] ??
    (status >= 500 ? "The API reported an error." : "The request failed.");
  return truncate(`${status} ${message}`);
}

function responseDetail(body: string): string | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return null;
  }
  const detail = isRecord(parsed) ? parsed.detail : undefined;
  if (typeof detail === "string") return detail.trim() || null;
  if (Array.isArray(detail)) {
    // FastAPI validation errors: [{loc, msg, type}, ...]
    const messages = detail
      .map((item) => (isRecord(item) ? item.msg : undefined))
      .filter((msg): msg is string => typeof msg === "string" && !!msg);
    return messages.length ? messages.join("; ") : null;
  }
  return null;
}

function truncate(value: string): string {
  const flat = value.replace(/\s+/g, " ");
  return flat.length > MAX_MESSAGE_LENGTH
    ? `${flat.slice(0, MAX_MESSAGE_LENGTH - 1)}…`
    : flat;
}

export async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
  });
  if (!res.ok) throw new ApiError(res.status, await res.text());
  return res.json() as Promise<T>;
}
