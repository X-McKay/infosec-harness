export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, detail: string) {
    super(`${status} ${detail}`);
    this.name = "ApiError";
    this.status = status;
  }
}
export async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
  });
  if (!res.ok) throw new ApiError(res.status, await res.text());
  return res.json() as Promise<T>;
}
