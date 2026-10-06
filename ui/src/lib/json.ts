/** Narrowing helpers for recorded JSON; absent or malformed values never coerce into data. */
export type JsonRecord = Record<string, unknown>;

export function isRecord(value: unknown): value is JsonRecord {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
export const asRecord = (value: unknown): JsonRecord =>
  isRecord(value) ? value : {};
export const text = (value: unknown): string | null =>
  typeof value === "string" && value ? value : null;
export const numeric = (value: unknown): number | null =>
  typeof value === "number" && Number.isFinite(value) ? value : null;
