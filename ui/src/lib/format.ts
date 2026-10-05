/** Every formatter renders a missing measurement as "Unavailable"; callers need no guard. */
const UNAVAILABLE = "Unavailable";

export function number(value: number | null | undefined, digits = 1): string {
  return value == null
    ? UNAVAILABLE
    : new Intl.NumberFormat(undefined, {
        maximumFractionDigits: digits,
      }).format(value);
}
export const integer = (value: number | null | undefined) => number(value, 0);
export const money = (value: number | null | undefined) =>
  value == null ? UNAVAILABLE : `$${number(value, 4)}`;
export const seconds = (value: number | null | undefined) =>
  value == null
    ? UNAVAILABLE
    : value > 0 && value < 1
      ? `${number(value * 1000)}ms`
      : `${number(value)}s`;
/** A recorded fraction (0..1) as a fixed-precision percentage. */
export const percent = (value: number | null | undefined, digits = 1) =>
  value == null ? UNAVAILABLE : `${(value * 100).toFixed(digits)}%`;

/** Missing or malformed recorded times never render as Invalid Date. */
export function timestamp(
  value: string | number | null | undefined,
  style: "dateTime" | "time" = "dateTime",
): string {
  if (value == null || value === "") return UNAVAILABLE;
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return UNAVAILABLE;
  return style === "time" ? date.toLocaleTimeString() : date.toLocaleString();
}
