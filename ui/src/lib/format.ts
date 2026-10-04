export function number(value: number | null | undefined, digits = 1): string {
  return value == null
    ? "Unavailable"
    : new Intl.NumberFormat(undefined, {
        maximumFractionDigits: digits,
      }).format(value);
}
export const money = (value: number | null | undefined) =>
  value == null ? "Unavailable" : `$${number(value, 4)}`;
export const seconds = (value: number | null | undefined) =>
  value == null
    ? "Unavailable"
    : value > 0 && value < 1
      ? `${number(value * 1000)}ms`
      : `${number(value)}s`;

/** Missing or malformed recorded times never render as Invalid Date. */
export function timestamp(
  value: string | number | null | undefined,
  style: "dateTime" | "time" = "dateTime",
): string {
  if (value == null || value === "") return "Unavailable";
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "Unavailable";
  return style === "time" ? date.toLocaleTimeString() : date.toLocaleString();
}
