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
/** Elapsed time: seconds below a minute, then minutes and seconds, then hours and minutes. */
export function duration(value: number | null | undefined): string {
  if (value == null || !Number.isFinite(value) || value < 0) return UNAVAILABLE;
  if (value < 60) return seconds(value);
  const total = Math.floor(value);
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  return hours ? `${hours}h ${minutes}m` : `${minutes}m ${String(total % 60)}s`;
}
/** A recorded fraction (0..1) as a fixed-precision percentage. */
export const percent = (value: number | null | undefined, digits = 1) =>
  value == null ? UNAVAILABLE : `${(value * 100).toFixed(digits)}%`;

/**
 * Lines in recorded output as a reader counts them: a final line break ends the last line
 * rather than starting an empty one, so "a\nb\n" is two lines. CRLF counts as one break.
 */
export function lineCount(text: string): number {
  if (!text) return 0;
  const breaks = text.match(/\r\n|\r|\n/g)?.length ?? 0;
  return /[\r\n]$/.test(text) ? breaks : breaks + 1;
}

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
