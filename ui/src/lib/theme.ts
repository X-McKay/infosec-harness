export const THEMES = ["system", "light", "dark"] as const;
export type Theme = (typeof THEMES)[number];
export const THEME_STORAGE_KEY = "harness-theme";

/** A stored preference that is absent or unrecognized falls back to the system setting. */
export function parseTheme(value: unknown): Theme {
  return (THEMES as readonly unknown[]).includes(value)
    ? (value as Theme)
    : "system";
}
export function isDark(theme: Theme, systemDark: boolean): boolean {
  return theme === "dark" || (theme === "system" && systemDark);
}
