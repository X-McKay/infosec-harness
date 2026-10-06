/**
 * Keyboard shortcuts shared by the list and detail views. Shortcuts never fire while the user
 * types in a field or holds a modifier, so they never swallow text input or browser shortcuts.
 */

/** True when a key event should be left to the focused control or the browser. */
export function typingTarget(
  event: Pick<KeyboardEvent, "metaKey" | "ctrlKey" | "altKey">,
  target: { closest?: (selector: string) => unknown } | null,
): boolean {
  if (event.metaKey || event.ctrlKey || event.altKey) return true;
  return !!target?.closest?.("input, textarea, select, [contenteditable]");
}

/**
 * The row to focus for a list key, or null when the key does not move. `current` is the index
 * of the focused row, or -1 when no row has focus: then j and k enter the list at its first or
 * last row, while the arrow keys are left to scroll the page.
 */
export function nextRowIndex(
  key: string,
  current: number,
  count: number,
): number | null {
  if (count <= 0) return null;
  const outside = current < 0;
  switch (key) {
    case "j":
      return outside ? 0 : Math.min(current + 1, count - 1);
    case "k":
      return outside ? count - 1 : Math.max(current - 1, 0);
    case "ArrowDown":
      return outside ? null : Math.min(current + 1, count - 1);
    case "ArrowUp":
      return outside ? null : Math.max(current - 1, 0);
    case "Home":
      return outside ? null : 0;
    case "End":
      return outside ? null : count - 1;
    default:
      return null;
  }
}
