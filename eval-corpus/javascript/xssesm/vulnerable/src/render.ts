// Render a comment into HTML. VULNERABLE: no output encoding.
export function renderComment(text: string): string {
  return "<div class='comment'>" + text + "</div>";
}
