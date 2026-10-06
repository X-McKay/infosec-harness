function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Render a comment into HTML.
export function renderComment(text: string): string {
  return "<div class='comment'>" + escapeHtml(text) + "</div>";
}
