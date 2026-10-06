function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// Render a comment into HTML. FIXED: HTML-encode untrusted text.
function renderComment(text) {
  return "<div class='comment'>" + escapeHtml(text) + "</div>";
}

module.exports = { renderComment, escapeHtml };
