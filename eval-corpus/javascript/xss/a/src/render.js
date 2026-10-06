// Render a comment into HTML. VULNERABLE: no output encoding.
function renderComment(text) {
  return "<div class='comment'>" + text + "</div>";
}

module.exports = { renderComment };
