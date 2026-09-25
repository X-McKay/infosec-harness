def render_comment(text: str) -> str:
    """Render a user comment into HTML. VULNERABLE: no output encoding."""
    return "<div class='comment'>" + text + "</div>"
