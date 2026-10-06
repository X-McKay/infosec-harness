import html


def render_comment(text: str) -> str:
    """Render a user comment into HTML."""
    return "<div class='comment'>" + html.escape(text) + "</div>"
