import http.server
from urllib.parse import parse_qs, urlparse

# Post-login redirects only ever go back into our own single-page app.
ALLOWED_HOSTS = frozenset({"app.example.com"})


def redirect_target(next_url: str) -> str:
    """Choose the Location destination for the post-login redirect.

    FIXED: only a same-site relative path or an allowlisted host is accepted, so the
    caller cannot redirect the browser to an external origin.
    """
    parsed = urlparse(next_url)
    if not parsed.scheme and not parsed.netloc and next_url.startswith("/") and not next_url.startswith("//"):
        return next_url
    if parsed.scheme in ("http", "https") and parsed.hostname in ALLOWED_HOSTS:
        return next_url
    return "/"


class LoginHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        next_url = parse_qs(urlparse(self.path).query).get("next", ["/"])[0]
        self.send_response(302)
        self.send_header("Location", redirect_target(next_url))
        self.end_headers()
