import http.server
from urllib.parse import parse_qs, urlparse


def redirect_target(next_url: str) -> str:
    """Choose the Location destination for the post-login redirect."""
    return next_url


class LoginHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        next_url = parse_qs(urlparse(self.path).query).get("next", ["/"])[0]
        self.send_response(302)
        self.send_header("Location", redirect_target(next_url))
        self.end_headers()
