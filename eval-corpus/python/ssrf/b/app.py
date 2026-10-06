import urllib.parse
import urllib.request

# Link previews are only ever fetched from the documentation sites we publish.
ALLOWED_HOSTS = frozenset({"docs.example.com", "www.example.com"})


def fetch_preview(url: str) -> str:
    """Fetch the start of a page so the UI can show a link preview.

    FIXED: the destination must be an allowlisted http(s) host, so the caller cannot
    redirect the request at an internal address.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("destination host is not allowlisted")
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.read(4096).decode("utf-8", "replace")
