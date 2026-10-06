import urllib.request


def fetch_preview(url: str) -> str:
    """Fetch the start of a page so the UI can show a link preview."""
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.read(4096).decode("utf-8", "replace")
