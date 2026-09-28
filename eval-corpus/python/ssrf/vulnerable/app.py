import urllib.request


def fetch_preview(url: str) -> str:
    """Fetch the start of a page so the UI can show a link preview.

    VULNERABLE: the caller chooses the destination and nothing constrains it, so the
    server will request whatever host the input names.
    """
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.read(4096).decode("utf-8", "replace")
