import os

BASE = os.path.realpath(os.path.join(os.path.dirname(__file__), "data"))


def read_doc(name: str) -> bytes:
    """Read a document from the data directory."""
    target = os.path.realpath(os.path.join(BASE, name))
    if not (target == BASE or target.startswith(BASE + os.sep)):
        raise ValueError("path escapes the document root")
    with open(target, "rb") as f:
        return f.read()
