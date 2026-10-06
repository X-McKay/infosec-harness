import os

BASE = os.path.join(os.path.dirname(__file__), "data")


def read_doc(name: str) -> bytes:
    """Read a document from the data directory."""
    with open(os.path.join(BASE, name), "rb") as f:
        return f.read()
