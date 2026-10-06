import os


def read_config(path: str) -> str:
    """Read a config file."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as handle:
        return handle.read()
