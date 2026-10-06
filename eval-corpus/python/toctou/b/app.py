import os


def read_config(path: str) -> str:
    """Read a config file after checking it exists."""
    if os.path.exists(path):
        with open(path) as handle:
            return handle.read()
    raise FileNotFoundError(path)
