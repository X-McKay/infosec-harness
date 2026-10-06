import os


def read_config(path: str) -> str:
    """Read a config file after checking it exists.

    VULNERABLE: time-of-check to time-of-use (CWE-367). The existence check and
    the open resolve the path name twice, so a symlink swapped in between (or a
    symlink that was already there) redirects open() to a different file than the
    one the check vouched for.
    """
    if os.path.exists(path):
        with open(path) as handle:
            return handle.read()
    raise FileNotFoundError(path)
