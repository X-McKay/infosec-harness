import os


def read_config(path: str) -> str:
    """Read a config file.

    FIXED: a single os.open with O_NOFOLLOW resolves the path once and refuses to
    traverse a final symlink, closing the check/use gap. There is no separate
    existence check to race against, and a swapped-in symlink raises OSError
    instead of being followed.
    """
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as handle:
        return handle.read()
