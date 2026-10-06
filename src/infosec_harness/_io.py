"""The atomic writer for evidence files.

Reports, ledgers, lease records and artifacts are evidence, so a reader must see either the
previous complete file or the new complete one, never a partial one: the bytes go to an
owner-only (``mkstemp``: 0600) temporary file beside the target, are flushed to disk, and are
published in one step. An exception at any point leaves the previous file and no temporary
file behind; a killed process or a power loss can still leave a ``.<name>.*`` temporary file.
(Source snapshots publish by renaming a whole directory instead; see workflows/snapshot.py.)
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any


def atomic_write_bytes(path: Path, data: bytes, *, exclusive: bool = False,
                       sync_directory: bool = False) -> None:
    """Publish ``data`` at ``path`` atomically and owner-only.

    ``exclusive`` publishes only if ``path`` does not exist yet (``FileExistsError``
    otherwise) instead of replacing it. ``sync_directory`` also flushes the directory entry,
    for records that must survive a crash, not just a concurrent reader.
    """
    directory = path.parent
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=directory)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if exclusive:
            os.link(temporary, path)
        else:
            os.replace(temporary, path)
        if sync_directory:
            directory_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


def write_json(path: Path, document: Any, *, exclusive: bool = False) -> None:
    """Strict, indented JSON with a trailing newline, written by :func:`atomic_write_bytes`.

    ``NaN`` and infinities are refused (``ValueError``): they are not JSON, and the API would
    list such a report as unreadable. The document is encoded before any directory is made.
    """
    # Any: report documents are arbitrary JSON-compatible values built by the callers.
    encoded = json.dumps(document, indent=2, allow_nan=False) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_bytes(path, encoded.encode(), exclusive=exclusive)
