"""Shared confinement rules for every reader of an immutable repository snapshot."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Iterator
from pathlib import Path, PurePosixPath

from infosec_harness.domain.models import CodeRef

MAX_TRAVERSAL_ENTRIES = 200_000


class RepositoryAccessError(ValueError):
    """A requested path or repository entry violates the source boundary."""


def resolve_confined(root: str | Path, relative: str, *, must_exist: bool = False) -> Path:
    """Resolve a repository-relative path without permitting an escape through ``..`` or links.

    Internal file symlinks are permitted and resolve to their target. Directory symlinks are not
    traversed by :func:`walk_files`, which avoids cycles and keeps traversal accounting exact.
    """
    base = Path(root).resolve(strict=True)
    supplied = Path(relative)
    portable = PurePosixPath(relative.replace("\\", "/"))
    if supplied.is_absolute() or portable.is_absolute() or ".." in portable.parts:
        raise RepositoryAccessError(f"path {relative!r} is outside the repository")
    target = (base / supplied).resolve(strict=must_exist)
    if target != base and not target.is_relative_to(base):
        raise RepositoryAccessError(f"path {relative!r} is outside the repository")
    return target


def walk_files(root: str | Path, *, skip_dirs: set[str] | frozenset[str] = frozenset(),
               max_entries: int = MAX_TRAVERSAL_ENTRIES) -> Iterator[tuple[str, Path]]:
    """Yield confined regular files and internal file symlinks under ``root``.

    Unsupported special files fail closed. External and broken links are rejected rather than
    followed. The entry budget bounds traversal even when a caller's output is much smaller.
    """
    base = Path(root).resolve(strict=True)
    seen = 0
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        safe_dirs: list[str] = []
        for name in sorted(dirnames):
            seen += 1
            if seen > max_entries:
                raise RepositoryAccessError(f"repository traversal exceeds {max_entries} entries")
            candidate = Path(dirpath) / name
            if name in skip_dirs:
                continue
            if candidate.is_symlink():
                raise RepositoryAccessError(
                    f"directory symlinks are not supported in snapshots: "
                    f"{candidate.relative_to(base).as_posix()!r}"
                )
            mode = candidate.lstat().st_mode
            if not stat.S_ISDIR(mode):
                raise RepositoryAccessError(f"unsupported repository entry: {candidate}")
            safe_dirs.append(name)
        dirnames[:] = safe_dirs
        for name in sorted(filenames):
            seen += 1
            if seen > max_entries:
                raise RepositoryAccessError(f"repository traversal exceeds {max_entries} entries")
            candidate = Path(dirpath) / name
            rel = candidate.relative_to(base).as_posix()
            try:
                resolved = resolve_confined(base, rel, must_exist=True)
            except (OSError, RepositoryAccessError) as exc:
                raise RepositoryAccessError(f"unsafe repository link {rel!r}: {exc}") from exc
            mode = candidate.lstat().st_mode
            if candidate.is_symlink():
                if not resolved.is_file():
                    raise RepositoryAccessError(f"repository link {rel!r} does not target a file")
            elif not stat.S_ISREG(mode):
                raise RepositoryAccessError(f"unsupported repository entry: {rel!r}")
            yield rel, candidate


def validate_code_ref(root: str | Path, reference: CodeRef) -> CodeRef:
    """Validate a citation against snapshot bytes and attach its source digest."""
    target = resolve_confined(root, reference.file_path, must_exist=True)
    if not target.is_file():
        raise RepositoryAccessError(f"citation is not a file: {reference.file_path!r}")
    if reference.start_line < 1 or reference.end_line < reference.start_line:
        raise RepositoryAccessError(
            f"invalid citation range {reference.start_line}-{reference.end_line}"
        )
    raw = target.read_bytes()
    line_count = len(raw.decode(errors="replace").splitlines())
    if reference.end_line > line_count:
        raise RepositoryAccessError(
            f"citation {reference.file_path}:{reference.start_line}-{reference.end_line} "
            f"exceeds the file's {line_count} lines"
        )
    digest = hashlib.sha256(raw).hexdigest()
    if reference.source_digest and reference.source_digest != digest:
        raise RepositoryAccessError(
            f"citation digest for {reference.file_path!r} does not match the snapshot"
        )
    return reference.model_copy(update={"file_path": target.relative_to(Path(root).resolve()).as_posix(),
                                        "source_digest": digest})
