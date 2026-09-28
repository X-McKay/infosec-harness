"""Repo snapshot (P0): clone/copy a repo at a revision onto the shared workspace, content-hashed.

Supports git URLs and local paths (local paths are convenient for fixtures and the eval
corpus). The content hash keys the prepared-environment cache.
"""

from __future__ import annotations

import asyncio
import hashlib
import shutil
from pathlib import Path

from infosec_harness.domain.models import RepoRef, RepoSnapshot
from infosec_harness.sandbox.docker import default_workspace

SKIP = {".git", "node_modules", ".venv", "venv", "__pycache__", "target", "build", "dist"}


async def _git(*args: str, cwd: str | None = None) -> tuple[int, str]:
    proc = await asyncio.create_subprocess_exec(
        "git", *args, cwd=cwd,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    out, _ = await proc.communicate()
    return proc.returncode, out.decode(errors="replace")


def _content_hash(root: Path) -> str:
    h = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file() and not _skipped(p, root)):
        h.update(str(path.relative_to(root)).encode())
        h.update(path.read_bytes())
    return h.hexdigest()


def _skipped(path: Path, root: Path) -> bool:
    return any(part in SKIP for part in path.relative_to(root).parts)


def _remove_excluded(dest: Path, exclude_paths: list[str]) -> None:
    """Delete repo-relative paths from a fresh checkout, before anything reads it.

    Used to strip a benchmark's own proof-of-vulnerability test (see RepoRef.exclude_paths).
    Paths are resolved against the checkout and anything escaping it is ignored rather than
    followed -- the list comes from a dataset, which is untrusted input like any other.
    """
    root = dest.resolve()
    for rel in exclude_paths:
        target = (root / rel).resolve()
        if not target.is_relative_to(root) or not target.exists():
            continue
        if target.is_dir():
            shutil.rmtree(target, ignore_errors=True)
        else:
            target.unlink(missing_ok=True)


async def checkout(ref: RepoRef) -> RepoSnapshot:
    workspace = default_workspace() / "snapshots"
    workspace.mkdir(parents=True, exist_ok=True)
    key = hashlib.sha256(f"{ref.repo_url}@{ref.revision}".encode()).hexdigest()[:16]
    dest = workspace / key
    resolved: str | None = None

    is_local = ref.repo_url.startswith(("/", "./", "file://")) or Path(ref.repo_url).exists()
    if dest.exists():
        shutil.rmtree(dest)

    if is_local:
        src = Path(ref.repo_url.removeprefix("file://"))
        shutil.copytree(src, dest, ignore=shutil.ignore_patterns(*SKIP))
    else:
        code, log = await _git("clone", "--filter=blob:none", "--no-checkout", ref.repo_url, str(dest))
        if code != 0:
            raise RuntimeError(f"git clone failed: {log[-2000:]}")
        code, log = await _git("checkout", ref.revision, cwd=str(dest))
        if code != 0:
            raise RuntimeError(f"git checkout {ref.revision} failed: {log[-2000:]}")
        _, rev = await _git("rev-parse", "HEAD", cwd=str(dest))
        resolved = rev.strip()
        shutil.rmtree(dest / ".git", ignore_errors=True)

    # Applied before the content hash, so a masked checkout is not mistaken for the unmasked
    # one: the hash is what identifies this tree downstream.
    _remove_excluded(dest, ref.exclude_paths)

    return RepoSnapshot(
        repo_url=ref.repo_url,
        revision=ref.revision,
        resolved_commit=resolved,
        path=str(dest.resolve()),
        content_hash=_content_hash(dest),
    )
