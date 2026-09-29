"""Revision-aware, immutable repository snapshot materialization."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import stat
import tempfile
from pathlib import Path, PurePosixPath

from infosec_harness.domain.models import RepoRef, RepoSnapshot, SourceMode
from infosec_harness.repo.access import RepositoryAccessError, walk_files
from infosec_harness.sandbox.docker import default_workspace

# Source capture excludes repository metadata and dependency/cache trees. Generated build output
# (`target`, `build`, `dist`) remains source material: a directory name alone cannot prove it is
# irrelevant, and hard size/count limits provide the bound.
SKIP = {".git", "node_modules", ".venv", "venv", "__pycache__"}
MAX_FILES = 100_000
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
GIT_TIMEOUT_S = 300
GIT_LOG_BYTES = 64_000


async def _git(*args: str, cwd: str | None = None) -> tuple[int, str]:
    proc = await asyncio.create_subprocess_exec(
        "git", *args, cwd=cwd,
        env={**os.environ, "GIT_LFS_SKIP_SMUDGE": "1", "GIT_TERMINAL_PROMPT": "0"},
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    async def drain_tail() -> bytes:
        assert proc.stdout is not None
        tail = bytearray()
        while chunk := await proc.stdout.read(16_384):
            tail.extend(chunk)
            if len(tail) > GIT_LOG_BYTES:
                del tail[:-GIT_LOG_BYTES]
        await proc.wait()
        return bytes(tail)

    try:
        out = await asyncio.wait_for(drain_tail(), timeout=GIT_TIMEOUT_S)
    except (TimeoutError, asyncio.CancelledError):
        proc.kill()
        await proc.wait()
        raise
    return proc.returncode, out.decode(errors="replace")


def _hash_part(digest, value: bytes) -> None:
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def _content_identity(root: Path) -> tuple[str, int]:
    """Hash types, paths, executable modes, contents, and normalized internal link targets."""
    digest = hashlib.sha256()
    total = 0
    count = 0
    for rel, path in walk_files(root, skip_dirs=SKIP, max_entries=MAX_FILES * 2):
        count += 1
        if count > MAX_FILES:
            raise RepositoryAccessError(f"snapshot exceeds {MAX_FILES} files")
        _hash_part(digest, rel.encode())
        mode = path.lstat().st_mode
        _hash_part(digest, f"{mode & 0o111:o}".encode())
        if path.is_symlink():
            resolved = path.resolve(strict=True)
            target = resolved.relative_to(root.resolve()).as_posix()
            _hash_part(digest, b"symlink")
            _hash_part(digest, target.encode())
            continue
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            raise RepositoryAccessError(
                f"snapshot file {rel!r} exceeds {MAX_FILE_BYTES} bytes"
            )
        total += size
        if total > MAX_TOTAL_BYTES:
            raise RepositoryAccessError(f"snapshot exceeds {MAX_TOTAL_BYTES} total bytes")
        _hash_part(digest, b"file")
        _hash_part(digest, path.read_bytes())
    return digest.hexdigest(), count


def _policy_hash(exclude_paths: list[str]) -> str:
    payload = json.dumps(
        {"excluded_dir_names": sorted(SKIP), "requested_paths": sorted(set(exclude_paths))},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _remove_excluded(dest: Path, exclude_paths: list[str]) -> None:
    """Remove lexical repo-relative paths without following a link at the final component."""
    for raw in exclude_paths:
        portable = PurePosixPath(raw.replace("\\", "/"))
        if portable.is_absolute() or ".." in portable.parts:
            continue
        target = dest.joinpath(*portable.parts)
        try:
            target.relative_to(dest)
        except ValueError:
            continue
        # A Git tree may contain arbitrary links. Never follow one in an intermediate component
        # while applying a dataset-supplied exclusion, because unlinking through that path would
        # mutate the link target outside the temporary checkout.
        current = dest
        unsafe_parent = False
        for part in portable.parts[:-1]:
            current /= part
            if current.is_symlink():
                unsafe_parent = True
                break
        if unsafe_parent:
            continue
        if target.is_symlink() or target.is_file():
            target.unlink(missing_ok=True)
        elif target.is_dir():
            shutil.rmtree(target)


def _is_local(repo_url: str) -> tuple[bool, Path | None]:
    if repo_url.startswith("file://"):
        return True, Path(repo_url.removeprefix("file://")).resolve()
    candidate = Path(repo_url)
    if repo_url.startswith(("/", "./", "../")) or candidate.exists():
        return True, candidate.resolve()
    return False, None


async def _is_git_repo(path: Path) -> bool:
    code, out = await _git("-C", str(path), "rev-parse", "--show-toplevel")
    return code == 0 and Path(out.strip()).resolve() == path.resolve()


async def _materialize_git(repo_url: str, revision: str, dest: Path,
                           local_path: Path | None) -> str:
    source = str(local_path) if local_path is not None else repo_url
    args = ["clone", "--no-checkout"]
    args.append("--no-hardlinks" if local_path is not None else "--filter=blob:none")
    code, log = await _git(*args, source, str(dest))
    if code != 0:
        raise RuntimeError(f"git clone failed: {log[-2000:]}")
    code, log = await _git("checkout", "--detach", revision, cwd=str(dest))
    if code != 0:
        raise RuntimeError(f"git checkout {revision!r} failed: {log[-2000:]}")
    code, resolved = await _git("rev-parse", "HEAD", cwd=str(dest))
    if code != 0:
        raise RuntimeError(f"could not resolve checked-out revision: {resolved[-2000:]}")
    shutil.rmtree(dest / ".git")
    return resolved.strip()


def _copy_working_snapshot(source: Path, dest: Path) -> None:
    if not source.is_dir():
        raise ValueError(f"working snapshot source is not a directory: {source}")
    tuple(walk_files(source, skip_dirs=SKIP, max_entries=MAX_FILES * 2))
    shutil.copytree(source, dest, symlinks=True, ignore=shutil.ignore_patterns(*SKIP))


def _make_read_only(root: Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_symlink():
            continue
        mode = path.stat().st_mode
        path.chmod(mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
    root.chmod(root.stat().st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))


def _make_writable_for_cleanup(root: Path) -> None:
    """Restore owner permissions on an unpublished tree so temporary cleanup is reliable."""
    if not root.exists():
        return
    root.chmod(root.stat().st_mode | stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    for path in root.rglob("*"):
        if path.is_symlink():
            continue
        mode = path.stat().st_mode | stat.S_IRUSR | stat.S_IWUSR
        if path.is_dir():
            mode |= stat.S_IXUSR
        path.chmod(mode)


async def checkout(ref: RepoRef) -> RepoSnapshot:
    workspace = default_workspace() / "snapshots"
    workspace.mkdir(parents=True, exist_ok=True)
    local, local_path = _is_local(ref.repo_url)
    local_git = bool(local_path and await _is_git_repo(local_path))
    mode = ref.source_mode or (
        SourceMode.git_revision if (not local or local_git) else SourceMode.working_snapshot
    )
    if mode is SourceMode.git_revision and local and not local_git:
        raise ValueError(
            f"requested git_revision {ref.revision!r}, but {ref.repo_url!r} is not a Git repository"
        )
    if mode is SourceMode.working_snapshot and not local:
        raise ValueError("working_snapshot mode requires a local directory")
    if mode is SourceMode.working_snapshot and ref.revision != "HEAD":
        raise ValueError(
            f"working_snapshot cannot resolve requested revision {ref.revision!r}; use "
            "source_mode='git_revision' for a commit, tag, or branch"
        )

    policy_hash = _policy_hash(ref.exclude_paths)
    tmp_parent = Path(tempfile.mkdtemp(prefix="snapshot-", dir=workspace))
    materialized = tmp_parent / "tree"
    resolved: str | None = None
    git_dirty: bool | None = None
    try:
        if mode is SourceMode.git_revision:
            resolved = await _materialize_git(ref.repo_url, ref.revision, materialized, local_path)
        else:
            assert local_path is not None
            if local_git:
                code, status = await _git(
                    "-C", str(local_path), "status", "--porcelain", "--untracked-files=all"
                )
                if code != 0:
                    raise RuntimeError(f"could not determine working-tree state: {status[-2000:]}")
                git_dirty = bool(status.strip())
            _copy_working_snapshot(local_path, materialized)
        _remove_excluded(materialized, ref.exclude_paths)
        content_hash, file_count = _content_identity(materialized)
        identity = json.dumps(
            {
                "repo": str(local_path) if local_path else ref.repo_url,
                "mode": mode.value,
                "resolved": resolved,
                "content": content_hash,
                "git_dirty": git_dirty,
                "exclusion_policy": policy_hash,
                "submodules": "excluded",
                "lfs": "pointer_only",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        dest = workspace / hashlib.sha256(identity.encode()).hexdigest()
        published = dest / "tree"
        _make_read_only(materialized)
        try:
            # macOS refuses to rename the read-only tree itself. Publish its writable wrapper
            # atomically instead: the only source path consumers can see (`dest/tree`) is already
            # immutable before the wrapper name becomes visible.
            tmp_parent.rename(dest)
            dest.chmod(dest.stat().st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
        except OSError as exc:
            if not dest.exists():
                raise
            if dest.is_symlink() or not dest.is_dir():
                raise RuntimeError(f"snapshot destination is not a directory: {dest}") from exc
            # Compatibility with snapshots published by the earlier direct-directory layout.
            # Try both shapes by content; an old repository could itself contain a `tree/`
            # directory, so shape alone cannot distinguish them.
            matched = None
            for candidate in (published, dest):
                if candidate.is_symlink() or not candidate.is_dir():
                    continue
                existing_hash, existing_count = _content_identity(candidate)
                if existing_hash == content_hash:
                    matched = (candidate, existing_count)
                    break
            if matched is None:
                raise RuntimeError(f"snapshot identity collision at {dest}") from exc
            published, file_count = matched
            _make_read_only(dest)
        return RepoSnapshot(
            repo_url=ref.repo_url,
            revision=ref.revision,
            resolved_commit=resolved,
            path=str(published.resolve()),
            content_hash=content_hash,
            source_mode=mode,
            exclusion_policy_hash=policy_hash,
            file_count=file_count,
            git_dirty=git_dirty,
        )
    finally:
        _make_writable_for_cleanup(tmp_parent)
        shutil.rmtree(tmp_parent, ignore_errors=True)
