"""Revision-aware, immutable repository snapshot materialization."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
from pathlib import Path, PurePosixPath

from infosec_harness.domain.canonical import canonical_bytes, digest, sha256_hex
from infosec_harness.domain.models import RepoRef, RepoSnapshot, SourceMode
from infosec_harness.persistence.paths import workspace_dir
from infosec_harness.repo.access import DEPENDENCY_DIRS, RepositoryAccessError, walk_files
from infosec_harness.sandbox.process import run_bounded
from infosec_harness.settings import get_settings

MAX_FILES = 100_000
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
GIT_TIMEOUT_S = 300
GIT_LOG_BYTES = 64_000


# Command-line configuration outranks every repository, global and system file. Only HTTPS
# transport is allowed (no ssh, git://, ext:: or local file protocol) unless the source is an
# operator-approved local path; credential helpers and repository-configured hooks or
# filesystem monitors never run.
_GIT_CONFIG = (
    "-c", "protocol.allow=never",
    "-c", "protocol.https.allow=always",
    "-c", "credential.helper=",
    "-c", "core.fsmonitor=false",
    "-c", "core.hooksPath=/dev/null",
)
_LOCAL_TRANSPORT = ("-c", "protocol.file.allow=always")


def _git_environment() -> dict[str, str]:
    """No ambient credentials, SSH agent, askpass, global or system Git configuration."""
    return {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_ASKPASS": "",
        "SSH_ASKPASS": "",
        "LC_ALL": "C",
    }


async def _git(*args: str, cwd: str | None = None, local: bool = False) -> tuple[int, str]:
    config = (*_GIT_CONFIG, *(_LOCAL_TRANSPORT if local else ()))
    result = await run_bounded(["git", *config, *args], env=_git_environment(),
                               timeout=GIT_TIMEOUT_S, cwd=cwd, capture_limit=GIT_LOG_BYTES,
                               stderr_to_stdout=True)
    if result.timed_out:
        raise TimeoutError(f"git timed out after {GIT_TIMEOUT_S} seconds")
    return result.exit_code, result.stdout


def _hash_part(hasher, value: bytes) -> None:
    hasher.update(len(value).to_bytes(8, "big"))
    hasher.update(value)


def _content_identity(root: Path) -> tuple[str, int]:
    """Hash types, paths, executable modes, contents, and normalized internal link targets."""
    hasher = hashlib.sha256()
    total = 0
    count = 0
    for rel, path in walk_files(root, skip_dirs=DEPENDENCY_DIRS, max_entries=MAX_FILES * 2):
        count += 1
        if count > MAX_FILES:
            raise RepositoryAccessError(f"snapshot exceeds {MAX_FILES} files")
        _hash_part(hasher, rel.encode())
        mode = path.lstat().st_mode
        _hash_part(hasher, f"{mode & 0o111:o}".encode())
        if path.is_symlink():
            resolved = path.resolve(strict=True)
            target = resolved.relative_to(root.resolve()).as_posix()
            _hash_part(hasher, b"symlink")
            _hash_part(hasher, target.encode())
            continue
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            raise RepositoryAccessError(
                f"snapshot file {rel!r} exceeds {MAX_FILE_BYTES} bytes"
            )
        total += size
        if total > MAX_TOTAL_BYTES:
            raise RepositoryAccessError(f"snapshot exceeds {MAX_TOTAL_BYTES} total bytes")
        _hash_part(hasher, b"file")
        _hash_part(hasher, path.read_bytes())
    return hasher.hexdigest(), count


def _policy_hash(exclude_paths: list[str]) -> str:
    return digest({"excluded_dir_names": sorted(DEPENDENCY_DIRS),
                   "requested_paths": sorted(set(exclude_paths))})


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
    """Classify a source; a local one must resolve beneath an operator-approved root."""
    if repo_url.startswith("file://"):
        candidate = Path(repo_url.removeprefix("file://"))
    elif repo_url.startswith(("/", "./", "../")) or Path(repo_url).exists():
        candidate = Path(repo_url)
    else:
        return False, None
    resolved = candidate.resolve()
    for root in get_settings().local_repo_roots:
        if resolved.is_relative_to(Path(root).resolve()):
            return True, resolved
    raise ValueError(
        f"local repository {repo_url!r} is outside the operator-approved local_repo_roots"
    )


def _validate_remote(repo_url: str) -> None:
    if not repo_url.startswith("https://") or any(c in repo_url for c in "\0\n\r"):
        raise ValueError(f"remote repository {repo_url!r} must be an https:// URL")


def _validate_revision(revision: str) -> None:
    if not revision or revision.startswith("-") or any(c in revision for c in "\0\n\r"):
        raise ValueError(f"invalid revision {revision!r}")


async def _is_git_repo(path: Path) -> bool:
    code, out = await _git("-C", str(path), "rev-parse", "--show-toplevel", local=True)
    return code == 0 and Path(out.strip()).resolve() == path.resolve()


async def _materialize_git(repo_url: str, revision: str, dest: Path,
                           local_path: Path | None) -> str:
    local = local_path is not None
    source = str(local_path) if local else repo_url
    args = ["clone", "--no-checkout", "--no-hardlinks" if local else "--filter=blob:none"]
    code, log = await _git(*args, "--", source, str(dest), local=local)
    if code != 0:
        raise RuntimeError(f"git clone failed: {log[-2000:]}")
    code, log = await _git("checkout", "--detach", revision, "--", cwd=str(dest), local=local)
    if code != 0:
        raise RuntimeError(f"git checkout {revision!r} failed: {log[-2000:]}")
    code, resolved = await _git("rev-parse", "HEAD", cwd=str(dest), local=local)
    if code != 0:
        raise RuntimeError(f"could not resolve checked-out revision: {resolved[-2000:]}")
    shutil.rmtree(dest / ".git")
    return resolved.strip()


def _copy_working_snapshot(source: Path, dest: Path) -> None:
    if not source.is_dir():
        raise ValueError(f"working snapshot source is not a directory: {source}")
    tuple(walk_files(source, skip_dirs=DEPENDENCY_DIRS, max_entries=MAX_FILES * 2))
    shutil.copytree(source, dest, symlinks=True, ignore=shutil.ignore_patterns(*DEPENDENCY_DIRS))


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
    workspace = workspace_dir() / "snapshots"
    workspace.mkdir(parents=True, exist_ok=True)
    local, local_path = _is_local(ref.repo_url)
    if not local:
        _validate_remote(ref.repo_url)
    _validate_revision(ref.revision)
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
                    "-C", str(local_path), "status", "--porcelain", "--untracked-files=all",
                    local=True,
                )
                if code != 0:
                    raise RuntimeError(f"could not determine working-tree state: {status[-2000:]}")
                git_dirty = bool(status.strip())
            _copy_working_snapshot(local_path, materialized)
        _remove_excluded(materialized, ref.exclude_paths)
        content_hash, file_count = _content_identity(materialized)
        identity = {
            "repo": str(local_path) if local_path else ref.repo_url,
            "mode": mode.value,
            "resolved": resolved,
            "content": content_hash,
            "git_dirty": git_dirty,
            "exclusion_policy": policy_hash,
            "submodules": "excluded",
            "lfs": "pointer_only",
        }
        # Published snapshot directory names keep their ASCII-escaped identity encoding.
        dest = workspace / sha256_hex(canonical_bytes(identity, ascii_only=True))
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
            # Published concurrently (or earlier) under the same identity. The name is not
            # trusted: the published tree is re-hashed and reused only if its content matches.
            if published.is_symlink() or not published.is_dir():
                raise RuntimeError(f"snapshot identity collision at {dest}") from exc
            existing_hash, file_count = _content_identity(published)
            if existing_hash != content_hash:
                raise RuntimeError(f"snapshot identity collision at {dest}") from exc
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
