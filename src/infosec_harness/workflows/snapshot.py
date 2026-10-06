"""Bounded immutable source capture. Repository code never executes on the worker."""

from __future__ import annotations

import asyncio
import errno
import hashlib
import json
import logging
import os
import stat
import tempfile
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from infosec_harness.config import Settings, get_settings
from infosec_harness.contracts import Citation, Finding
from infosec_harness.sandbox.process import finish, run_bounded

EXCLUDED = frozenset({".git", ".venv", "venv", "node_modules", "__pycache__"})
MAX_FILE = 32 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_ENTRIES = 100_000

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Snapshot:
    path: str
    digest: str


# Characters of a model-supplied citation path echoed in feedback and failure messages.
SHOWN_PATH_CHARS = 200


class InvalidCitation(ValueError):
    """A model-supplied citation names no bounded file line range of the original snapshot.

    Raised only for the model's own mistakes (a missing, non-file or non-relative path, or
    lines past the end). Symlink and escape refusals stay plain ``ValueError``: capture
    rejects links, so meeting one means the snapshot changed, never an agent-level fault.
    """


def shown(relative: str) -> str:
    return repr(relative[:SHOWN_PATH_CHARS])


def confined(root: str | Path, relative: str) -> Path:
    """The regular file ``relative`` names inside ``root``; ``ValueError`` for anything else.

    A missing root is an ``OSError``: the snapshot, not the caller, is absent.
    """
    path = PurePosixPath(relative.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise InvalidCitation(f"citation path {shown(relative)} is not a relative source path")
    base = Path(root).resolve(strict=True)
    missing = InvalidCitation(
        f"citation path {shown(relative)} is not a file in the original snapshot; cite only "
        "files that existed before your probes, or drop the citation"
    )
    target = base.joinpath(*path.parts)
    try:
        if any(
            p.is_symlink()
            for p in (target, *target.parents)
            if p != base and p.is_relative_to(base)
        ):
            raise ValueError("source symlinks are not supported")
        # Non-strict: no component is a link (checked above), so a missing path resolves to
        # itself and is refused below as a caller error instead of escaping as an OSError.
        target = target.resolve()
        if not target.is_relative_to(base):
            raise ValueError("source path escapes snapshot")
        if not target.is_file():
            raise missing
    except OSError as error:
        # A model-supplied over-long component cannot name a captured file; any other
        # OSError (permissions, I/O) is the harness's and propagates.
        if error.errno != errno.ENAMETOOLONG:
            raise
        raise missing from None
    return target


def validate_citation(snapshot_path: str | Path, citation: Citation) -> Citation:
    path = confined(snapshot_path, citation.path)
    if path.stat().st_size > MAX_FILE:
        raise InvalidCitation(f"citation path {shown(citation.path)} is not a bounded source file")
    lines = len(path.read_bytes().splitlines())
    if citation.end_line > lines:
        raise InvalidCitation(
            f"citation {shown(citation.path)} line range {citation.start_line}-{citation.end_line} "
            f"exceeds source file length ({lines} lines)"
        )
    return citation


def citation_feedback(snapshot_path: str | Path, citations: list[Citation]) -> list[str]:
    """One bounded message per invalid citation; any other failure propagates (fail closed)."""
    problems = []
    for citation in citations:
        try:
            validate_citation(snapshot_path, citation)
        except InvalidCitation as error:
            problems.append(str(error))
    return problems


def _capture(source: Path, destination: Path | None) -> str:
    """Descriptor-relative reads reject links/special files, including concurrent substitution."""
    hasher = hashlib.sha256()
    count = total = 0
    # Anchor each ancestor before traversal: a source owner cannot swap a parent
    # for a symlink between path admission and descriptor-relative file reads.
    root_descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in source.absolute().parts[1:]:
            if component in (".", ".."):
                raise ValueError("source must have a canonical absolute path")
            child = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_descriptor
            )
            os.close(root_descriptor)
            root_descriptor = child
        for directory, directories, files, descriptor in os.fwalk(
            ".", follow_symlinks=False, dir_fd=root_descriptor
        ):
            relative_dir = Path(directory)
            directories[:] = sorted(name for name in directories if name not in EXCLUDED)
            for name in directories:
                if not stat.S_ISDIR(
                    os.stat(name, dir_fd=descriptor, follow_symlinks=False).st_mode
                ):
                    raise ValueError("source directory links are forbidden")
            count += len(directories) + len(files)
            if count > MAX_ENTRIES:
                raise ValueError("source entry limit exceeded")
            if destination is not None:
                (destination / relative_dir).mkdir(parents=True, exist_ok=True)
            for name in sorted(files):
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
                with os.fdopen(fd, "rb") as stream:
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
                        raise ValueError("source must contain bounded regular files only")
                    data = stream.read(MAX_FILE + 1)
                total += len(data)
                if len(data) > MAX_FILE or total > MAX_TOTAL:
                    raise ValueError("source size limit exceeded")
                relative = (relative_dir / name).as_posix()
                for part in (relative.encode(), str(info.st_mode & 0o111).encode(), data):
                    hasher.update(len(part).to_bytes(8, "big"))
                    hasher.update(part)
                if destination is not None:
                    target = destination / relative
                    target.write_bytes(data)
                    target.chmod(0o555 if info.st_mode & 0o111 else 0o444)
    finally:
        os.close(root_descriptor)
    return hasher.hexdigest()


async def _off_loop[T](function: Callable[..., T], *args: object) -> T:
    """Run a blocking capture in a thread, keeping the worker's event loop free.

    On cancellation, wait for the thread to stop touching the staging tree before the
    cancellation propagates (and the staging directory is removed); the work is bounded.
    """
    future = asyncio.ensure_future(asyncio.to_thread(function, *args))
    try:
        return await asyncio.shield(future)
    except asyncio.CancelledError:
        with suppress(Exception):
            await finish(future)
        raise


async def _git(source: str, revision: str, destination: Path, *, local: bool) -> None:
    if revision.startswith("-") or any(c in revision for c in "\x00\r\n"):
        raise ValueError("invalid revision")
    config = [
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.https.allow=always",
        "-c",
        "credential.helper=",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
    ]
    if local:
        config += ["-c", "protocol.file.allow=always"]
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "LC_ALL": "C",
    }
    for args, cwd in (
        (["clone", "--no-checkout", "--no-hardlinks", "--", source, str(destination)], None),
        (["checkout", "--detach", revision, "--"], str(destination)),
    ):
        result = await run_bounded(["git", *config, *args], env=env, timeout=300, cwd=cwd)
        if result.exit_code != 0 or result.timed_out:
            # Step, exit code and timeout only: Git's stderr can echo repository content.
            log.warning("event=source_checkout_failed step=%s exit_code=%s timed_out=%s",
                        args[0], result.exit_code, result.timed_out)
            raise RuntimeError(
                f"source checkout failed at git {args[0]} (exit {result.exit_code}, "
                f"timed_out {result.timed_out}); no repository code was executed"
            )


async def snapshot(finding: Finding, run_id: str, settings: Settings | None = None) -> Snapshot:
    settings = settings or get_settings()
    parent = settings.workspace_dir.resolve() / "sources"
    parent.mkdir(parents=True, exist_ok=True)
    key = hashlib.sha256(run_id.encode()).hexdigest()
    identity = hashlib.sha256(finding.model_dump_json().encode()).hexdigest()
    published = parent / key

    def existing() -> Snapshot:
        if published.is_symlink() or (published / "metadata.json").is_symlink():
            raise ValueError("unsafe snapshot destination")
        metadata = json.loads((published / "metadata.json").read_text())
        if (
            metadata["finding"] != identity
            or _capture(published / "tree", None) != metadata["digest"]
        ):
            raise ValueError("snapshot identity/content mismatch")
        return Snapshot(str(published / "tree"), metadata["digest"])

    # Capture and re-hash read up to MAX_TOTAL bytes; keep them off the worker's event loop,
    # which other activities (and, under a parallel cohort, other cases) share.
    if published.exists():
        return await _off_loop(existing)
    remote = urlsplit(finding.repo_url)
    local_path = None
    if remote.scheme:
        if (
            remote.scheme != "https"
            or not remote.hostname
            or remote.username
            or remote.password
            or remote.fragment
            or any(c in finding.repo_url for c in "\x00\r\n")
        ):
            raise ValueError("remote source must be an HTTPS URL without credentials or fragments")
        if finding.source_mode != "git_revision":
            raise ValueError("working snapshots require a local source")
    else:
        local_path = Path(finding.repo_url).resolve(strict=True)
        if not any(local_path.is_relative_to(root.resolve()) for root in settings.local_repo_roots):
            raise ValueError("local source is outside operator-approved roots")
    with tempfile.TemporaryDirectory(prefix=".capture-", dir=parent) as temporary:
        staging = Path(temporary)
        source = local_path
        if finding.source_mode == "git_revision":
            source = staging / "checkout"
            await _git(
                str(local_path) if local_path else finding.repo_url,
                finding.revision,
                source,
                local=local_path is not None,
            )
        elif finding.revision != "HEAD":
            raise ValueError("working snapshot cannot resolve a Git revision")
        if source is None:  # Unreachable: a remote source was refused unless git_revision.
            raise ValueError("working snapshots require a local source")
        candidate = staging / "snapshot"
        candidate.mkdir()
        digest = await _off_loop(_capture, source, candidate / "tree")
        (candidate / "metadata.json").write_text(
            json.dumps({"finding": identity, "digest": digest})
        )
        try:
            candidate.rename(published)
        except OSError:
            if not published.exists():
                raise
        return await _off_loop(existing)
