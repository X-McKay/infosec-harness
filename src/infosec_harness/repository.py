"""Bounded immutable source capture. Repository code never executes on the worker."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from infosec_harness.config import Settings, get_settings
from infosec_harness.models import Citation, Finding
from infosec_harness.process import run_bounded

EXCLUDED = frozenset({".git", ".venv", "venv", "node_modules", "__pycache__"})
MAX_FILE = 32 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_ENTRIES = 100_000


@dataclass(frozen=True)
class Snapshot:
    path: str
    digest: str


def confined(root: str | Path, relative: str) -> Path:
    path = PurePosixPath(relative.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError("expected a relative source path")
    base = Path(root).resolve(strict=True)
    target = base.joinpath(*path.parts)
    if any(
        p.is_symlink() for p in (target, *target.parents) if p != base and p.is_relative_to(base)
    ):
        raise ValueError("source symlinks are not supported")
    target = target.resolve(strict=True)
    if not target.is_relative_to(base):
        raise ValueError("source path escapes snapshot")
    return target


def validate_citation(snapshot_path: str | Path, citation: Citation) -> Citation:
    path = confined(snapshot_path, citation.path)
    if not path.is_file() or path.stat().st_size > MAX_FILE:
        raise ValueError("citation must identify a bounded source file")
    if citation.end_line > len(path.read_bytes().splitlines()):
        raise ValueError("citation exceeds source file")
    return citation


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
            raise RuntimeError("source checkout failed; no repository code was executed")


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

    if published.exists():
        return existing()
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
        assert source is not None
        candidate = staging / "snapshot"
        candidate.mkdir()
        digest = _capture(source, candidate / "tree")
        (candidate / "metadata.json").write_text(
            json.dumps({"finding": identity, "digest": digest})
        )
        try:
            candidate.rename(published)
        except OSError:
            if not published.exists():
                raise
        return existing()
