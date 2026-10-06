"""Bounded archive transfer into sandboxes and source snapshots out of them.

``Transfer`` is mixed into :class:`~infosec_harness.sandbox.openshell.OpenShell`. Archives
are extracted only inside sandboxes; on the worker a captured snapshot's metadata is parsed
and compared with the original source, and no member is ever extracted.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import logging
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any

from infosec_harness._io import atomic_write_bytes

from .execution import (
    _PYTHON,
    CommandResult,
    Execution,
    ExecutionUnknown,
    OpenShellError,
    Sandbox,
    SourceChanged,
    SourceRejected,
    TransferRecord,
    _digest,
    _event,
    _load,
    _operation_id,
    _records,
    _request_id,
    _sandbox_record,
)

log = logging.getLogger(__name__)

# The pinned gateway decodes at most 1 MiB per gRPC message; archives travel in parts.
_PART_BYTES = 900_000
# Members of one source snapshot, captured or original.
_MAX_FILES = 65536


class UnsafeSnapshotMetadata(OpenShellError):
    """A captured archive failed metadata admission; execution outcome is separate."""


def _sha256(stream: Any) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(65536):
        digest.update(chunk)
    return digest.hexdigest()


def _path(path: str) -> str:
    value = PurePosixPath(path)
    if not value.is_absolute() or ".." in value.parts or str(value) != path:
        raise OpenShellError("sandbox path must be canonical and absolute")
    if value != PurePosixPath("/workspace") and PurePosixPath("/workspace") not in value.parents:
        raise OpenShellError("repository tools are confined to /workspace")
    return path


class Transfer(Execution):
    """Repository upload, probe workspace copies and source verification; a mixin of ``OpenShell``."""

    async def upload(self, sandbox: Sandbox, source: Path, destination: str) -> None:
        self._owned(sandbox)
        _path(destination)
        if sandbox.profile == "model":
            raise OpenShellError("repository upload is forbidden in model sandboxes")
        if not source.is_dir() or source.is_symlink():
            raise SourceRejected("source must be a regular directory")
        archive = io.BytesIO()
        total = 0
        with tarfile.open(fileobj=archive, mode="w") as tar:
            for path in sorted(source.rglob("*")):
                if path.is_symlink() or not (path.is_file() or path.is_dir()):
                    raise SourceRejected("source archive cannot contain symlinks or special files")
                total += path.stat().st_size if path.is_file() else 0
                # Checked before the file enters the in-memory archive, and again after.
                if total > self.config.max_transfer_bytes:
                    raise self._over_bound("source archive")
                tar.add(path, arcname=str(path.relative_to(source)), recursive=False)
                if archive.tell() > self.config.max_transfer_bytes:
                    raise self._over_bound("source archive")
        data = archive.getvalue()
        result = await self._deliver(sandbox, data, destination,
            operation_id="upload:" + _digest([destination, hashlib.sha256(data).hexdigest()]))
        if result.exit_code:
            raise OpenShellError(f"source upload failed: extraction exit {result.exit_code}")

    def _over_bound(self, what: str) -> SourceRejected:
        return SourceRejected(f"{what} exceeds the transfer bound: more than "
                              f"{self.config.max_transfer_bytes} bytes (max_transfer_bytes in the "
                              "OpenShell runtime config)")

    async def _deliver(self, sandbox: Sandbox, data: bytes, destination: str, *,
                       operation_id: str) -> CommandResult:
        """Extract an archive inside the sandbox, sending at most _PART_BYTES per request.

        Each part is its own replayable receipt; the final extraction consumes the staged
        file and removes it. Extraction always uses the data filter inside the sandbox.
        """
        extract = ("import io,pathlib,sys,tarfile; p=pathlib.Path(sys.argv[1]); "
                   "p.mkdir(parents=True,exist_ok=True); "
                   "t=tarfile.open(fileobj=io.BytesIO(sys.stdin.buffer.read())); "
                   "t.extractall(p,filter='data')")
        if len(data) <= _PART_BYTES:
            return await self.execute(sandbox, [_PYTHON, "-I", "-c", extract, destination],
                                      operation_id=operation_id, timeout=60, stdin=data)
        staged = "/workspace/.ih-stage-" + hashlib.sha256(data).hexdigest()[:16]
        append = ("import pathlib,sys; "
                  "pathlib.Path(sys.argv[1]).open('ab').write(sys.stdin.buffer.read())")
        for index, offset in enumerate(range(0, len(data), _PART_BYTES)):
            result = await self.execute(sandbox, [_PYTHON, "-I", "-c", append, staged],
                operation_id=f"{operation_id}:part{index}", timeout=60,
                stdin=data[offset:offset + _PART_BYTES])
            if result.exit_code:
                return result
        unpack = ("import pathlib,sys,tarfile; p=pathlib.Path(sys.argv[1]); "
                  "p.mkdir(parents=True,exist_ok=True); s=pathlib.Path(sys.argv[2]); "
                  "t=tarfile.open(s); t.extractall(p,filter='data'); s.unlink()")
        return await self.execute(sandbox, [_PYTHON, "-I", "-c", unpack, destination, staged],
                                  operation_id=operation_id, timeout=60)

    async def _snapshot(self, source: Sandbox, *, operation_id: str, expected_source: Path,
                        cover_operations: bool = False) -> tuple[bytes, Path, str]:
        """Capture and compare source bytes; never extract repository code on the worker.

        With ``cover_operations`` the intent records, before capture, the operations already
        completed on ``source``: only those can be covered by this capture, including when
        a later attempt replays it.
        """
        self._owned(source)
        if source.profile not in ("workspace", "probe"):
            raise OpenShellError("model workload cannot provide a repository snapshot")
        _operation_id(operation_id)
        key = _digest([source.id, operation_id])
        record = self._record("transfers", key)
        archive = record.with_suffix(".tar")
        async with self._locks.setdefault(key, asyncio.Lock()):
            if record.exists():
                saved: TransferRecord = _load(record)
                if "sha256" not in saved:
                    raise ExecutionUnknown("source snapshot has an unknown prior outcome")
                raw = archive.read_bytes()
                if len(raw) != saved["size"] or hashlib.sha256(raw).hexdigest() != saved["sha256"]:
                    raise OpenShellError("persisted source snapshot integrity failed")
            else:
                intent: TransferRecord = {"source": _sandbox_record(source), "operation_id": operation_id}
                if cover_operations:
                    intent["covered_operations"] = self._completed_operations(source)
                self._save(record, intent, exclusive=True)
                try:
                    await self._corroborate(source, "source native identity changed")
                    result, raw = await asyncio.to_thread(self._stream, source,
                        ["/usr/bin/tar", "-C", "/workspace/repo", "-cf", "-", "."],
                        60, None, _request_id(key), self.config.max_transfer_bytes, True)
                    if result.exit_code or result.output_truncated:
                        raise OpenShellError(f"source snapshot capture failed: tar exit {result.exit_code}")
                    atomic_write_bytes(archive, raw, sync_directory=True)
                    self._save(record, {**intent, "sha256": hashlib.sha256(raw).hexdigest(),
                                        "size": len(raw)})
                    _event(log, logging.INFO, "receipt_written", run_id=source.run_id,
                           operation_id=operation_id, sandbox_id=source.id, kind="capture",
                           archive_bytes=len(raw))
                except BaseException as error:
                    await self._close_owned(source, error)
                    raise
            # Parse metadata only. No archive member is ever extracted on the
            # worker; hardlinks, symlinks, devices and traversal are refused.
            try:
                with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
                    size = 0
                    seen = set()
                    archived_files = {}
                    for count, member in enumerate(tar, 1):
                        path = PurePosixPath(member.name)
                        size += member.size
                        if (path.is_absolute() or ".." in path.parts or path in seen
                                or not (member.isfile() or member.isdir())
                                or count > _MAX_FILES or size > self.config.max_transfer_bytes):
                            raise UnsafeSnapshotMetadata("source snapshot contains unsafe archive metadata")
                        seen.add(path)
                        if member.isfile():
                            stream = tar.extractfile(member)
                            if stream is None:  # Never for a regular file; checked, not asserted.
                                raise UnsafeSnapshotMetadata("source snapshot member is unreadable")
                            archived_files[path] = (_sha256(stream), member.mode & 0o111)
            except tarfile.TarError:
                raise OpenShellError("source snapshot is not a valid archive") from None
            original_files = {}
            if not expected_source.is_dir() or expected_source.is_symlink():
                raise SourceRejected("original source snapshot must be a regular directory")
            total = 0
            for original in sorted(expected_source.rglob("*")):
                if original.is_symlink() or not (original.is_file() or original.is_dir()):
                    raise SourceRejected("original source snapshot contains unsafe file types")
                if original.is_file():
                    total += original.stat().st_size
                    if total > self.config.max_transfer_bytes or len(original_files) >= _MAX_FILES:
                        raise SourceRejected(
                            f"original source snapshot exceeds bound: more than "
                            f"{self.config.max_transfer_bytes} bytes (max_transfer_bytes) or "
                            f"{_MAX_FILES} files")
                    with original.open("rb") as stream:
                        content_digest = _sha256(stream)
                    name = PurePosixPath(original.relative_to(expected_source).as_posix())
                    identity = (content_digest, original.stat().st_mode & 0o111)
                    original_files[str(name)] = identity
                    if archived_files.get(name) != identity:
                        # The name comes from the immutable snapshot, not from the model.
                        raise SourceChanged(f"workspace changed or deleted original source: {name}")
            return raw, record, _digest(original_files)

    async def copy_workspace(self, source: Sandbox, probe: Sandbox, *, operation_id: str,
                             expected_source: Path) -> str:
        self._owned(probe)
        if source.profile != "workspace" or probe.profile != "probe" or source.run_id != probe.run_id:
            raise OpenShellError("source snapshots may only enter this investigation's offline probe")
        raw, record, original_digest = await self._snapshot(source, operation_id=operation_id,
                                                          expected_source=expected_source)
        result = await self._deliver(probe, raw, "/workspace/repo",
                                     operation_id=operation_id + ":restore")
        if result.exit_code:
            raise OpenShellError(f"offline probe source restore failed: extraction exit {result.exit_code}")
        archive_digest = hashlib.sha256(raw).hexdigest()
        restored: TransferRecord = {"source": _sandbox_record(source), "probe": _sandbox_record(probe),
            "operation_id": operation_id, "sha256": archive_digest, "size": len(raw),
            "expected_source_digest": original_digest, "restored": True}
        self._save(record, restored)
        return archive_digest

    async def verify_source(self, probe: Sandbox, expected_source: Path, *, operation_id: str) -> None:
        if probe.profile != "probe":
            raise OpenShellError("post-execution integrity checks require an offline probe")
        raw, record, original_digest = await self._snapshot(probe, operation_id=operation_id,
            expected_source=expected_source, cover_operations=True)
        saved: TransferRecord = _load(record)
        if saved.get("source_verified"):
            return
        # Only operations completed before the capture began. A capture saved without that
        # set (before it was recorded) certifies nothing rather than guessing.
        covered = saved.get("covered_operations", [])
        self._save(record, {**saved, "expected_source_digest": original_digest,
                            "source_verified": True, "verified_operations": covered})

    def _completed_operations(self, sandbox: Sandbox) -> list[str]:
        """Operation ids with a completed receipt on this exact native sandbox."""
        return sorted(saved["operation_id"] for saved in _records(self.config.state_dir, "operations")
                      if saved["sandbox"]["id"] == sandbox.id and "result" in saved)
