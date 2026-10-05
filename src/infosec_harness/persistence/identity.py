"""Worker-host provenance added to evidence at the moment it is persisted.

Computed lazily on the persisting host, the first time an output is persisted, never inside
workflow code: source-file and deployment identity must not become workflow I/O or replay
inputs.
"""

from __future__ import annotations

import hashlib
from functools import cache
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from infosec_harness.resources import package_root
from infosec_harness.settings import get_settings

MANIFEST_SCHEMA_VERSION = 3


def _files_digest(root: Path, paths: list[Path]) -> str:
    """Hash names and bytes with boundaries so a renamed file changes the identity."""
    digest = hashlib.sha256()
    for path in sorted(paths):
        relative = path.relative_to(root).as_posix().encode()
        body = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(body).to_bytes(8, "big"))
        digest.update(body)
    return digest.hexdigest()


@cache
def _harness_identity() -> dict:
    """Identify the packaged runtime that persisted a result.

    The digest is diagnostic provenance, not a claim that mutable external dependencies can be
    recreated byte-for-byte.
    """
    root = package_root()
    settings = get_settings()
    try:
        harness_version = version("infosec-harness")
    except PackageNotFoundError:  # pragma: no cover - editable/test installs have metadata
        harness_version = "unknown"
    return {
        "identity_scope": "persistence_worker",
        "version": harness_version,
        "git_commit_sha": settings.git_commit_sha or None,
        "worker_build_id": settings.worker_build_id or None,
        "packaged_source_sha256": _files_digest(root, [
            path for path in root.rglob("*")
            if path.is_file() and "__pycache__" not in path.parts
            and path.suffix in {".py", ".yaml", ".yml", ".json", ".md"}]),
    }


def persisted_manifest(manifest: dict) -> dict:
    """Add worker-host provenance immediately before evidence is persisted.

    Workflow code builds ``manifest`` only from its serialized inputs. The persistence
    activity calls this function outside the Temporal workflow sandbox, so source-file and
    deployment identity never become workflow I/O or replay inputs.
    """
    return {**manifest, "schema_version": MANIFEST_SCHEMA_VERSION,
            "harness": dict(_harness_identity())}
