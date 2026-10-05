"""Worker-host provenance added to evidence at the moment it is persisted.

Computed once at import on the persisting host, never inside workflow code: source-file and
deployment identity must not become workflow I/O or replay inputs.
"""

from __future__ import annotations

import hashlib
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from infosec_harness.resources import package_root
from infosec_harness.settings import get_settings


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


def _runtime_digests() -> dict[str, str]:
    """Identify the packaged runtime and the policy-bearing subsets used by a run.

    This is evaluated eagerly while the module crosses Temporal's ``imports_passed_through``
    boundary, so the filesystem work happens on the worker host rather than as workflow I/O.
    The digest is diagnostic provenance, not a claim that mutable external dependencies can be
    recreated byte-for-byte.
    """
    root = package_root()
    runtime_files = [
        path for path in root.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
        and path.suffix in {".py", ".yaml", ".yml", ".json", ".md"}
    ]
    graph_files = [path for path in (root / "graph").glob("*.py") if path.is_file()]
    graph_files.extend(path for path in (root / "workflows").glob("*.py") if path.is_file())
    verdict_files = [
        root / "agents" / "validators.py",
        root / "agents" / "verdict" / "agent.yaml",
        root / "graph" / "scoring.py",
        root / "graph" / "triage.py",
    ]
    return {
        "packaged_source_sha256": _files_digest(root, runtime_files),
        "graph_policy_sha256": _files_digest(root, graph_files),
        "verdict_policy_sha256": _files_digest(root, verdict_files),
    }


def _load_harness_identity() -> dict:
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
        **_runtime_digests(),
    }


_HARNESS_IDENTITY = _load_harness_identity()


def _harness_identity() -> dict:
    """Return a copy so one result cannot mutate the worker's recorded identity."""
    return dict(_HARNESS_IDENTITY)


def persisted_manifest(manifest: dict) -> dict:
    """Add worker-host provenance immediately before evidence is persisted.

    Workflow code builds ``manifest`` only from its serialized inputs.  The persistence
    activity/local repository layer calls this function outside the Temporal workflow sandbox,
    so source-file and deployment identity never become workflow I/O or replay inputs.
    """
    return {**manifest, "schema_version": 2, "harness": _harness_identity()}
