"""Secret-free identities needed to reproduce one triage result."""

from __future__ import annotations

import hashlib
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from infosec_harness.agents.ecosystem_contract import ADAPTER_CONTRACT_VERSION
from infosec_harness.agents.ecosystem_profiles import profile_manifest
from infosec_harness.domain.models import (
    PreparedEnvironment,
    RepoSnapshot,
    StackFingerprint,
    canonical_json,
    sha256_text,
)
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


def source_manifest(snapshot: RepoSnapshot, stack: StackFingerprint | None = None) -> dict:
    source = {
        "requested_revision": snapshot.revision,
        "resolved_commit": snapshot.resolved_commit,
        "source_mode": snapshot.source_mode.value,
        "content_hash": snapshot.content_hash,
        "exclusion_policy_hash": snapshot.exclusion_policy_hash,
        "file_count": snapshot.file_count,
        "git_dirty": snapshot.git_dirty,
        "submodule_policy": snapshot.submodule_policy,
        "lfs_policy": snapshot.lfs_policy,
    }
    manifest = {"schema_version": 1, "source": source}
    if stack is not None:
        manifest["stack_digest"] = sha256_text(canonical_json(stack))
    return manifest


def execution_manifest(prepared: PreparedEnvironment) -> dict:
    """Describe source and environment identities without storing env values or credentials."""
    manifest = source_manifest(prepared.snapshot, prepared.stack)
    spec = prepared.build.spec if prepared.build is not None else None
    environment = {
        "adapter_contract_version": ADAPTER_CONTRACT_VERSION,
        "adapter_profiles": profile_manifest(prepared.stack.languages),
        "status": prepared.status,
        "image_tag": prepared.build.image_tag if prepared.build is not None else None,
        "spec_digest": sha256_text(canonical_json(spec)) if spec is not None else None,
    }
    if spec is not None:
        environment.update({
            "base_image": spec.base_image,
            "scope": spec.scope,
            "module_path": spec.module_path,
            "env_names": sorted(spec.env),
            "install_command_digests": [sha256_text(command) for command in spec.install_commands],
            "test_command_digest": sha256_text(spec.test_command),
        })
    manifest["environment"] = environment
    manifest["preparation"] = {
        "status": prepared.status,
        "attempts": prepared.attempts,
        "reason": prepared.reason,
        "build": None if prepared.build is None else {
            "ok": prepared.build.ok,
            "image_tag": prepared.build.image_tag,
            "duration_s": prepared.build.duration_s,
            "log_artifact": prepared.build.log_artifact,
        },
        "smoke": None if prepared.smoke is None else {
            "ok": prepared.smoke.ok,
        },
    }
    return manifest
