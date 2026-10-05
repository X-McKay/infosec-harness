"""Secret-free identities needed to reproduce one triage result."""

from __future__ import annotations

from infosec_harness.agents.ecosystem_contract import ADAPTER_CONTRACT_VERSION
from infosec_harness.agents.ecosystem_profiles import profile_manifest
from infosec_harness.domain.models import (
    PreparedEnvironment,
    RepoSnapshot,
    StackFingerprint,
    canonical_json,
    sha256_text,
)


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
