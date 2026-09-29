from __future__ import annotations

import asyncio
import os
import subprocess
from pathlib import Path

import pytest

from infosec_harness.domain.models import (
    BuildResult,
    EnvironmentSpec,
    Finding,
    FindingInput,
    PreparedEnvironment,
    RepoRef,
    RepoSnapshot,
    SourceMode,
    StackFingerprint,
    canonical_json,
    sha256_text,
)
from infosec_harness.graph.manifests import execution_manifest
from infosec_harness.repo import checkout as checkout_module
from infosec_harness.repo.access import RepositoryAccessError
from infosec_harness.repo.checkout import checkout


@pytest.fixture
def snapshot_workspace(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    monkeypatch.setattr(checkout_module, "default_workspace", lambda: workspace)
    return workspace


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, text=True,
                          capture_output=True).stdout.strip()


async def test_local_git_revision_is_materialized_instead_of_current_files(
    tmp_path, snapshot_workspace
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "Test")
    (repo / "value.txt").write_text("old\n")
    _git(repo, "add", "value.txt")
    _git(repo, "commit", "-m", "old")
    old = _git(repo, "rev-parse", "HEAD")
    (repo / "value.txt").write_text("dirty working tree\n")

    snapshot = await checkout(RepoRef(repo_url=str(repo), revision=old))

    assert snapshot.source_mode is SourceMode.git_revision
    assert snapshot.resolved_commit == old
    assert Path(snapshot.path, "value.txt").read_text() == "old\n"

    working = await checkout(RepoRef(
        repo_url=str(repo), source_mode=SourceMode.working_snapshot
    ))
    assert working.resolved_commit is None
    assert working.git_dirty is True
    assert Path(working.path, "value.txt").read_text() == "dirty working tree\n"


async def test_nonexistent_local_revision_fails(snapshot_workspace, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    with pytest.raises(RuntimeError, match="git checkout"):
        await checkout(RepoRef(repo_url=str(repo), revision="does-not-exist",
                               source_mode=SourceMode.git_revision))


async def test_working_snapshot_allows_internal_file_link_and_rejects_external_link(
    snapshot_workspace, tmp_path
):
    source = tmp_path / "source"
    source.mkdir()
    (source / "real.txt").write_text("inside\n")
    (source / "link.txt").symlink_to("real.txt")
    internal = await checkout(RepoRef(repo_url=str(source), source_mode="working_snapshot"))
    assert Path(internal.path, "link.txt").read_text() == "inside\n"

    outside = tmp_path / "outside.txt"
    outside.write_text("secret\n")
    (source / "outside-link.txt").symlink_to(outside)
    with pytest.raises(RepositoryAccessError, match="unsafe repository link"):
        await checkout(RepoRef(repo_url=str(source), source_mode="working_snapshot"))


async def test_concurrent_materialization_shares_one_immutable_destination(
    snapshot_workspace, tmp_path
):
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.py").write_text("print('x')\n")
    ref = RepoRef(repo_url=str(source), source_mode="working_snapshot")

    first, second = await asyncio.gather(checkout(ref), checkout(ref))

    assert first.path == second.path
    assert first.content_hash == second.content_hash
    assert not os.access(first.path, os.W_OK)


async def test_existing_direct_directory_snapshot_is_verified_and_reused(
    snapshot_workspace, tmp_path
):
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.py").write_text("print('x')\n")
    ref = RepoRef(repo_url=str(source), source_mode="working_snapshot")
    first = await checkout(ref)
    tree = Path(first.path)
    wrapper = tree.parent
    legacy = wrapper.with_name(wrapper.name + "-legacy")
    checkout_module._make_writable_for_cleanup(wrapper)
    tree.rename(legacy)
    wrapper.rmdir()
    legacy.rename(wrapper)
    checkout_module._make_read_only(wrapper)

    second = await checkout(ref)

    assert Path(second.path) == wrapper
    assert second.content_hash == first.content_hash


async def test_exclusion_policy_participates_in_snapshot_identity(snapshot_workspace, tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "kept.txt").write_text("same bytes\n")

    one = await checkout(RepoRef(repo_url=str(source), source_mode="working_snapshot",
                                 exclude_paths=["absent-one.txt"]))
    two = await checkout(RepoRef(repo_url=str(source), source_mode="working_snapshot",
                                 exclude_paths=["absent-two.txt"]))

    assert one.content_hash == two.content_hash
    assert one.exclusion_policy_hash != two.exclusion_policy_hash
    assert one.path != two.path


async def test_generated_output_directory_is_captured_as_source(snapshot_workspace, tmp_path):
    source = tmp_path / "source"
    (source / "dist").mkdir(parents=True)
    (source / "dist" / "shipped.js").write_text("export const shipped = true;\n")

    snapshot = await checkout(RepoRef(
        repo_url=str(source), source_mode=SourceMode.working_snapshot
    ))

    assert Path(snapshot.path, "dist", "shipped.js").is_file()


def test_omitted_source_mode_preserves_legacy_finding_identity():
    finding = FindingInput(title="SQL injection", repo_url="/repo", revision="HEAD")
    legacy_key = canonical_json({
        "repo": "/repo", "rev": "HEAD", "file": None, "line": None, "cwe": None,
        "title": "SQL injection", "ext": None,
    })

    assert Finding.compute_fingerprint(finding) == sha256_text(legacy_key)[:24]
    assert Finding.compute_fingerprint(
        finding.model_copy(update={"source_mode": SourceMode.working_snapshot})
    ) != Finding.compute_fingerprint(finding)


def test_exclusion_never_follows_an_intermediate_link(tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "victim.txt"
    victim.write_text("keep me\n")
    (tree / "linked-dir").symlink_to(outside, target_is_directory=True)

    checkout_module._remove_excluded(tree, ["linked-dir/victim.txt"])

    assert victim.read_text() == "keep me\n"


def test_execution_manifest_records_identities_without_environment_values(tmp_path):
    snapshot = RepoSnapshot(
        repo_url=str(tmp_path), revision="HEAD", path=str(tmp_path), content_hash="a" * 64,
        exclusion_policy_hash="b" * 64,
    )
    prepared = PreparedEnvironment(
        snapshot=snapshot,
        stack=StackFingerprint(languages={"python": 1}),
        build=BuildResult(
            ok=True, image_tag="harness-target:abc", spec=EnvironmentSpec(
                base_image="python:3.12-slim", install_commands=["pip install -e ."],
                test_command="pytest {test_file}", env={"PRIVATE_TOKEN": "do-not-persist"},
            ),
        ),
        status="ready",
    )

    manifest = execution_manifest(prepared)
    assert manifest["environment"]["adapter_contract_version"] == "unit-probe-adapters/v1"
    assert manifest["environment"]["adapter_profiles"] == {
        "profiles": [
            {"id": "python-unit-probe", "version": "1", "support": "experimental"}
        ],
        "unmapped_languages": [],
    }

    assert manifest["source"]["content_hash"] == "a" * 64
    assert manifest["environment"]["env_names"] == ["PRIVATE_TOKEN"]
    assert "do-not-persist" not in canonical_json(manifest)
