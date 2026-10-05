from __future__ import annotations

import asyncio
import os
import subprocess
from pathlib import Path

import pytest

from infosec_harness.domain.canonical import canonical_bytes, digest
from infosec_harness.domain.models import (
    BuildResult,
    EnvironmentSpec,
    Finding,
    FindingInput,
    PreparedEnvironment,
    RepoRef,
    RepoSnapshot,
    SmokeResult,
    SourceMode,
    StackFingerprint,
)
from infosec_harness.graph.manifests import execution_manifest
from infosec_harness.persistence.identity import persisted_manifest
from infosec_harness.repo import checkout as checkout_module
from infosec_harness.repo.access import RepositoryAccessError
from infosec_harness.repo.checkout import checkout
from infosec_harness.sandbox.profiles import ADAPTER_CONTRACT_VERSION
from infosec_harness.settings import get_settings


@pytest.fixture
def snapshot_workspace(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    monkeypatch.setattr(checkout_module, "workspace_dir", lambda: workspace)
    # Local sources are admitted only beneath operator-approved roots.
    monkeypatch.setattr(get_settings(), "local_repo_roots", [tmp_path])
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


def _republish(snapshot_path: str, mutate) -> Path:
    """Rewrite a published snapshot wrapper in place, as an older or tampered workspace would."""
    tree = Path(snapshot_path)
    wrapper = tree.parent
    checkout_module._make_writable_for_cleanup(wrapper)
    mutate(tree, wrapper)
    checkout_module._make_read_only(wrapper)
    return wrapper


async def test_existing_snapshot_is_reused_only_after_its_tree_is_rehashed(
    snapshot_workspace, tmp_path
):
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.py").write_text("print('x')\n")
    ref = RepoRef(repo_url=str(source), source_mode="working_snapshot")
    first = await checkout(ref)
    second = await checkout(ref)
    assert second.path == first.path and second.file_count == first.file_count

    # Same identity name, different bytes: the name is not trusted.
    _republish(first.path, lambda tree, _wrapper: (tree / "a.py").write_text("tampered\n"))
    with pytest.raises(RuntimeError, match="identity collision"):
        await checkout(ref)


async def test_a_snapshot_in_the_old_direct_directory_layout_is_not_reused(
    snapshot_workspace, tmp_path
):
    """No compatibility shape: a wrapper without ``tree/`` fails closed instead of being
    re-hashed as a second candidate layout."""
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.py").write_text("print('x')\n")
    ref = RepoRef(repo_url=str(source), source_mode="working_snapshot")
    first = await checkout(ref)

    def flatten(tree: Path, wrapper: Path) -> None:
        legacy = wrapper.with_name(wrapper.name + "-legacy")
        tree.rename(legacy)
        wrapper.rmdir()
        legacy.rename(wrapper)

    _republish(first.path, flatten)
    with pytest.raises(RuntimeError, match="identity collision"):
        await checkout(ref)


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
    identity = digest({
        "repo": "/repo", "rev": "HEAD", "file": None, "line": None, "cwe": None,
        "title": "SQL injection", "ext": None,
    })

    assert Finding.compute_fingerprint(finding) == identity[:24]
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
            log_artifact="sha256:" + "c" * 64,
            duration_s=4.25,
            error_excerpt="PRIVATE_TOKEN=do-not-persist",
        ),
        smoke=SmokeResult(ok=True, output_excerpt="PRIVATE_TOKEN=do-not-persist"),
        status="ready",
        attempts=2,
        reason="validated",
    )

    workflow_manifest = execution_manifest(prepared)
    # The schema version is assigned once, when the manifest is persisted.
    assert "schema_version" not in workflow_manifest
    assert "harness" not in workflow_manifest
    manifest = persisted_manifest(workflow_manifest)
    assert manifest["environment"]["adapter_contract_version"] == ADAPTER_CONTRACT_VERSION
    assert manifest["environment"]["adapter_profiles"] == {
        "profiles": [
            {"id": "python-unit-probe", "support": "experimental"}
        ],
        "unmapped_languages": [],
    }

    assert manifest["source"]["content_hash"] == "a" * 64
    assert manifest["environment"]["env_names"] == ["PRIVATE_TOKEN"]
    assert manifest["schema_version"] == 3
    assert manifest["harness"]["identity_scope"] == "persistence_worker"
    assert manifest["harness"]["version"]
    assert len(manifest["harness"]["packaged_source_sha256"]) == 64
    assert manifest["preparation"] == {
        "status": "ready",
        "attempts": 2,
        "reason": "validated",
        "build": {
            "ok": True,
            "image_tag": "harness-target:abc",
            "duration_s": 4.25,
            "log_artifact": "sha256:" + "c" * 64,
        },
        "smoke": {"ok": True},
    }
    assert b"do-not-persist" not in canonical_bytes(manifest)


async def test_local_source_outside_approved_roots_is_rejected(tmp_path, monkeypatch):
    repo = tmp_path / "unapproved"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n")
    monkeypatch.setattr(get_settings(), "local_repo_roots", [tmp_path / "approved"])
    for url in (str(repo), f"file://{repo}"):
        with pytest.raises(ValueError, match="local_repo_roots"):
            await checkout(RepoRef(repo_url=url, source_mode="working_snapshot"))
    monkeypatch.setattr(get_settings(), "local_repo_roots", [])
    with pytest.raises(ValueError, match="local_repo_roots"):
        await checkout(RepoRef(repo_url=str(repo), source_mode="working_snapshot"))


@pytest.mark.parametrize("url", ["ssh://example.invalid/r.git", "git@example.invalid:r.git",
                                 "ext::sh -c touch% /tmp/pwned", "--upload-pack=touch /tmp/x",
                                 "http://example.invalid/r.git"])
async def test_only_https_remote_sources_are_admitted(snapshot_workspace, url):
    with pytest.raises(ValueError, match="https"):
        await checkout(RepoRef(repo_url=url, revision="HEAD"))


@pytest.mark.parametrize("revision", ["--output=/tmp/x", "-b", "main\nmore"])
async def test_option_like_revisions_are_rejected_before_git(snapshot_workspace, tmp_path, revision):
    repo = tmp_path / "repo"
    repo.mkdir()
    with pytest.raises(ValueError, match="revision"):
        await checkout(RepoRef(repo_url=str(repo), revision=revision))


async def test_git_runs_with_controlled_config_and_without_ambient_credentials(
        snapshot_workspace, tmp_path, monkeypatch):
    seen = {}

    async def capture(argv, *, env, **_kwargs):
        seen["argv"], seen["env"] = argv, env
        from infosec_harness.sandbox.process import ProcessResult
        return ProcessResult(0, "", "", False, 0.0)

    monkeypatch.setenv("GIT_ASKPASS", "/ambient/askpass")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/ambient/agent.sock")
    monkeypatch.setenv("IH_PROVIDER_SECRET", "must-not-reach-git")
    monkeypatch.setattr(checkout_module, "run_bounded", capture)
    await checkout_module._git("clone", "--", "https://example.invalid/r.git", "dest")
    argv, env = seen["argv"], seen["env"]
    assert argv[0] == "git" and "protocol.allow=never" in argv
    assert "protocol.https.allow=always" in argv and "protocol.file.allow=always" not in argv
    assert "credential.helper=" in argv and "core.fsmonitor=false" in argv
    assert argv[-3:] == ["--", "https://example.invalid/r.git", "dest"]
    assert env["GIT_CONFIG_NOSYSTEM"] == "1" and env["GIT_ASKPASS"] == ""
    assert "SSH_AUTH_SOCK" not in env and "IH_PROVIDER_SECRET" not in env
