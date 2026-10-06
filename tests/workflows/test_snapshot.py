from pathlib import Path

import pytest

from infosec_harness.config import Settings
from infosec_harness.contracts import Citation, Finding
from infosec_harness.workflows.snapshot import snapshot, validate_citation


@pytest.fixture
def source(tmp_path):
    repo = tmp_path / "source"
    repo.mkdir()
    (repo / "target.py").write_text("def target(value):\n    return value\n")
    settings = Settings(workspace_dir=tmp_path / "state", local_repo_roots=[repo])
    finding = Finding(title="finding", repo_url=str(repo), source_mode="working_snapshot")
    return repo, settings, finding


async def test_capture_is_immutable_and_retry_reuses_same_source(source):
    repo, settings, finding = source
    captured = await snapshot(finding, "run", settings)
    (repo / "target.py").write_text("changed upstream\n")
    retried = await snapshot(finding, "run", settings)
    assert retried == captured
    assert Path(captured.path, "target.py").read_text().startswith("def target")
    assert not Path(captured.path, "target.py").stat().st_mode & 0o222
    assert await snapshot(finding, "different-run", settings) != captured


async def test_outside_operator_root_is_rejected(source, tmp_path):
    _, settings, finding = source
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(ValueError, match="operator-approved"):
        await snapshot(finding.model_copy(update={"repo_url": str(outside)}), "run", settings)


@pytest.mark.parametrize("kind", ["file", "directory"])
async def test_symlinks_never_import_external_bytes(source, tmp_path, kind):
    repo, settings, finding = source
    secret = tmp_path / "secret"
    secret.write_text("not source")
    (repo / "escape").symlink_to(tmp_path if kind == "directory" else secret)
    with pytest.raises((ValueError, OSError)):
        await snapshot(finding, "run", settings)
    assert secret.read_text() == "not source"


async def test_snapshot_corruption_is_detected_before_reuse(source):
    _, settings, finding = source
    captured = await snapshot(finding, "run", settings)
    target = Path(captured.path, "target.py")
    target.chmod(0o644)
    target.write_text("tampered")
    with pytest.raises(ValueError, match="mismatch"):
        await snapshot(finding, "run", settings)


async def test_identity_cannot_be_reassigned_to_another_finding(source):
    _, settings, finding = source
    await snapshot(finding, "run", settings)
    with pytest.raises(ValueError, match="mismatch"):
        await snapshot(finding.model_copy(update={"title": "different"}), "run", settings)


async def test_size_limit_fails_before_publication(source, monkeypatch):
    import infosec_harness.workflows.snapshot as repository

    _, settings, finding = source
    monkeypatch.setattr(repository, "MAX_FILE", 3)
    with pytest.raises(ValueError, match="bounded regular"):
        await snapshot(finding, "run", settings)


@pytest.mark.parametrize(
    "url",
    ["http://example.org/repo", "https://user:secret@example.org/repo", "ssh://example.org/repo"],
)
async def test_unsafe_remote_rejected_without_git(source, url):
    _, settings, finding = source
    with pytest.raises(ValueError, match="HTTPS"):
        await snapshot(
            finding.model_copy(update={"repo_url": url, "source_mode": "git_revision"}),
            "run",
            settings,
        )


def test_citation_must_exist_inside_exact_source(source):
    repo, _, _ = source
    assert (
        validate_citation(repo, Citation(path="target.py", start_line=1, end_line=2)).path
        == "target.py"
    )
    with pytest.raises(ValueError, match="exceeds"):
        validate_citation(repo, Citation(path="target.py", start_line=1, end_line=3))
    with pytest.raises(ValueError, match="relative"):
        validate_citation(repo, Citation(path="../secret", start_line=1, end_line=1))


async def test_approved_source_ancestor_substitution_never_imports_external_bytes(
    tmp_path, monkeypatch
):
    import infosec_harness.workflows.snapshot as repository

    admitted = tmp_path / "admitted"
    source = admitted / "repository" / "nested"
    source.mkdir(parents=True)
    (source / "target.py").write_text("approved source")
    external = tmp_path / "external"
    (external / "nested").mkdir(parents=True)
    (external / "nested" / "secret").write_text("must not be captured")
    settings = Settings(workspace_dir=tmp_path / "state", local_repo_roots=[admitted])
    finding = Finding(title="finding", repo_url=str(source), source_mode="working_snapshot")
    original_capture = repository._capture
    swapped = False

    def capture(path, destination):
        nonlocal swapped
        if not swapped:
            swapped = True
            source.parent.rename(admitted / "original")
            source.parent.symlink_to(external, target_is_directory=True)
        return original_capture(path, destination)

    monkeypatch.setattr(repository, "_capture", capture)
    with pytest.raises((ValueError, OSError)):
        await snapshot(finding, "run", settings)
    assert not list((settings.workspace_dir / "sources").glob("*/tree/secret"))


def _commit(repo: Path, home: Path, content: str, message: str) -> str:
    import os
    import subprocess

    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home),
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "LC_ALL": "C"}

    def git(*args):
        return subprocess.run(
            ["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
             "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", *args],
            cwd=repo, env=env, check=True, capture_output=True, text=True, timeout=30,
        ).stdout.strip()

    if not (repo / ".git").exists():
        git("init", "-q")
    (repo / "target.py").write_text(content)
    git("add", "target.py")
    git("commit", "-q", "-m", message)
    return git("rev-parse", "HEAD")


async def test_git_revision_captures_the_committed_tree_from_a_local_repository(tmp_path):
    """The default source mode: a bounded clone and detached checkout, no repository code."""
    repo = tmp_path / "repository"
    repo.mkdir()
    first = _commit(repo, tmp_path, "first = 1\n", "first")
    _commit(repo, tmp_path, "second = 2\n", "second")
    (repo / "target.py").write_text("uncommitted = 3\n")
    (repo / "untracked.py").write_text("never captured\n")
    settings = Settings(workspace_dir=tmp_path / "state", local_repo_roots=[repo])
    finding = Finding(title="finding", repo_url=str(repo), revision=first)
    assert finding.source_mode == "git_revision"
    pinned = await snapshot(finding, "pinned", settings)
    assert Path(pinned.path, "target.py").read_text() == "first = 1\n"
    assert sorted(path.name for path in Path(pinned.path).iterdir()) == ["target.py"]
    head = await snapshot(finding.model_copy(update={"revision": "HEAD"}), "head", settings)
    assert Path(head.path, "target.py").read_text() == "second = 2\n"
    assert head.digest != pinned.digest
    # A retry of the same run reuses the published snapshot after re-hashing it.
    assert await snapshot(finding, "pinned", settings) == pinned


@pytest.mark.parametrize("revision", ["-c core.pager=x", "main\nother"])
async def test_git_revision_refuses_option_or_multiline_revisions(tmp_path, revision):
    repo = tmp_path / "repository"
    repo.mkdir()
    _commit(repo, tmp_path, "first = 1\n", "first")
    settings = Settings(workspace_dir=tmp_path / "state", local_repo_roots=[repo])
    finding = Finding(title="finding", repo_url=str(repo), revision=revision)
    with pytest.raises(ValueError, match="invalid revision"):
        await snapshot(finding, "run", settings)


async def test_unknown_git_revision_fails_without_publishing(tmp_path):
    repo = tmp_path / "repository"
    repo.mkdir()
    _commit(repo, tmp_path, "first = 1\n", "first")
    settings = Settings(workspace_dir=tmp_path / "state", local_repo_roots=[repo])
    finding = Finding(title="finding", repo_url=str(repo), revision="0" * 40)
    with pytest.raises(RuntimeError, match="source checkout failed"):
        await snapshot(finding, "run", settings)
    assert not list((settings.workspace_dir / "sources").iterdir())
