"""Combined target observation preserves the existing read-only boundary."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic_ai import ModelRetry

from infosec_harness.agents.capabilities import DEFAULT_REPO_RO_TOOLS, REPO_RO_TOOLS
from infosec_harness.agents.deps import AgentDeps
from infosec_harness.agents.target_context import MAX_TARGET_CONTEXT_BYTES, inspect_target


def context(root: Path) -> SimpleNamespace:
    return SimpleNamespace(deps=AgentDeps(repo_path=str(root)))


def test_target_inspection_combines_binding_and_numbered_source_without_execution(tmp_path):
    source = tmp_path / "target.py"
    source.write_text("raise RuntimeError('must not execute')\ndef lookup(value):\n    return value + 1\n")
    result = inspect_target(context(tmp_path), "target.py")
    assert "lookup" in result and "from target import lookup" in result
    assert "return value + 1" in result and "Numbered source" in result
    assert "untrusted data" in result


@pytest.mark.parametrize("path", ["../outside.py", "/etc/passwd"])
def test_target_inspection_cannot_escape_snapshot(tmp_path, path):
    with pytest.raises(ModelRetry):
        inspect_target(context(tmp_path), path)


def test_target_inspection_rejects_symlink_escape(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("def secret(): return 'private'\n")
    (root / "target.py").symlink_to(outside)
    with pytest.raises(ModelRetry):
        inspect_target(context(root), "target.py")


def test_target_context_truncation_is_explicit_and_byte_bounded(tmp_path):
    (tmp_path / "target.py").write_text("# " + "é" * 40_000 + "\ndef lookup(): return 1\n")
    result = inspect_target(context(tmp_path), "target.py")
    assert "truncated" in result
    assert len(result.encode()) <= MAX_TARGET_CONTEXT_BYTES


def test_target_context_is_opt_in_and_does_not_expand_default_tools():
    assert "inspect_target" in REPO_RO_TOOLS
    assert "inspect_target" not in DEFAULT_REPO_RO_TOOLS


def test_target_inspection_reads_the_file_once(tmp_path, monkeypatch):
    """Both sections come from one bounded read, so they describe the same bytes."""
    from infosec_harness.agents import repo_tools, target_context

    (tmp_path / "target.py").write_text("def lookup(value):\n    return value + 1\n")
    reads = []
    real = repo_tools._read_capped

    def counting(target):
        reads.append(target)
        return real(target)

    monkeypatch.setattr(target_context, "_read_capped", counting)
    inspect_target(context(tmp_path), "target.py")
    assert len(reads) == 1


def test_each_section_is_clipped_with_its_own_marker(tmp_path):
    from infosec_harness.agents.target_context import _SECTION_BYTES

    (tmp_path / "wide.py").write_text("".join(f"x{i} = '{'y' * 200}'\n" for i in range(300)))
    result = inspect_target(context(tmp_path), "wide.py")
    source = result.split("## Numbered source\n", 1)[1]
    assert source.endswith("\n[truncated: request a smaller range]")
    assert len(source.encode()) <= _SECTION_BYTES + len("\n[truncated: request a smaller range]")
