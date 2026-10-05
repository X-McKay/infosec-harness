"""Deterministic checks for the repository's developer-facing entry points."""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_claude_instructions_are_the_shared_instructions():
    """CLAUDE.md imports AGENTS.md rather than copying it, so there is one source to edit."""
    assert (ROOT / "CLAUDE.md").read_text().strip() == "@AGENTS.md"
    assert (ROOT / "AGENTS.md").is_file()


def test_codex_discovers_the_same_development_skills_as_claude():
    """`.agents/skills` is a symlink to `.claude/skills`; there is one copy of each skill."""
    codex = ROOT / ".agents" / "skills"
    claude = ROOT / ".claude" / "skills"
    assert codex.is_symlink() and codex.resolve() == claude.resolve()
    skills = sorted(p.parent.name for p in claude.glob("*/SKILL.md"))
    assert skills, "no development skills found"
    assert sorted(p.parent.name for p in codex.glob("*/SKILL.md")) == skills
    assert not (ROOT / "dev-skills").exists()


def test_launcher_exposes_safe_commands_without_starting_services():
    result = subprocess.run([str(ROOT / "dev"), "--help"], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0
    assert "offline" in result.stdout
    assert "preserves this checkout" in result.stdout
    assert "volumes" in result.stdout


def _log_snapshot_function() -> str:
    """Exercise the launcher's shell function with a fake compose process, without bootstrapping."""
    text = (ROOT / "dev").read_text()
    return "save_logs() {" + text.split("save_logs() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"


def test_log_snapshots_are_unique_private_and_keep_compose_failures(tmp_path):
    import stat

    shell = "set -euo pipefail\n" + _log_snapshot_function() + '''
SERVICE=worker
compose() {
  [[ "$*" == "logs --no-color --timestamps --tail=100 worker" ]] || return 99
  echo "worker: fixture output"
}
save_logs
save_logs
'''
    result = subprocess.run(["bash", "-c", shell], cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    snapshots = list((tmp_path / ".harness/logs").iterdir())
    assert len(snapshots) == 2
    for path in snapshots:
        assert path.read_text() == "worker: fixture output\n"
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    failed = subprocess.run(
        ["bash", "-c", "set -euo pipefail\n" + _log_snapshot_function()
         + '\nSERVICE=""\ncompose() { echo "fixture failure" >&2; return 17; }\nsave_logs\n'],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert failed.returncode == 17
    assert "saved logs:" not in failed.stdout
    assert any(path.read_text() == "fixture failure\n"
               for path in (tmp_path / ".harness/logs").iterdir())
