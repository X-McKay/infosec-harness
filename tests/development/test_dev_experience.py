"""Deterministic checks for the repository's developer-facing generated artifacts."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def run_script(script: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / script), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_generated_development_artifacts_are_in_sync():
    instructions = run_script("sync_dev_instructions.py", "check")
    skills = run_script("sync_dev_skills.py", "check")
    assert instructions.returncode == 0, instructions.stdout + instructions.stderr
    assert skills.returncode == 0, skills.stdout + skills.stderr


def test_launcher_exposes_safe_commands_without_starting_services():
    result = subprocess.run([str(ROOT / "dev"), "--help"], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0
    assert "offline" in result.stdout
    assert "preserves this checkout" in result.stdout
    assert "volumes" in result.stdout


def test_matching_copies_do_not_hide_stale_canonical_digest(tmp_path, monkeypatch):
    import importlib.util
    import shutil

    script = Path(__file__).resolve().parents[2] / "scripts/sync_dev_skills.py"
    spec = importlib.util.spec_from_file_location("skill_sync", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source = tmp_path / "dev-skills"
    destinations = (tmp_path / "codex", tmp_path / "claude")
    skill = source / "sample" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("---\nname: sample\nmetadata:\n  content_digest: stale\n---\nNew procedure.\n")
    for destination in destinations:
        shutil.copytree(source, destination)
    monkeypatch.setattr(module, "SOURCE", source)
    monkeypatch.setattr(module, "DESTINATIONS", destinations)
    assert any("canonical content digest drift" in error for error in module.check())
    module.sync()
    assert module.check() == []


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
