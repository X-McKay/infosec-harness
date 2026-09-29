"""Deterministic checks for the repository's developer-facing generated artifacts."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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

    script = Path(__file__).resolve().parents[1] / "scripts/sync_dev_skills.py"
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
