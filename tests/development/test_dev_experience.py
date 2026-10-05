"""Deterministic checks for the repository's developer-facing entry points."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

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


# --- One pin source --------------------------------------------------------------------------

def _mise_tools() -> dict[str, str]:
    import tomllib

    tools = tomllib.loads((ROOT / ".mise.toml").read_text())["tools"]
    return {name: value if isinstance(value, str) else value["version"]
            for name, value in tools.items()}


def test_mise_toml_is_the_only_tool_version_source():
    """versions.env keeps only what mise cannot manage; nothing else re-types a tool version."""
    tools = _mise_tools()
    assert {"python", "uv", "node", "just", "http:temporal"} <= tools.keys()
    keys = {line.split("=", 1)[0] for line in (ROOT / ".dev-tools/versions.env").read_text()
            .splitlines() if "=" in line and not line.startswith("#")}
    assert keys == {"MISE_VERSION", "MISE_MACOS_ARM64_SHA256", "MISE_LINUX_X64_SHA256",
                    "LIMA_VERSION", "LIMA_MACOS_ARM64_SHA256", "LIMA_LINUX_X64_SHA256"}
    for path in ("scripts/dev_setup.py", "dev", "justfile", ".github/workflows/ci.yml"):
        text = (ROOT / path).read_text()
        for name, version in tools.items():
            assert version not in text, f"{path} re-types the {name} pin {version}"


def test_temporal_cli_is_pinned_with_a_hash_for_every_supported_host():
    import tomllib

    temporal = tomllib.loads((ROOT / ".mise.toml").read_text())["tools"]["http:temporal"]
    platforms = temporal["platforms"]
    # ./dev supports exactly macOS Apple Silicon and Linux x86-64 (dev_setup.supported_platform).
    assert set(platforms) == {"macos-arm64", "linux-x64"}
    for entry in platforms.values():
        assert entry["url"].startswith("https://github.com/temporalio/cli/releases/download/")
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", entry["checksum"])


def test_images_derive_from_the_mise_pins_and_are_digest_pinned():
    tools = _mise_tools()
    dockerfile = (ROOT / "Dockerfile").read_text()
    sources = re.findall(r"^FROM (\S+)", dockerfile, re.MULTILINE)
    images = sources + re.findall(
        r"^\s+image: (\S+)", (ROOT / "docker-compose.yml").read_text()
        + (ROOT / "docker-compose.dev.yml").read_text(), re.MULTILINE)
    for image in images:
        assert re.fullmatch(r"[\w./-]+:[\w.-]+@sha256:[0-9a-f]{64}", image), image
        assert ":latest@" not in image, image
    tags = {image.split("@")[0].rsplit(":", 1)[0]: image.split("@")[0].rsplit(":", 1)[1]
            for image in images}
    assert tags["python"] == f"{tools['python']}-slim"
    assert tags["ghcr.io/astral-sh/uv"] == tools["uv"]
    assert tags["node"] == f"{tools['node']}-slim"
    assert "pip install uv" not in dockerfile and "uv==" not in dockerfile


def test_image_docker_clients_match_the_vm_daemon_and_buildx():
    """The backend image's Docker CLI and Buildx are the versions the managed VM provisions."""
    lima = (ROOT / "deploy/dev-runtime/lima.yaml").read_text()
    daemon = re.search(r"^\s+docker_version=(\S+)", lima, re.MULTILINE).group(1)
    buildx = re.search(r"^\s+buildx_version=(\S+)", lima, re.MULTILINE).group(1)
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert f"FROM docker:{daemon}-cli@" in dockerfile
    assert f"FROM docker/buildx-bin:{buildx}@" in dockerfile


def test_backend_image_takes_only_the_optional_ca_from_deploy():
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "COPY deploy" not in dockerfile
    ignored = (ROOT / ".dockerignore").read_text().splitlines()
    assert "deploy/*" in ignored and "!deploy/extra-ca.crt" in ignored


def test_ci_runs_the_justfile_recipes_with_the_pinned_tools():
    import yaml

    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    text = (ROOT / ".github/workflows/ci.yml").read_text()
    for forbidden in ("setup-uv", "setup-node", "--all-extras", " -k ", "for dataset in",
                      "ruff check", "pytest"):
        assert forbidden not in text, forbidden
    for job in workflow["jobs"].values():
        mise = [step for step in job["steps"] if "jdx/mise-action" in step.get("uses", "")]
        assert len(mise) == 1
        assert re.fullmatch(r"jdx/mise-action@[0-9a-f]{40}", mise[0]["uses"])
        assert mise[0]["with"]["sha256"] == "${{ steps.pins.outputs.mise-sha256 }}"
    backend = [step.get("run", "") for step in workflow["jobs"]["backend"]["steps"]]
    for recipe in ("bootstrap", "check", "generated-check", "test", "test-network",
                   "eval-adapters"):
        assert f"just {recipe}" in backend
    assert workflow["jobs"]["backend"]["env"]["HARNESS_TEST_REQUIRE_TEMPORAL"] == "1"
    assert workflow["env"]["UV_PYTHON_DOWNLOADS"] == "never"


def test_justfile_lints_scripts_and_never_rewrites_the_lock():
    text = (ROOT / "justfile").read_text()
    assert "ruff check src tests scripts" in text
    assert re.search(r"^test \*args:\n.*-m \"not network\"", text, re.MULTILINE)
    assert "uv sync --all-extras" not in text
    assert all("uv run --locked" in line for line in text.splitlines()
               if re.match(r"\s+.*\buv run\b", line))
    for removed in ("up", "down", "down-reset", "worker", "api", "web-build", "web-check"):
        assert not re.search(rf"^{removed}\b.*:", text, re.MULTILINE), removed
    assert not (ROOT / ".pre-commit-config.yaml").exists()


# --- ./dev argument handling under the target shell (/bin/bash, 3.2 on macOS) ----------------

def _fake_checkout(tmp_path):
    """A copy of ./dev whose mise and docker only record how they were called."""
    import hashlib
    import shutil

    shutil.copy(ROOT / "dev", tmp_path / "dev")
    bindir = tmp_path / ".harness" / "bin"
    bindir.mkdir(parents=True)
    log = tmp_path / "calls.log"
    recorder = ('#!/bin/sh\nprintf "%s|%s|%s|%s\\n" "$(basename "$0")" '
                '"${HARNESS_MODEL_MODE:-}" "${HARNESS_TEST_REQUIRE_TEMPORAL:-}" "$*" >> '
                f'"{log}"\n')
    for name in ("mise", "docker"):
        (bindir / name).write_text(recorder)
        (bindir / name).chmod(0o755)
    digest = hashlib.sha256((bindir / "mise").read_bytes()).hexdigest()
    (tmp_path / ".dev-tools").mkdir()
    (tmp_path / ".dev-tools/versions.env").write_text(
        f"MISE_VERSION=0\nMISE_MACOS_ARM64_SHA256={digest}\nMISE_LINUX_X64_SHA256={digest}\n")
    (tmp_path / ".harness/dev.env").write_text(
        "COMPOSE_PROJECT_NAME=harness-fixture\nHARNESS_API_PORT=8001\nHARNESS_WEB_PORT=8081\n")
    return log


def _dev(tmp_path, *args):
    import os

    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("HARNESS_", "MISE_"))}
    result = subprocess.run(["/bin/bash", str(tmp_path / "dev"), *args], cwd=tmp_path, env=env,
                            capture_output=True, text=True, timeout=30)
    log = tmp_path / "calls.log"
    calls = log.read_text().splitlines() if log.exists() else []
    if log.exists():
        log.unlink()
    return result, calls


@pytest.mark.parametrize(("args", "expected"), [
    # No validation options: an empty array under `set -u` used to abort bash 3.2.
    (["--profile", "offline", "validate"],
     ["mise|||exec -- uv run --locked python scripts/service_validation.py --offline"]),
    (["validate"],
     ["mise|||exec -- uv run --locked python scripts/service_validation.py --managed-worker "
      "--api-url http://127.0.0.1:8001 --web-url http://127.0.0.1:8081"]),
    (["validate", "--model", "--report", "r.json"],
     ["mise|||exec -- uv run --locked python scripts/service_validation.py --managed-worker "
      "--api-url http://127.0.0.1:8001 --web-url http://127.0.0.1:8081 --model --report r.json"]),
    (["check"], ["mise|||exec -- just check"]),
    (["test"], ["mise|stub|1|exec -- just test"]),
    (["logs", "--profile", "offline"],
     ["docker|||compose -f docker-compose.yml -f docker-compose.dev.yml --project-name "
      "harness-fixture --env-file .harness/dev.env logs --no-color --timestamps --tail=100"]),
    (["logs", "worker"],
     ["docker|||compose -f docker-compose.yml -f docker-compose.dev.yml --project-name "
      "harness-fixture --env-file .harness/dev.env logs --no-color --timestamps --tail=100 "
      "worker"]),
    (["stop"],
     ["docker|||compose -f docker-compose.yml -f docker-compose.dev.yml --project-name "
      "harness-fixture --env-file .harness/dev.env down"]),
    (["stop", "--vm"],
     ["docker|||compose -f docker-compose.yml -f docker-compose.dev.yml --project-name "
      "harness-fixture --env-file .harness/dev.env down",
      "mise|||exec -- python scripts/dev_setup.py stop-vm"]),
    (["reset"], ["mise|||exec -- python scripts/dev_setup.py reset"]),
    (["reset", "--yes"], ["mise|||exec -- python scripts/dev_setup.py reset --yes"]),
    (["gc"], ["mise|||exec -- python scripts/dev_setup.py gc"]),
    (["gc", "--delete"], ["mise|||exec -- python scripts/dev_setup.py gc --delete"]),
    (["--profile", "offline"],
     ["mise|||exec -- python scripts/dev_setup.py --profile offline",
      "mise|stub||exec -- just check",
      "mise|stub|1|exec -- just test"]),
])
def test_launcher_dispatch_under_the_target_shell(tmp_path, args, expected):
    _fake_checkout(tmp_path)
    result, calls = _dev(tmp_path, *args)
    assert result.returncode == 0, result.stderr
    assert calls == expected
    if args == ["--profile", "offline"]:
        assert "not_checked" in result.stdout and "just check" in result.stdout


@pytest.mark.parametrize("args", [
    ["check", "--vm"], ["stop", "--yes"], ["start", "--delete"], ["check", "--model"],
    ["--profile", "partial"], ["bogus"],
])
def test_launcher_rejects_misplaced_options_before_doing_anything(tmp_path, args):
    _fake_checkout(tmp_path)
    result, calls = _dev(tmp_path, *args)
    assert result.returncode == 2 and calls == []


def test_launcher_usage_lists_every_command_it_dispatches():
    text = (ROOT / "dev").read_text()
    dispatched = text.split('case "$1" in', 1)[1].split("esac", 1)[0]
    commands = re.search(r"\n\s+(start\|check\|[\w|-]+)\)", dispatched).group(1).split("|")
    usage = subprocess.run(["/bin/bash", str(ROOT / "dev"), "--help"], cwd=ROOT,
                           capture_output=True, text=True).stdout
    for command in [*commands, "logs"]:
        assert re.search(rf"^  {re.escape(command)}\b", usage, re.MULTILINE), command


# --- tests/conftest.py: fail-closed isolation and one gate per condition ---------------------

def _child_session(tmp_path, env_overrides):
    """Run a fixture test file under this repository's conftest in a clean environment."""
    import os
    import sys

    (tmp_path / "test_fixture.py").write_text(
        "import os\n"
        "def test_isolated():\n"
        "    assert os.environ['HARNESS_MODEL_MODE'] == 'stub'\n"
        "    assert os.environ['HARNESS_DATABASE_URL'].startswith('sqlite+aiosqlite:///')\n")
    env = {key: value for key, value in os.environ.items() if not key.startswith("HARNESS_")}
    env.update(PYTHONPATH=str(ROOT / "tests"), PYTHONDONTWRITEBYTECODE="1", **env_overrides)
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-p", "conftest",
         "-c", str(ROOT / "pyproject.toml"), "--rootdir", str(ROOT), str(tmp_path)],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120)


@pytest.mark.parametrize(("ambient", "refused"), [
    ({"HARNESS_MODEL_MODE": "live"}, "HARNESS_MODEL_MODE=live is set"),
    ({"HARNESS_DATABASE_URL": "postgresql+asyncpg://real/db"}, "HARNESS_DATABASE_URL is set"),
])
def test_ambient_live_mode_or_database_refuses_the_session(tmp_path, ambient, refused):
    result = _child_session(tmp_path, ambient)
    assert result.returncode == 4
    assert refused in result.stderr


def test_isolation_holds_without_opt_ins_and_the_opt_ins_are_explicit(tmp_path):
    assert _child_session(tmp_path, {}).returncode == 0
    assert _child_session(tmp_path, {"HARNESS_MODEL_MODE": "stub"}).returncode == 0
    opted_in = _child_session(tmp_path, {
        "HARNESS_DATABASE_URL": "postgresql+asyncpg://ignored/db",
        "HARNESS_TEST_DATABASE_URL": f"sqlite+aiosqlite:///{tmp_path / 'chosen.db'}"})
    assert opted_in.returncode == 0, opted_in.stdout


def test_missing_temporal_cli_skips_with_one_reason_or_fails_when_required(monkeypatch):
    import conftest

    monkeypatch.setattr(conftest, "_temporal_cli", lambda: None)
    monkeypatch.delenv("HARNESS_TEST_REQUIRE_TEMPORAL", raising=False)
    with pytest.raises(pytest.skip.Exception, match="Temporal CLI not found"):
        conftest._require_temporal()
    monkeypatch.setenv("HARNESS_TEST_REQUIRE_TEMPORAL", "1")
    with pytest.raises(pytest.fail.Exception, match="HARNESS_TEST_REQUIRE_TEMPORAL=1"):
        conftest._require_temporal()
    monkeypatch.setattr(conftest, "_temporal_cli", lambda: "/managed/temporal")
    assert conftest._require_temporal() == "/managed/temporal"


def test_load_script_returns_the_module_scripts_import_each_other_as():
    from conftest import load_script

    validation = load_script("service_validation")
    smoke = load_script("ui_deployment_smoke")
    assert validation.check_ui is smoke.check
    with pytest.raises(ImportError):
        load_script("json")  # resolves to the standard library, not scripts/
