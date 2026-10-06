"""Package data and installed executor closure; no provider requests."""

import ast
import os
import shutil
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_standalone_executor_has_no_worker_runtime_imports():
    source = ROOT / "src/infosec_harness/sandbox/executor.py"
    tree = ast.parse(source.read_text())
    allowed = {
        "asyncio",
        "os",
        "sys",
        "typing",
        "urllib",
        "pydantic",
        "pydantic_ai",
        "openai",
        "boto3",
        "botocore",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name.split(".")[0] in allowed for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0
            assert node.module and node.module.split(".")[0] in allowed


def test_executor_import_loads_no_other_package_module():
    """The package initialisers stay lazy, so the shipped executor imports alone."""
    script = (
        "import sys, infosec_harness.sandbox.executor; "
        "print(sorted(m for m in sys.modules if m.startswith('infosec_harness')))"
    )
    loaded = subprocess.run(
        [sys.executable, "-c", script], check=True, capture_output=True, text=True
    ).stdout.strip()
    expected = ["infosec_harness", "infosec_harness.sandbox", "infosec_harness.sandbox.executor"]
    assert loaded == repr(expected)


@pytest.mark.network
def test_installed_wheel_executor_imports_with_only_native_provider_dependencies(tmp_path):
    uv = shutil.which("uv")
    if not uv:
        pytest.fail("The pinned uv executable is required for installed-wheel qualification")
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(tmp_path),
        "UV_CACHE_DIR": str(tmp_path / "cache"),
        "UV_NO_MANAGED_PYTHON": "1",
        "PYDANTIC_AI_NO_BANNER": "1",
    }

    def run(*argv, cwd=tmp_path):
        subprocess.run(
            [str(value) for value in argv],
            cwd=cwd,
            env=env,
            check=True,
            capture_output=True,
            timeout=180,
        )

    wheel_dir = tmp_path / "dist"
    run(uv, "build", "--wheel", "--python", sys.executable, "--out-dir", wheel_dir, ROOT)
    (wheel,) = wheel_dir.glob("*.whl")
    with zipfile.ZipFile(wheel) as artifact:
        names = set(artifact.namelist())
        assert "infosec_harness/skills/investigate/SKILL.md" in names
        assert "infosec_harness/evals/release-policy.yaml" in names
        assert "infosec_harness/sandbox/executor.py" in names
    environment = tmp_path / "environment"
    run(uv, "venv", "--python", sys.executable, environment)
    python = environment / "bin/python"
    run(uv, "pip", "install", "--python", python, "--no-deps", wheel)
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    version = next(
        package["version"] for package in lock["package"] if package["name"] == "pydantic-ai-slim"
    )
    run(uv, "pip", "install", "--python", python, f"pydantic-ai-slim[openai,bedrock]=={version}")
    script = """
import importlib.util, pathlib, sys
import infosec_harness.sandbox.executor as executor
assert pathlib.Path(executor.__file__).is_relative_to(pathlib.Path(sys.prefix))
assert importlib.util.find_spec('temporalio') is None
assert importlib.util.find_spec('openshell') is None
assert 'infosec_harness.workflows.investigation' not in sys.modules
assert 'infosec_harness.sandbox.openshell' not in sys.modules
assert 'infosec_harness.workflows.snapshot' not in sys.modules
assert executor.ModelInvocation.model_fields['provider']
"""
    run(python, "-I", "-c", script)
