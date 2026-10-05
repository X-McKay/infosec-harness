"""The wheel must carry everything an agent needs to run, and nothing may need the CWD.

agent-playbook 02 (Build and packaging) states both halves:

    Agent specifications, instruction files, and runtime `SKILL.md` files MUST be included as
    package data. Tests MUST load resources from the built wheel or equivalent deployment
    artifact. Runtime resource paths SHOULD be resolved with `importlib.resources`, not a
    process working-directory assumption.

Neither held before this file existed, and no test could have noticed. Specs, skills and the
model catalogue sat at the repository root, so the wheel shipped **none** of them -- 65 entries,
of which the only data files were two `tool.yaml`. `REPO_ROOT` was
``Path(__file__).parents[2]``, which is the repository root only when the package is imported
from ``src/``; from ``site-packages`` it resolves to the directory above ``site-packages``. And
the ``Skills`` capability was handed the bare string ``skills``, which the loader resolved
against the *process working directory*, so agents found their skills only when something
launched the worker from the repository root.

The in-tree suite passed throughout, because in-tree every one of those accidents is true.
Checking this needs the built artifact, which is why these tests build one.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from infosec_harness.resources import package_root, source_checkout

REPO = source_checkout()
pytestmark = pytest.mark.skipif(REPO is None, reason="needs a source checkout to build from")


@pytest.fixture(scope="session")
def wheel(tmp_path_factory) -> Path:
    """Build the real wheel once. Skips rather than fails when no builder is available."""
    builder = shutil.which("uv")
    out = tmp_path_factory.mktemp("wheel")
    cmd = ([builder, "build", "--wheel", "-o", str(out)] if builder
           else [sys.executable, "-m", "build", "--wheel", "--outdir", str(out)])
    try:
        subprocess.run(cmd, cwd=REPO, check=True, capture_output=True, timeout=600)
    except FileNotFoundError as exc:
        pytest.skip(f"cannot build a wheel here: {exc}")
    except subprocess.CalledProcessError as exc:
        pytest.fail(f"wheel build failed: {exc.stderr.decode(errors='replace')}")
    wheels = list(out.glob("*.whl"))
    assert wheels, "the build produced no wheel"
    return wheels[0]


def _names(wheel: Path) -> list[str]:
    with zipfile.ZipFile(wheel) as z:
        return z.namelist()


def test_every_agent_spec_ships_in_the_wheel(wheel):
    """One `agent.yaml` per agent directory: a spec left behind is an agent that cannot start."""
    packaged = {n.split("/")[-2] for n in _names(wheel) if n.endswith("/agent.yaml")}
    on_disk = {p.parent.name for p in (package_root() / "agents").glob("*/agent.yaml")}
    assert packaged == on_disk, f"specs missing from the wheel: {sorted(on_disk - packaged)}"


def test_every_skill_ships_in_the_wheel(wheel):
    packaged = {n.split("/")[-2] for n in _names(wheel) if n.endswith("/SKILL.md")}
    on_disk = {p.parent.name for p in (package_root() / "skills").glob("*/SKILL.md")}
    assert packaged == on_disk, f"skills missing from the wheel: {sorted(on_disk - packaged)}"


def test_only_current_agent_specs_ship(wheel):
    """No retained replay generation (agents/<name>/agent-v*.yaml) remains in the package."""
    retained = [n for n in _names(wheel) if "/agents/" in n and "/agent-v" in n]
    assert not retained, f"retained agent specs still ship: {retained}"


def test_the_approved_model_catalogue_ships_in_the_wheel(wheel):
    """Model policy is governance data, so it travels with the code it governs rather than
    being something a deployment is trusted to place correctly."""
    assert "infosec_harness/config/models.yaml" in _names(wheel)


def test_the_wheel_carries_no_build_droppings(wheel):
    stray = [n for n in _names(wheel) if "__pycache__" in n or n.endswith(".pyc")]
    assert not stray, f"the wheel ships build droppings: {stray[:5]}"


@pytest.fixture(scope="session")
def installed(wheel, tmp_path_factory) -> Path:
    """A throwaway venv with only the wheel in it, and no repository anywhere above."""
    if not (uv := shutil.which("uv")):
        pytest.skip("needs uv to create an isolated environment")
    env = tmp_path_factory.mktemp("venv") / "v"
    subprocess.run([uv, "venv", str(env)], check=True, capture_output=True)
    subprocess.run([uv, "pip", "install", "--python", str(env / "bin" / "python"), str(wheel)],
                   check=True, capture_output=True, timeout=600)
    return env / "bin" / "python"


def _run(python: Path, code: str, cwd: Path) -> str:
    """Run a snippet against the installed copy, from a directory that is not the repository."""
    environment = {**os.environ, "HARNESS_MODEL_MODE": "stub"}
    # Nothing may leak a path back to the checkout: that is the assumption under test.
    for leak in ("PYTHONPATH", "HARNESS_AGENTS_DIR", "HARNESS_SKILLS_DIR", "HARNESS_MODELS_CONFIG"):
        environment.pop(leak, None)
    result = subprocess.run([str(python), "-c", code], cwd=cwd, env=environment,
                            capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stderr[-3000:]
    return result.stdout.strip()


def test_the_installed_package_knows_it_has_no_repository(installed, tmp_path):
    """`source_checkout()` must answer None off a checkout rather than inventing a path.

    The old `REPO_ROOT` invented one -- `site-packages/../..` -- and every path derived from it
    pointed at a directory that simply did not exist, which is how this stayed invisible.
    """
    assert _run(installed, "from infosec_harness.resources import source_checkout;"
                           "print(source_checkout())", tmp_path) == "None"


def test_every_agent_builds_from_the_installed_wheel(installed, tmp_path):
    """The end-to-end property. Run from an unrelated directory, so a working-directory
    assumption anywhere in spec loading, skill loading or model resolution fails here."""
    names = json.loads(_run(installed, """
import json
from infosec_harness.agents.registry import AGENT_BINDINGS, build_agent
built = []
for name in sorted(AGENT_BINDINGS):
    build_agent(name)
    built.append(name)
print(json.dumps(built))
""", tmp_path))
    expected = sorted(p.parent.name for p in (package_root() / "agents").glob("*/agent.yaml"))
    assert names == expected


def test_skills_resolve_to_the_package_not_the_working_directory(installed, tmp_path):
    """`directories: skills` in a spec must become an absolute path inside the package.

    Left relative it resolved against the CWD, so this exact call raised `Skill library
    directory does not exist: skills` from anywhere but the repository root.
    """
    resolved = _run(installed, """
from infosec_harness.agents.registry import load_spec, _absolutize_skill_dirs
spec = _absolutize_skill_dirs(load_spec('context'))
dumped = spec.model_dump(by_alias=True, exclude_none=True, mode='json')
for cap in dumped['capabilities']:
    if cap.get('name') == 'Skills':
        print(cap['arguments']['directories'])
""", tmp_path)
    assert resolved.startswith("/") and resolved.endswith("/infosec_harness/skills"), resolved
