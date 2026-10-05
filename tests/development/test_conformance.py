"""Checkout selection must survive conformance's temporary working directory."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("selection", ["relative_cli", "relative_env", "absolute_cli"])
def test_checkout_is_resolved_before_entering_the_mirror(tmp_path, selection):
    caller = tmp_path / "caller"
    project = caller / "playbooks" / "tools" / "agentctl"
    project.mkdir(parents=True)
    (project / "pyproject.toml").write_text('[project]\nname = "agentctl-fixture"\n')
    executable = tmp_path / "bin" / "uv"
    executable.parent.mkdir()
    executable.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "args = sys.argv[1:]\n"
        "project = Path(args[args.index('--project') + 1])\n"
        "if not (project / 'pyproject.toml').is_file():\n"
        "    sys.stderr.write('selected checkout unavailable in temporary mirror')\n"
        "    raise SystemExit(2)\n"
        "with open(os.environ['CONFORMANCE_FIXTURE_LOG'], 'a') as output:\n"
        "    output.write(json.dumps({'project':str(project),'cwd':os.getcwd(),'args':args}) + '\\n')\n"
        "print(json.dumps({'ok':True,'diagnostics':[]}))\n"
    )
    executable.chmod(0o755)
    log = tmp_path / "calls.jsonl"
    environment = {**os.environ, "PATH": str(executable.parent) + os.pathsep + os.environ["PATH"],
                   "CONFORMANCE_FIXTURE_LOG": str(log)}
    environment.pop("AGENTCTL", None)
    command = [sys.executable, str(ROOT / "scripts" / "conformance.py")]
    relative = str(project.relative_to(caller))
    if selection == "relative_env":
        environment["AGENTCTL"] = relative
    else:
        command.extend(["--agentctl", str(project) if selection == "absolute_cli" else relative])
    result = subprocess.run(command, cwd=caller, env=environment, capture_output=True,
                            text=True, check=False, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    # Only the agent and skill validators run: the rendered risk assessments and System Spec
    # the other two read are not materialized in this repository.
    assert len(calls) == 2
    assert all(Path(call["project"]) == project and Path(call["project"]).is_absolute()
               for call in calls)
    assert all(Path(call["cwd"]) != caller and "harness-conformance-" in call["cwd"]
               for call in calls)
    assert [call["args"][6:-2][:2] for call in calls] == [
        ["validate", "--root"], ["skills", "validate"],
    ]
    assert result.stdout.count("PASS") == 2
