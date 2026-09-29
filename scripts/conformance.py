"""Check this repository against the Agent and Multi-Agent Playbooks using `agentctl`.

`agentctl` discovers artifacts on the playbook's golden-path layout, which this repository now
uses directly: agent specs live at `src/infosec_harness/agents/<name>/agent.yaml` and skills at
`src/infosec_harness/skills/<name>/SKILL.md`, so they ship in the wheel as the playbook's Build
and packaging section requires.

Two differences remain, and both are naming rather than structure, so a throwaway mirror still
stands between the repository and `agentctl`:

* Agent and system directories are named as they are written (`probe-author`), while
  `agentctl` expects the module-normalized form (`probe_author`).
* Durable systems are expected to have an `activities/` package beside `workflows/`; ours is
  one module, `workflows/activities.py`.

The contracts checked are the real ones: the same YAML files, the same schemas, the same
semantic rules. Only the filenames are rearranged.

    uv run python scripts/conformance.py             # summary
    uv run python scripts/conformance.py --verbose    # every diagnostic

Requires agentctl on PATH or importable; pass --agentctl to point at a checkout.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PACKAGE = "infosec_harness"

# Deviations we take deliberately, with the reason. A waiver is reported, never hidden: a
# permanently red check trains people to ignore it, and an unexplained green one is worse.
WAIVERS = {
    "AGENT029": (
        "agentctl requires `retries` to be a plain integer. pydantic-ai's own Agent Spec "
        "schema accepts either an integer or an AgentRetries mapping — see the generated "
        "agents/agent_schema.json, where `retries` is anyOf[integer, AgentRetries, null] — and "
        "the mapping is what lets `verdict` carry output: 4 while its tool retries stay at 2. "
        "Collapsing it to one number would lose a distinction the framework supports and we "
        "rely on. Worth raising upstream against agentctl."
    ),
}
PACKAGE_DIR = REPO / "src" / PACKAGE
_IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc")

# Reviewable project files, which stay at the repository root by design and are what the specs'
# `risk_assessment` and `threat_model` metadata point at.
PROJECT_DIRS = ("docs", "evals")


def build_mirror(destination: Path) -> None:
    for name in PROJECT_DIRS:
        source = REPO / name
        if source.is_dir():
            shutil.copytree(source, destination / name, dirs_exist_ok=True, ignore=_IGNORE)
    # The package, copied whole except for the agent directories, which are *renamed* below
    # rather than duplicated: leaving both spellings in place makes every agent resolve twice
    # and `agentctl` reports the members as ambiguous.
    package = destination / "src" / PACKAGE
    shutil.copytree(PACKAGE_DIR, package, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "agents"))
    for spec in sorted((PACKAGE_DIR / "agents").glob("*/agent.yaml")):
        shutil.copytree(spec.parent, package / "agents" / spec.parent.name.replace("-", "_"),
                        dirs_exist_ok=True, ignore=_IGNORE)
    for module in sorted(PACKAGE_DIR.glob("agents/*.py")):
        shutil.copy2(module, package / "agents" / module.name)
    # Two root-level copies, because `agentctl` resolves these from the project root while the
    # runtime resolves them from the package: skills are discovered there, and a spec's
    # `evaluation_policy` is written `agents/<name>/evals/...` -- the path inside the
    # distribution, which is the package root at runtime and the project root to agentctl.
    shutil.copytree(PACKAGE_DIR / "skills", destination / "skills", dirs_exist_ok=True,
                    ignore=_IGNORE)
    shutil.copytree(PACKAGE_DIR / "agents", destination / "agents", dirs_exist_ok=True,
                    ignore=_IGNORE)
    for system in sorted((REPO / "systems").glob("*/system.yaml")):
        target = package / "systems" / system.parent.name.replace("-", "_")
        shutil.copytree(system.parent, target, dirs_exist_ok=True, ignore=_IGNORE)
    # agentctl requires a durable system to have both directories beside the package. Ours are
    # one module (workflows/activities.py) rather than a package, so mirror the shape.
    for directory in ("workflows", "activities"):
        (package / directory).mkdir(parents=True, exist_ok=True)
        (package / directory / "__init__.py").write_text(
            f'"""Mirrored for agentctl discovery; the real module is '
            f'src/{PACKAGE}/workflows/."""\n'
        )


def run(args: list[str], cwd: Path) -> dict:
    result = subprocess.run([*args, "--format", "json"], cwd=cwd, capture_output=True, text=True)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "diagnostics": [
            {"severity": "error", "code": "AGENTCTL",
             "message": (result.stderr or result.stdout or "no output").strip()[:400]}]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verbose", action="store_true", help="print every diagnostic")
    parser.add_argument("--agentctl", default=os.environ.get("AGENTCTL"),
                        help="path to an agentctl checkout (uses `uv run --locked agentctl`)")
    options = parser.parse_args()

    if options.agentctl:
        base = ["uv", "run", "--locked", "--project", options.agentctl, "agentctl", "--no-color"]
    elif shutil.which("agentctl"):
        base = ["agentctl", "--no-color"]
    else:
        print("agentctl not found: install it (`uv tool install ./tools/agentctl` from the "
              "playbooks repo) or pass --agentctl <path to that checkout>", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="harness-conformance-") as tmp:
        mirror = Path(tmp)
        build_mirror(mirror)
        checks = {
            "agents": [*base, "validate", "--root", str(mirror)],
            "skills": [*base, "skills", "validate", str(mirror / "skills")],
            # Only the agent assessments: the system one under systems/ has its own schema and
            # is validated by `system validate`, which reads it through the System Spec.
            "risk": [*base, "risk", "validate",
                     *(str(p) for p in sorted((mirror / "docs" / "risk-assessments").glob("*.yaml")))],
            "system": [*base, "system", "validate", "--root", str(mirror)],
        }
        failed = 0
        for label, command in checks.items():
            report = run(command, cwd=mirror)
            diagnostics = report.get("diagnostics") or []
            warnings = [d for d in diagnostics if d.get("severity") == "warning"]
            raw_errors = [d for d in diagnostics if d.get("severity") != "warning"]
            waived = [d for d in raw_errors if d.get("code") in WAIVERS]
            errors = [d for d in raw_errors if d.get("code") not in WAIVERS]
            status = "PASS" if not errors else "FAIL"
            failed += bool(errors)
            print(f"{status:4} {label:8} errors={len(errors):3} waived={len(waived):3} "
                  f"warnings={len(warnings):3}")
            shown = diagnostics if options.verbose else errors
            for diagnostic in shown:
                print(f"       [{diagnostic.get('severity','error')}] "
                      f"{diagnostic.get('code')} {str(diagnostic.get('message'))[:150]}")
            for code in sorted({d["code"] for d in waived}):
                count = sum(1 for d in waived if d["code"] == code)
                print(f"       waived {code} x{count}: {WAIVERS[code]}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
