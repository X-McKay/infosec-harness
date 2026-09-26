"""Check this repository against the Agent and Multi-Agent Playbooks using `agentctl`.

`agentctl` discovers artifacts on its golden-path layout — `src/<package>/agents/<name>/`,
`src/<package>/systems/<name>/`, `src/<package>/activities/` — while this repository keeps
agent specs, skills, and systems at the top level, next to each other, because they are
reviewed together as data (see the Layout section of README.md). That is a deliberate
difference in filing, not in contract.

So rather than relocating the repository to satisfy a discovery convention, this builds a
throwaway mirror in the expected shape and validates that. The contracts checked are the real
ones: the same YAML files, the same schemas, the same semantic rules.

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
# Mirrored as-is: these paths are already what the specs reference relative to the root.
COPY_AS_IS = ("agents", "skills", "docs", "evals", "config")


def build_mirror(destination: Path) -> None:
    for name in COPY_AS_IS:
        source = REPO / name
        if source.is_dir():
            shutil.copytree(source, destination / name, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    package = destination / "src" / PACKAGE
    (package / "agents").mkdir(parents=True, exist_ok=True)
    for spec in sorted((REPO / "agents").glob("*/agent.yaml")):
        # agentctl expects the directory to be the agent name normalized to a module name.
        target = package / "agents" / spec.parent.name.replace("-", "_")
        target.mkdir(parents=True, exist_ok=True)
        shutil.copy2(spec, target / "agent.yaml")
    # Skills and tool policies are discovered beside the package.
    shutil.copytree(REPO / "skills", package / "skills", dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copytree(REPO / "src" / PACKAGE / "tools", package / "tools", dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for system in sorted((REPO / "systems").glob("*/system.yaml")):
        target = package / "systems" / system.parent.name.replace("-", "_")
        shutil.copytree(system.parent, target, dirs_exist_ok=True)
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
