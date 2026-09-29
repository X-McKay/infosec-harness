"""Offline structural and reference-oracle validation for the sealed quality gate bundle."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
AGENTS = ("partial-build", "context", "verdict", "probe-author", "probe-repair")
TRACKED_PREFIX = Path("evals/heldout/quality-gates-v1/fixtures")


def fixture_path(repo: str) -> Path:
    relative = Path(repo).relative_to(TRACKED_PREFIX)
    resolved = (ROOT / "fixtures" / relative).resolve()
    resolved.relative_to((ROOT / "fixtures").resolve())
    return resolved


def main() -> None:
    cases = []
    for agent in AGENTS:
        document = yaml.safe_load((ROOT / "datasets" / agent / "dataset.yaml").read_text())
        assert document["version"] == "quality-gates-v1"
        assert len(document["cases"]) == 2
        for case in document["cases"]:
            assert case["name"] and case["group"] and case["category"]
            assert "expected" in case
            if repo := case.get("repo"):
                assert fixture_path(repo).is_dir(), repo
            cases.append((agent, case))

    assert len(cases) == 10
    assert len({case["name"] for _, case in cases}) == 10
    for agent in AGENTS:
        groups = {case["group"] for owner, case in cases if owner == agent}
        assert len(groups) == 1, (agent, groups)

    fixtures_text = "\n".join(
        path.read_text(errors="replace")
        for path in sorted((ROOT / "fixtures").rglob("*")) if path.is_file()
    )
    assert "expected:" not in fixtures_text
    assert "likely_not_exploitable" not in fixtures_text
    assert "potentially_exploitable" not in fixtures_text

    sys.path.insert(0, str(ROOT / "fixtures" / "context-header" / "raw"))
    from header import make_header as raw_header
    assert "X-Injected: yes" in raw_header("ok\r\nX-Injected: yes")
    del sys.modules["header"]
    sys.path[0] = str(ROOT / "fixtures" / "context-header" / "checked")
    from header import make_header as checked_header
    try:
        checked_header("ok\r\nX-Injected: yes")
    except ValueError:
        pass
    else:
        raise AssertionError("checked header fixture accepted a line break")

    js = ROOT / "fixtures" / "probe-js" / "redirect.js"
    output = subprocess.check_output([
        "node", "-e",
        f"const r=require({json.dumps(str(js))});process.stdout.write(r.redirectTarget('https://attacker.invalid/x'))",
    ], text=True)
    assert output == "https://attacker.invalid/x"

    group_hashes = sorted({
        hashlib.sha256(case["group"].encode()).hexdigest()
        for _, case in cases
    })
    print(json.dumps({
        "agents": {agent: 2 for agent in AGENTS},
        "cases": len(cases), "groups": len(group_hashes), "group_hashes": group_hashes,
        "ecosystems": ["javascript", "python"], "status": "passed",
    }, sort_keys=True))


if __name__ == "__main__":
    main()
