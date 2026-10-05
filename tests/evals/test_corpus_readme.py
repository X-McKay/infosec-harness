"""eval-corpus/README.md describes exactly the cases manifest.json contains."""

from __future__ import annotations

import json
import re

from infosec_harness.settings import REPO_ROOT

README = REPO_ROOT / "eval-corpus" / "README.md"
MANIFEST = json.loads((REPO_ROOT / "eval-corpus" / "manifest.json").read_text())


def _table_rows() -> list[list[str]]:
    lines = README.read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("| Cases |"))
    rows = []
    for line in lines[start + 2:]:
        if not line.startswith("|"):
            break
        rows.append([cell.strip() for cell in line.strip("|").split("|")])
    return rows


def test_the_case_table_lists_every_manifest_case_with_its_language_and_cwe():
    documented = {
        (name, language, cwe)
        for cases, language, cwe, _toolchain in _table_rows()
        for name in re.findall(r"`([^`]+)`", cases)
    }
    manifest = {(case["name"], case["language"], case["finding"]["cwe"])
                for case in MANIFEST["cases"]}
    assert documented == manifest, (
        f"README only: {sorted(documented - manifest)}; manifest only: "
        f"{sorted(manifest - documented)}")


def test_the_stated_case_count_is_the_manifests():
    count = re.search(r"## Cases \((\d+) total\)", README.read_text())
    assert count and int(count.group(1)) == len(MANIFEST["cases"])
