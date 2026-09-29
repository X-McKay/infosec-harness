#!/usr/bin/env python3
"""Synchronize the checked-in development skills to each supported client."""

from __future__ import annotations

import argparse
import filecmp
import hashlib
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "dev-skills"
DESTINATIONS = (ROOT / ".agents" / "skills", ROOT / ".claude" / "skills")


def content_digest(text: str) -> str:
    """Hash the portable skill text, excluding the self-referential digest field."""
    canonical = re.sub(r"^  content_digest:.*\n", "", text, flags=re.MULTILINE)
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def skill_files(base: Path) -> list[Path]:
    return sorted(path for path in base.glob("*/SKILL.md") if path.is_file())


def check() -> list[str]:
    errors: list[str] = []
    sources = skill_files(SOURCE)
    if not sources:
        return [f"no canonical skills found under {SOURCE}"]
    for source in sources:
        text = source.read_text()
        expected = re.search(r"^  content_digest: (.+)$", text, flags=re.MULTILINE)
        if expected is None or expected.group(1) != content_digest(text):
            errors.append(f"canonical content digest drift: {source.relative_to(SOURCE)}")
    names = {path.parent.name for path in sources}
    for destination in DESTINATIONS:
        for skill in sources:
            target = destination / skill.parent.name / skill.name
            if not target.exists():
                errors.append(f"missing generated skill: {target.relative_to(ROOT)}")
            elif not filecmp.cmp(skill, target, shallow=False):
                errors.append(f"generated skill drift: {target.relative_to(ROOT)}")
        for extra in destination.glob("*/SKILL.md"):
            if extra.parent.name not in names:
                errors.append(f"untracked generated skill: {extra.relative_to(ROOT)}")
    return errors


def sync() -> None:
    for source in skill_files(SOURCE):
        text = source.read_text()
        source.write_text(re.sub(r"^  content_digest:.*$", "  content_digest: " + content_digest(text),
                                 text, flags=re.MULTILINE))
    for destination in DESTINATIONS:
        destination.mkdir(parents=True, exist_ok=True)
        for skill in skill_files(SOURCE):
            target = destination / skill.parent.name / skill.name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(skill, target)
    print(f"synced {len(skill_files(SOURCE))} development skills to {len(DESTINATIONS)} clients")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("sync", "check"), nargs="?", default="check")
    args = parser.parse_args()
    if args.command == "sync":
        sync()
        return 0
    errors = check()
    if errors:
        print("development skill drift detected:")
        print("\n".join(f"- {error}" for error in errors))
        print("run: just dev-skills-sync")
        return 1
    print(f"development skills are in sync ({len(skill_files(SOURCE))} skills)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
