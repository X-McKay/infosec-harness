"""Synchronize the small set of copied development instructions."""

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    copies = [(ROOT / "AGENTS.md", ROOT / "CLAUDE.md")]
    for source in sorted((ROOT / "dev-skills").glob("*/SKILL.md")):
        # .agents/skills links to .claude/skills; one write updates both clients.
        copies.append((source, ROOT / ".claude/skills" / source.relative_to(ROOT / "dev-skills")))
    stale = []
    for source, target in copies:
        content = source.read_bytes()
        if target.exists() and target.read_bytes() == content:
            continue
        if args.check:
            stale.append(str(target.relative_to(ROOT)))
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
    if stale:
        raise SystemExit("Generated instruction drift: " + ", ".join(stale))


if __name__ == "__main__":
    main()
