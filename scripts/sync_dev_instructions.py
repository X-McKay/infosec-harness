#!/usr/bin/env python3
"""Generate the Claude entry point from the canonical AGENTS.md instructions."""

from __future__ import annotations

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "AGENTS.md"
TARGET = ROOT / "CLAUDE.md"


def sync() -> None:
    TARGET.write_text(SOURCE.read_text())
    print(f"generated {TARGET.relative_to(ROOT)} from {SOURCE.relative_to(ROOT)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("sync", "check"), nargs="?", default="check")
    args = parser.parse_args()
    if args.command == "sync":
        sync()
        return 0
    if not TARGET.exists() or TARGET.read_text() != SOURCE.read_text():
        print("CLAUDE.md drift detected; run: just generated-sync")
        return 1
    print("CLAUDE.md is synchronized with AGENTS.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
