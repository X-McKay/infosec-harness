"""Add the playbook's required structure to every SKILL.md, preserving its content.

The skill standard (agent-playbook §4) requires positive and negative activation criteria, a
procedure, safety constraints, and completion criteria, plus an owner and semantic version.
Our skills had the procedure and nothing else.

The activation criteria matter beyond conformance. The `description` is what a model reads
when deciding whether to load a skill at all, and the measured jump in context's skill
evocation (19% -> 100%, docs/LIVE_VALIDATION.md) came from making that choice explicit rather
than implied. `agentctl skills validate` warns when a description does not say *when* to use
the skill; every one now does.

Idempotent: run it again after editing scripts/skill_specs.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))
from skill_specs import SKILLS  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
OWNER = "appsec"
VERSION = "1.0.0"
MANAGED = ("## Use this skill when", "## Do not use this skill when",
           "## Safety constraints", "## Completion criteria")


def _bullets(items: list[str]) -> str:
    return "\n".join(f"- {item}" for item in items)


def _split(text: str) -> tuple[dict, str]:
    """Return (frontmatter, body) for a SKILL.md."""
    assert text.startswith("---\n"), "SKILL.md must open with frontmatter"
    _, fm, body = text.split("---\n", 2)
    return yaml.safe_load(fm) or {}, body.lstrip("\n")


def _strip_managed(body: str) -> str:
    """Remove sections this script owns, so re-running replaces rather than duplicates."""
    lines = body.splitlines(keepends=True)
    out, skipping = [], False
    for line in lines:
        if line.startswith("## "):
            skipping = line.rstrip().startswith(MANAGED)
        if not skipping:
            out.append(line)
    return "".join(out).rstrip() + "\n"


def restructure(name: str) -> bool:
    path = REPO / "skills" / name / "SKILL.md"
    spec = SKILLS[name]
    frontmatter, body = _split(path.read_text())
    body = _strip_managed(body)

    # The heading and reference content the skill already had become its procedure.
    title, _, remainder = body.partition("\n")
    procedure = remainder.strip("\n")

    frontmatter = {
        "name": name,
        "description": spec["description"],
        "metadata": {"owner": OWNER, "version": VERSION},
    }
    rendered = (
        "---\n"
        + yaml.safe_dump(frontmatter, sort_keys=False, width=96, allow_unicode=True)
        + "---\n\n"
        + f"{title}\n\n"
        + "## Use this skill when\n\n" + _bullets(spec["use_when"]) + "\n\n"
        + "## Do not use this skill when\n\n" + _bullets(spec["avoid_when"]) + "\n\n"
        + procedure + "\n\n"
        + "## Safety constraints\n\n" + _bullets(spec["safety"]) + "\n\n"
        + "## Completion criteria\n\n" + _bullets(spec["completion"]) + "\n"
    )
    if rendered == path.read_text():
        return False
    path.write_text(rendered)
    return True


def main() -> int:
    changed = [name for name in sorted(SKILLS) if restructure(name)]
    print(f"restructured {len(changed)} of {len(SKILLS)} skills")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
