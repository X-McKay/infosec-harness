"""Add the playbook's required structure to every SKILL.md, preserving its content.

The skill standard (agent-playbook §4) requires positive and negative activation criteria, a
procedure, safety constraints, and completion criteria, plus an owner and semantic version.
Our skills had the procedure and nothing else.

The activation criteria matter beyond conformance: a skill's `description` is what a model
reads when deciding whether to load it, and the measured jump in context's skill evocation
(19% -> 100%, docs/LIVE_VALIDATION.md) came from making that choice explicit.

**The regions this script owns are delimited by explicit markers.** An earlier version
inferred them from heading positions instead, and on a second run it deleted the body of every
skill whose procedure had no `## ` heading of its own -- including the line in `build-python`
mandating `pytest -s`, without which a probe's oracle markers are captured away by pytest and
every Python probe silently reports nothing. Markers make the round-trip exact: everything
outside them is content, and this script never touches it.

Idempotent. Run after editing scripts/skill_specs.py.
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
BEGIN = "<!-- generated: activation criteria (scripts/restructure_skills.py) -->"
END = "<!-- /generated: activation criteria -->"
BEGIN_C = "<!-- generated: constraints (scripts/restructure_skills.py) -->"
END_C = "<!-- /generated: constraints -->"


def _bullets(items: list[str]) -> str:
    return "\n".join(f"- {item}" for item in items)


def _split_frontmatter(text: str) -> tuple[dict, str]:
    if not text.startswith("---\n"):
        raise ValueError("SKILL.md must open with YAML frontmatter")
    _, frontmatter, body = text.split("---\n", 2)
    return yaml.safe_load(frontmatter) or {}, body.lstrip("\n")


def _drop_region(body: str, begin: str, end: str) -> str:
    """Remove one generated region, if present. Content outside it is never touched."""
    while begin in body and end in body:
        head, rest = body.split(begin, 1)
        _, tail = rest.split(end, 1)
        body = head + tail.lstrip("\n")
    return body


def restructure(name: str) -> bool:
    path = REPO / "skills" / name / "SKILL.md"
    spec = SKILLS[name]
    original = path.read_text()
    _, body = _split_frontmatter(original)
    body = _drop_region(_drop_region(body, BEGIN, END), BEGIN_C, END_C).strip("\n")

    title, _, procedure = body.partition("\n")
    procedure = procedure.strip("\n")
    if not procedure:
        raise ValueError(
            f"{name}: no procedure content left after removing the generated regions. "
            "Refusing to write a skill with an empty body."
        )

    frontmatter = yaml.safe_dump(
        {"name": name, "description": spec["description"],
         "metadata": {"owner": OWNER, "version": VERSION}},
        sort_keys=False, width=96, allow_unicode=True)
    rendered = (
        f"---\n{frontmatter}---\n\n{title}\n\n"
        f"{BEGIN}\n\n"
        "## Use this skill when\n\n" + _bullets(spec["use_when"]) + "\n\n"
        "## Do not use this skill when\n\n" + _bullets(spec["avoid_when"]) + "\n\n"
        f"{END}\n\n"
        f"{procedure}\n\n"
        f"{BEGIN_C}\n\n"
        "## Safety constraints\n\n" + _bullets(spec["safety"]) + "\n\n"
        "## Completion criteria\n\n" + _bullets(spec["completion"]) + "\n\n"
        f"{END_C}\n"
    )
    if rendered == original:
        return False
    path.write_text(rendered)
    return True


def main() -> int:
    changed = [name for name in sorted(SKILLS) if restructure(name)]
    print(f"restructured {len(changed)} of {len(SKILLS)} skills")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
