"""Add the playbook's required structure to every SKILL.md, preserving its content.

The skill standard (agent-playbook §4) requires positive and negative activation criteria, a
procedure, safety constraints, and completion criteria, plus an owner and semantic version.
Our skills had the procedure and nothing else.

The activation criteria matter beyond conformance: a skill's `description` is what a model
reads when deciding whether to load it, and the measured jump in context's skill evocation
(19% -> 100%, docs/LIVE_VALIDATION.md) came from making that choice explicit.

The same argument extends to the precedence section this script renders from `relations`
("When another skill also applies"). Two skills whose negative criteria point at each other
tell a reader in the overlap to go round in a circle, so the agent guesses; naming the winner
is what turns that guess back into a decision the library made.

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


# The phrase each verdict renders as. It is bold in the output because it is the one clause a
# reader skimming the section needs, and it is a *fixed* phrase because `evals/skills.py` reads
# the verdict back out of the rendered file rather than out of this module: the skill as
# published is what an agent is given, so that is what the coverage check has to parse.
VERDICT_PHRASES = {"wins": "**this skill wins**", "yields": "**that skill wins**"}


def _bullets(items: list[str]) -> str:
    return "\n".join(f"- {item}" for item in items)


def _relations(name: str, relations: list[dict]) -> str:
    """Render the precedence section, refusing prose that disagrees with its own verdict."""
    if not relations:
        return ""
    bullets: list[str] = []
    for relation in relations:
        target, verdict, text = relation["skill"], relation["verdict"], relation["text"]
        if target not in SKILLS:
            raise ValueError(f"{name}: relation names {target!r}, which is not a skill")
        if target == name:
            raise ValueError(f"{name}: declares a relation with itself")
        if verdict not in VERDICT_PHRASES:
            raise ValueError(f"{name}/{target}: unknown verdict {verdict!r}")
        if not text.startswith(f"`{target}`"):
            raise ValueError(
                f"{name}/{target}: the relation's text must open with the other skill in "
                "backticks, so the reader and the parser agree on which pair it settles"
            )
        if VERDICT_PHRASES[verdict] not in text.lower():
            raise ValueError(
                f"{name}/{target}: verdict is {verdict!r} but the text does not contain "
                f"{VERDICT_PHRASES[verdict]!r}. A declared verdict the prose does not state is "
                "a rule the reader never sees"
            )
        bullets.append(text)
    return "## When another skill also applies\n\n" + _bullets(bullets) + "\n\n"


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
    path = REPO / "src" / "infosec_harness" / "skills" / name / "SKILL.md"
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
         "metadata": {"owner": OWNER, "version": spec.get("version", VERSION)}},
        sort_keys=False, width=96, allow_unicode=True)
    rendered = (
        f"---\n{frontmatter}---\n\n{title}\n\n"
        f"{BEGIN}\n\n"
        "## Use this skill when\n\n" + _bullets(spec["use_when"]) + "\n\n"
        "## Do not use this skill when\n\n" + _bullets(spec["avoid_when"]) + "\n\n"
        + _relations(name, spec.get("relations") or [])
        + f"{END}\n\n"
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
