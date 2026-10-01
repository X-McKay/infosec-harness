"""Recipe extraction and production-validator-backed skill cases."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import yaml
from pydantic_ai import ModelRetry

from infosec_harness.agents.validators import (
    PYTEST_TEST_COMMAND,
    environment_spec_violations,
    install_path_violations,
    offline_warmup_violations,
    validate_probe,
)
from infosec_harness.domain.models import EnvironmentSpec, ProbeSource

from .skill_documents import SkillDoc

# --- Extracting the recipes a skill shows --------------------------------------------------

_RUNNER_HEADS = (
    "mvn",
    "mvnw",
    "./mvnw",
    "gradle",
    "gradlew",
    "./gradlew",
    "prove",
    "pytest",
    "npx",
    "npm",
    "python",
    "python3",
    "cpanm",
    "pip",
)
# Fenced blocks in these languages are probe bodies, not shell.
_PROBE_LANGS = {
    "python": "tests/test_harness_probe.py",
    "java": "src/test/java/com/example/HarnessProbeTest.java",
    "perl": "t/harness_probe.t",
    "js": "__tests__/harness_probe.test.js",
    "javascript": "__tests__/harness_probe.test.js",
}
_SHELL_LANGS = {"", "sh", "bash", "shell", "console"}
_FENCE = re.compile(r"```(\w*)\n(.*?)```", re.S)


class CommandKind(StrEnum):
    """Which validator family judges a command the skill shows."""

    TEST = "test"
    """Goes in ``EnvironmentSpec.test_command``."""

    INSTALL = "install"
    """Goes in ``EnvironmentSpec.install_commands``."""


@dataclass(frozen=True)
class ShellCommand:
    text: str
    kind: CommandKind
    source: str
    """``fence`` or ``inline`` — where in the skill it was shown."""


# What marks a command as the one that runs the probe rather than one that prepares the image.
_TEST_MARKERS = ("{test_file}", "-Dtest=", "--tests", "--runTestsByPath")
_INSTALL_MARKERS = (
    "-DskipTests",
    "testClasses",
    "HarnessWarmupTest",
    "pip install",
    "npm ci",
    "npm install",
    "cpanm",
    "--version",
    "dependency:get",
)


def _classify(command: str) -> CommandKind | None:
    if any(marker in command for marker in _INSTALL_MARKERS):
        return CommandKind.INSTALL
    if any(marker in command for marker in _TEST_MARKERS):
        return CommandKind.TEST
    if command.split()[0] in ("prove", "pytest") and len(command.split()) > 1:
        return CommandKind.TEST
    return None


def extract_commands(skill: SkillDoc) -> list[ShellCommand]:
    """Every runnable command the skill shows, classified as a test or an install command.

    Both fenced shell blocks and inline code spans count: ``test-junit5`` shows its Maven
    command as an inline span wrapped over three lines, and that is the exemplar an author
    copies. Line continuations and wrapping are normalised so the span is judged as the one
    command it represents.

    Commands whose role cannot be determined are dropped rather than guessed at: a mis-filed
    install command judged as a test command would fail for a rule that does not apply to it,
    and a check with false positives gets disabled.
    """
    body = skill.procedure
    candidates: list[tuple[str, str]] = []

    fenced: list[str] = []
    for match in _FENCE.finditer(body):
        lang, code = match.group(1).lower(), match.group(2)
        fenced.append(match.group(0))
        if lang not in _SHELL_LANGS:
            continue
        for line in code.replace("\\\n", " ").splitlines():
            candidates.append(("fence", line))

    # Inline spans, with fenced blocks removed first so a fence's backticks cannot pair up
    # with a later inline one and splice unrelated text into a "command".
    prose = body
    for block in fenced:
        prose = prose.replace(block, "\n")
    for match in re.finditer(r"`([^`]+)`", prose):
        candidates.append(("inline", match.group(1)))

    out: list[ShellCommand] = []
    seen: set[str] = set()
    for source, raw in candidates:
        text = " ".join(raw.replace("\\", " ").split())
        if not text or text in seen:
            continue
        head = text.split()[0]
        if head not in _RUNNER_HEADS:
            continue
        kind = _classify(text)
        if kind is None:
            continue
        seen.add(text)
        out.append(ShellCommand(text=text, kind=kind, source=source))
    return out


def extract_exemplar_specs(skill: SkillDoc) -> list[EnvironmentSpec]:
    """Complete ``EnvironmentSpec`` exemplars the skill shows in a YAML fence.

    ``build-cpanm`` presents its recipe as install commands, ``env`` and ``test_command``
    together, which is the whole artifact an env-planner emits — so it can be judged whole, by
    every validator including the ones about coherence *between* those fields.
    """
    specs: list[EnvironmentSpec] = []
    for match in _FENCE.finditer(skill.procedure):
        if match.group(1).lower() != "yaml":
            continue
        try:
            data = yaml.safe_load(resolve_placeholders(match.group(2)))
        except yaml.YAMLError:
            continue
        if not isinstance(data, dict) or "test_command" not in data:
            continue
        data.setdefault("base_image", "perl:5.38-slim")
        specs.append(
            EnvironmentSpec.model_validate(
                {k: v for k, v in data.items() if k in EnvironmentSpec.model_fields}
            )
        )
    return specs


def extract_probe_exemplars(skill: SkillDoc) -> list[tuple[str, str, str]]:
    """``(language, assumed test path, source)`` for each probe body the skill shows."""
    out: list[tuple[str, str, str]] = []
    for match in _FENCE.finditer(skill.procedure):
        lang = match.group(1).lower()
        if lang in _PROBE_LANGS and "HARNESS_" in match.group(2):
            out.append((lang, _PROBE_LANGS[lang], match.group(2)))
    return out


# --- Judging them with the production validators -------------------------------------------

# Placeholders a skill legitimately shows in place of a value the author supplies. They are
# substituted before validation so the validators judge the shape, not the placeholder.
_PLACEHOLDERS = {
    "<ProbeClassName>": "HarnessProbeTest",
    "<fqcn>": "com.example.HarnessProbeTest",
    "<module>": "service",
    "<subproject>": "service",
    "<nonce>": "abc123",
    "<settings.xml>": "settings.xml",
}


def resolve_placeholders(text: str) -> str:
    for placeholder, value in _PLACEHOLDERS.items():
        text = text.replace(placeholder, value)
    return text


def spec_violations(spec: EnvironmentSpec) -> list[str]:
    """Every deterministic objection the harness would raise to this spec.

    The three production validators, in the order ``validate_environment_spec`` applies them,
    so a spec this function calls clean is one a live agent could have emitted without being
    told to retry.
    """
    return (
        environment_spec_violations(spec)
        + install_path_violations(spec)
        + offline_warmup_violations(spec)
    )


# A benign counterpart for judging one command on its own. The PERL5LIB entry is present
# because `install_path_violations` couples a cpanm install to it: judging a lone install
# command without it would report the *spec's* incoherence as a fault of the command. Spec
# coherence is judged instead by `extract_exemplar_specs`, where a whole spec is actually shown.
# The canonical command, not a copy of it: a new pytest rule must not make every *install*
# command in every skill fail because this filler went stale. That is what happened when
# `-o addopts=` was added.
_FILLER_TEST_COMMAND = PYTEST_TEST_COMMAND
_FILLER_ENV = {"PERL5LIB": "/work/home/perl5/lib/perl5"}


def command_violations(command: ShellCommand) -> list[str]:
    """The harness's objections to a single command the skill shows, judged on its own.

    ``offline_warmup_violations`` is deliberately not applied: it asks whether the *install*
    commands warmed what the *test* command needs, which is a property of a whole spec and not
    of any one line. Applying it here would report every Maven test command as defective for a
    reason belonging to a different command.
    """
    if command.kind is CommandKind.TEST:
        spec = EnvironmentSpec(
            base_image="scratch",
            test_command=resolve_placeholders(command.text),
            env=dict(_FILLER_ENV),
        )
    else:
        spec = EnvironmentSpec(
            base_image="scratch",
            test_command=_FILLER_TEST_COMMAND,
            install_commands=[resolve_placeholders(command.text)],
            env=dict(_FILLER_ENV),
        )
    return environment_spec_violations(spec) + install_path_violations(spec)


def probe_exemplar_violations(test_file_path: str, content: str) -> list[str]:
    """The harness's own objections to a probe body, via the production validator.

    Passing ``None`` for the ``RunContext`` runs the real rules rather than a restatement of them
    that could drift. ``validate_probe`` reads the checkout through the context when it has one,
    to know the repository's test framework and language level, and tolerates its absence: the
    framework-dependent rules simply stay silent here, so a case can only pin the ones that hold
    for any repository. The repo-aware pairings are covered in tests/agents/test_validators.py, which can
    build a checkout.
    """
    try:
        validate_probe(None, ProbeSource(test_file_path=test_file_path, content=content))
    except ModelRetry as exc:
        body = str(exc).split(":\n- ", 1)
        return (
            [p.strip() for p in body[-1].split("\n- ") if p.strip()]
            if len(body) > 1
            else [str(exc)]
        )
    return []


# --- Authored cases ------------------------------------------------------------------------


@dataclass(frozen=True)
class SkillCase:
    """One authored scenario for a skill, executable against the production validators."""

    skill: str
    id: str
    type: str
    scenario: str
    regression: str = ""
    environment_spec: dict[str, Any] | None = None
    probe: dict[str, Any] | None = None
    expect_violations: tuple[str, ...] = ()
    """Substrings, each of which must appear in some violation. Empty means "expect clean"."""

    shown_in_skill: tuple[str, ...] = ()
    """Strings that must still appear in the SKILL.md, so a case cannot outlive its recipe."""

    @property
    def expects_clean(self) -> bool:
        return not self.expect_violations


def illustrative_commands(skill: SkillDoc) -> dict[str, str]:
    """Commands a skill shows to *discuss* rather than to recommend, mapped to the reason.

    An escape hatch, kept deliberately narrow and noisy: the entry must name the exact command
    and carry a reason, so waving a command past the validators is a reviewable line in a file
    rather than a silent hole. ``build-cpanm`` mentions ``cpanm --installdeps .`` mid-sentence
    while explaining what the flag covers; its actual recipe is the YAML spec above it.
    """
    path = skill.cases_path
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text()) or {}
    out: dict[str, str] = {}
    for entry in data.get("illustrative_commands") or []:
        reason = (entry.get("reason") or "").strip()
        if not reason:
            raise ValueError(
                f"{path}: illustrative_commands entry {entry.get('command')!r} has no reason. "
                "An unexplained exemption is indistinguishable from a bug being hidden"
            )
        out[entry["command"]] = reason
    return out


def load_cases(skill: SkillDoc) -> list[SkillCase]:
    """Authored cases for one skill; an empty list when the skill deliberately has none."""
    path = skill.cases_path
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text()) or {}
    declared = data.get("skill")
    if declared != skill.name:
        raise ValueError(f"{path} declares skill {declared!r}, but lives under {skill.name!r}")
    cases: list[SkillCase] = []
    for raw in data.get("cases") or []:
        cases.append(
            SkillCase(
                skill=skill.name,
                id=raw["id"],
                type=raw["type"],
                scenario=raw.get("scenario", ""),
                regression=raw.get("regression", ""),
                environment_spec=raw.get("environment_spec"),
                probe=raw.get("probe"),
                expect_violations=tuple(raw.get("expect_violations") or ()),
                shown_in_skill=tuple(raw.get("shown_in_skill") or ()),
            )
        )
    return cases


def run_case(case: SkillCase, skill: SkillDoc) -> list[str]:
    """Execute one case. Returns the reasons it failed, empty when it passed.

    A case naming ``expect_violations`` is as important as one expecting a clean result: it is
    what proves the validator would actually reject the mistake, rather than the rule merely
    being written down somewhere. A gate that has never been shown to fail is the failure mode
    ``inert_gates`` is about.
    """
    failures: list[str] = []
    for needle in case.shown_in_skill:
        if needle not in skill.body:
            failures.append(
                f"the case pins {needle!r} as something {skill.name} shows, and it is no longer "
                "in the skill: either the recipe changed and the case is stale, or the recipe "
                "lost a load-bearing part"
            )

    violations: list[str] | None = None
    if case.environment_spec is not None:
        raw = {k: v for k, v in case.environment_spec.items()}
        raw["test_command"] = resolve_placeholders(raw.get("test_command", ""))
        raw["install_commands"] = [resolve_placeholders(c) for c in raw.get("install_commands", [])]
        violations = spec_violations(EnvironmentSpec.model_validate(raw))
    elif case.probe is not None:
        violations = probe_exemplar_violations(
            case.probe["test_file_path"], resolve_placeholders(case.probe["content"])
        )
    else:
        failures.append("case declares neither an environment_spec nor a probe to judge")
        return failures

    if case.expects_clean:
        if violations:
            failures.append(
                "expected the harness to accept this, but it objected: " + "; ".join(violations)
            )
        return failures

    for needle in case.expect_violations:
        if not any(needle in v for v in violations):
            failures.append(
                f"expected a violation mentioning {needle!r}; the harness raised "
                + (f"{violations}" if violations else "nothing at all, so this gate is inert")
            )
    return failures
