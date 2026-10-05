"""Score an agent run's trajectory: did it evoke the tools and skills it should have?

The runtime records tools_called / skills_loaded on every AgentOutcome with
``agents.trajectory.trace_calls``; here ``check_expectations`` scores them (the
"expected tools and skills are being read/evoked" question).

Under stub models no tools are called, so these are empty; they light up under a live model
and are exercised deterministically in tests via a scripted tool-calling model.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from functools import cache

from pydantic_ai.messages import ModelMessage

from infosec_harness.agents.capabilities import REPO_RO_TOOLS
from infosec_harness.agents.trajectory import trace_calls
from infosec_harness.evals.messages import MAX_NAME_CHARS, MAX_RECORDED_CALLS
from infosec_harness.settings import get_settings


@dataclass
class TrajectoryExpectation:
    """What a given agent should evoke on a case, expressed as signals (any-of)."""

    # The run passes the tool check if it called at least one tool from each required group.
    tool_groups: tuple[frozenset[str], ...] = ()
    # The run passes the skill check if it loaded at least one skill matching a prefix.
    skill_prefixes: tuple[str, ...] = ()


@dataclass
class TrajectoryResult:
    tools_called: list[str]
    skills_loaded: list[str]
    tools_ok: bool
    skills_ok: bool
    missing_tool_groups: list[list[str]]
    missing_skill_prefixes: list[str]

    @property
    def ok(self) -> bool:
        return self.tools_ok and self.skills_ok


def check_expectations(tools_called: Iterable[str], skills_loaded: Iterable[str],
                       expectation: TrajectoryExpectation) -> TrajectoryResult:
    tools = list(tools_called)
    skills = list(skills_loaded)
    missing_groups = [sorted(g) for g in expectation.tool_groups if not (set(g) & set(tools))]
    missing_prefixes = [p for p in expectation.skill_prefixes
                        if not any(s.startswith(p) for s in skills)]
    return TrajectoryResult(
        tools_called=tools, skills_loaded=skills,
        tools_ok=not missing_groups, skills_ok=not missing_prefixes,
        missing_tool_groups=missing_groups, missing_skill_prefixes=missing_prefixes,
    )


# What each tool-using agent is expected to evoke. Read-only file access is the core
# signal (the agent must actually look at the code); Skills-only agents just need the
# relevant skill loaded. Agents with no tools are absent.
# describe_callables belongs here: it is how an agent learns a symbol's name, signature and
# import form. Omitting it would score an agent that used it well as having read nothing.
READ_TOOLS = frozenset(REPO_RO_TOOLS)
AGENT_EXPECTATIONS: dict[str, TrajectoryExpectation] = {
    "recon": TrajectoryExpectation(tool_groups=(READ_TOOLS,)),
    "env-planner": TrajectoryExpectation(tool_groups=(READ_TOOLS,)),
    "context": TrajectoryExpectation(tool_groups=(READ_TOOLS,), skill_prefixes=("cwe-",)),
    "probe-author": TrajectoryExpectation(tool_groups=(READ_TOOLS,), skill_prefixes=("probe-oracle-protocol",)),
}


def scores_skills(agent: str) -> bool:
    """Whether this agent is actually checked on skill evocation.

    An agent with no ``skill_prefixes`` trivially satisfies the skill check, so reporting it
    as 100% claims a pass that was never tested. Callers use this to print "n/a" instead.
    """
    exp = AGENT_EXPECTATIONS.get(agent)
    return bool(exp and exp.skill_prefixes)


_CWE_SKILL = re.compile(r"cwe-(\d+)-.+")


@cache
def skill_covered_cwes() -> tuple[str, ...]:
    """The CWE classes a shipped `skills/cwe-<n>-*` skill covers, as ``CWE-<n>``, sorted.

    The single answer to "which CWEs have skills", used by the trajectory scorer and by the
    corpus harvester, so the two cannot disagree about what a harvested case can be scored on.
    """
    root = get_settings().skills_dir
    if not root.is_dir():
        return ()
    found = {int(m.group(1)) for p in root.iterdir()
             if p.is_dir() and (m := _CWE_SKILL.fullmatch(p.name))}
    return tuple(f"CWE-{number}" for number in sorted(found))


def cwe_skill_prefix(cwe: str | None) -> str | None:
    """Map CWE-89 -> the 'cwe-89' skill prefix so we can check the *matching* skill loaded.

    Returns None when no such skill exists. The seeded corpus only uses the eight classes we
    cover, but a harvested dataset does not: Vul4J spans 37 CWEs we have no skill for, and
    demanding the "matching" skill there would score an agent for failing to load a file that
    is not on disk. The honest answer is that skill loading is unscoreable for those cases.
    """
    if not cwe:
        return None
    num = cwe.upper().removeprefix("CWE-")
    if not num.isdigit():
        return None
    return f"cwe-{num}" if f"CWE-{num}" in skill_covered_cwes() else None


def summarize_calls(messages: Sequence[ModelMessage], *,
                    limit: int = MAX_RECORDED_CALLS) -> dict[str, object]:
    """Retain call order using encounter-local IDs, without recoverable argument hashes.

    Repetition is ``agents.trajectory.trace_calls``'s signature, so this summary and the
    runtime's ``repeated_tool_calls`` agree on what counts as the same call.
    """
    trace = trace_calls(messages)
    counts = Counter(name for name, _ in trace.sequence)
    sequence: list[dict[str, str]] = []
    argument_ids: dict[str, str] = {}
    for name, signature in trace.sequence[:limit]:
        argument_id = argument_ids.setdefault(signature, f"args-{len(argument_ids) + 1}")
        sequence.append({"tool": name[:MAX_NAME_CHARS], "argument_id": argument_id})
    total = len(trace.sequence)
    return {
        "tool_call_count": total,
        "counts": dict(sorted(counts.items())[:limit]),
        "sequence": sequence,
        "sequence_truncated": total > limit,
        "repeated_call_count": sum(count - 1 for count in trace.signatures.values()),
        "arguments_retained": False,
    }
