"""Inspect an agent run's trajectory: which tools it called and which skills it loaded.

Used two ways:
- at run time, ``inspect_messages`` records tools_called / skills_loaded on every
  AgentOutcome (so real runs are auditable and persisted);
- in evals, ``check_expectations`` scores whether an agent evoked the tools and skills it
  should have (the "expected tools and skills are being read/evoked" question).

Under stub models no tools are called, so these are empty; they light up under a live model
and are exercised deterministically in tests via a scripted tool-calling model.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from pydantic_ai.messages import ModelMessage, ToolCallPart

# The Skills capability exposes this tool; its argument carries the skill id being loaded.
LOAD_SKILL_TOOL = "load_capability"
_SKILL_ARG_KEYS = ("id", "capability_id", "name")


def _tool_calls(messages: Sequence[ModelMessage]) -> list[ToolCallPart]:
    calls: list[ToolCallPart] = []
    for msg in messages:
        for part in getattr(msg, "parts", []):
            if isinstance(part, ToolCallPart):
                calls.append(part)
    return calls


def _skill_id(args) -> str | None:
    if isinstance(args, dict):
        for key in _SKILL_ARG_KEYS:
            if key in args and isinstance(args[key], str):
                return args[key]
        for v in args.values():  # fall back to the first string arg
            if isinstance(v, str):
                return v
    return None


def inspect_messages(messages: Sequence[ModelMessage]) -> tuple[list[str], list[str]]:
    """Return (tools_called, skills_loaded), each de-duplicated and order-preserving.

    Output tools (``final_result`` and friends) are excluded — they are how the agent
    returns its answer, not tool *use*.
    """
    tools: list[str] = []
    skills: list[str] = []
    for call in _tool_calls(messages):
        name = call.tool_name
        if name == LOAD_SKILL_TOOL:
            sid = _skill_id(call.args_as_dict() if hasattr(call, "args_as_dict") else call.args)
            if sid and sid not in skills:
                skills.append(sid)
            continue
        if name.startswith("final_result") or name.startswith("_"):
            continue
        if name not in tools:
            tools.append(name)
    return tools, skills


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
READ_TOOLS = frozenset({"read_file", "search_code", "list_files"})
AGENT_EXPECTATIONS: dict[str, TrajectoryExpectation] = {
    "recon": TrajectoryExpectation(tool_groups=(READ_TOOLS,)),
    "env_planner": TrajectoryExpectation(tool_groups=(READ_TOOLS,)),
    "context": TrajectoryExpectation(tool_groups=(READ_TOOLS,), skill_prefixes=("cwe-",)),
    "probe_author": TrajectoryExpectation(tool_groups=(READ_TOOLS,), skill_prefixes=("probe-oracle-protocol",)),
}


def cwe_skill_prefix(cwe: str | None) -> str | None:
    """Map CWE-89 -> the 'cwe-89' skill prefix so we can check the *matching* skill loaded."""
    if not cwe:
        return None
    num = cwe.upper().removeprefix("CWE-")
    return f"cwe-{num}" if num.isdigit() else None
