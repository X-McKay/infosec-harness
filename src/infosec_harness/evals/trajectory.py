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

from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from functools import cache

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


def count_repeated_calls(messages: Sequence[ModelMessage]) -> dict[str, int]:
    """Count tool calls that were made with the *same arguments* more than once.

    `inspect_messages` de-duplicates by tool name and discards arguments, which is right for
    measuring evocation ("did the agent use its tools at all") but makes a run that read one
    file eight times byte-identical to one that read it once. That is exactly the distinction
    needed to tell a runaway loop from legitimate work when an agent exhausts its request
    budget, so it is counted separately here rather than by loosening the contract above.

    Keys are `tool(arg=value, ...)` with arguments sorted so the key is stable; only entries
    with a count above one are returned, so a healthy run yields an empty dict and costs
    nothing to record.
    """
    seen: Counter[str] = Counter()
    for call in _tool_calls(messages):
        name = call.tool_name
        if name.startswith("final_result") or name.startswith("_"):
            continue
        try:
            args = call.args_as_dict() if hasattr(call, "args_as_dict") else call.args
        except Exception:  # malformed args from the model must not break accounting
            args = None
        if isinstance(args, dict):
            rendered = ", ".join(f"{k}={args[k]!r}" for k in sorted(args))
        else:
            rendered = repr(args)
        seen[f"{name}({rendered})"] += 1
    return {key: n for key, n in seen.items() if n > 1}


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
READ_TOOLS = frozenset({"read_file", "search_code", "list_files", "describe_callables", "inspect_target", "read_files", "list_tree", "repo_digest"})
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


@cache
def _available_cwe_skill_prefixes() -> frozenset[str]:
    """The `cwe-*` skills that exist on disk, as prefixes."""
    from infosec_harness.settings import get_settings

    root = get_settings().skills_dir
    if not root.is_dir():
        return frozenset()
    return frozenset("-".join(p.name.split("-")[:2])
                     for p in root.iterdir() if p.name.startswith("cwe-"))


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
    prefix = f"cwe-{num}"
    return prefix if prefix in _available_cwe_skill_prefixes() else None


def summarize_calls(messages: Sequence[ModelMessage], *, limit: int = 128) -> dict[str, object]:
    """Retain call order using encounter-local IDs, without recoverable argument hashes."""
    import hashlib
    import json

    counts: Counter[str] = Counter()
    signatures: Counter[tuple[str, str]] = Counter()
    sequence: list[dict[str, str]] = []
    argument_ids: dict[tuple[str, str], str] = {}
    for call in _tool_calls(messages):
        name = call.tool_name
        if name.startswith("final_result") or name.startswith("_"):
            continue
        try:
            args = call.args_as_dict()
        except Exception:
            args = {"malformed": True}
        digest = hashlib.sha256(
            json.dumps(args, sort_keys=True, default=str).encode()
        ).hexdigest()
        counts[name] += 1
        signature = (name, digest)
        signatures[signature] += 1
        if len(sequence) < limit:
            argument_id = argument_ids.setdefault(signature, f"args-{len(argument_ids) + 1}")
            sequence.append({"tool": name[:128], "argument_id": argument_id})
    total = sum(counts.values())
    return {
        "tool_call_count": total,
        "counts": dict(sorted(counts.items())[:limit]),
        "sequence": sequence,
        "sequence_truncated": total > limit,
        "repeated_call_count": sum(count - 1 for count in signatures.values()),
        "arguments_retained": False,
    }
