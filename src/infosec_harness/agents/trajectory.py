"""What an agent run did: the tools it called and the skills it loaded.

Every AgentOutcome records these, so real runs are auditable and persisted. The eval package
scores them against expectations (``evals.trajectory``); the runtime must not depend on it.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import dataclass

from pydantic_ai.messages import ModelMessage, ModelResponse, ToolCallPart

# PydanticAI's default structured-output tool. Output tools are how an agent answers, not tool
# use, and `_`-prefixed tools are the framework's own.
OUTPUT_TOOL = "final_result"
# The Skills capability exposes this tool; its argument carries the skill id being loaded.
LOAD_SKILL_TOOL = "load_capability"
_SKILL_ARG_KEYS = ("id", "capability_id", "name")


def is_function_tool(name: str) -> bool:
    """True for a tool the agent *used*, false for output and framework-internal tools."""
    return not (name.startswith(OUTPUT_TOOL) or name.startswith("_"))


def function_tool_calls(messages: Sequence[ModelMessage]) -> Iterator[ToolCallPart]:
    """Every call to a function tool, over the whole run."""
    for message in messages:
        if isinstance(message, ModelResponse):
            for part in message.parts:
                if isinstance(part, ToolCallPart) and is_function_tool(part.tool_name):
                    yield part


def _skill_id(args: dict | None) -> str | None:
    if isinstance(args, dict):
        for key in _SKILL_ARG_KEYS:
            if key in args and isinstance(args[key], str):
                return args[key]
        for v in args.values():  # fall back to the first string arg
            if isinstance(v, str):
                return v
    return None


@dataclass(frozen=True)
class CallTrace:
    """One pass over a run's function-tool calls; every trajectory view derives from it.

    ``tools`` and ``skills`` are de-duplicated and order-preserving (``load_capability`` calls
    become skills, not tools). ``signatures`` counts each ``tool(arg=value, ...)`` key, with
    arguments sorted so the key is stable; ``sequence`` is every call's (tool, signature) in
    order. Arguments the model sent malformed count as ``None`` everywhere: one policy, so the
    runtime record and the eval summary agree on what a repeated call is.
    """

    tools: list[str]
    skills: list[str]
    signatures: Counter[str]
    sequence: list[tuple[str, str]]

    @property
    def repeated(self) -> dict[str, int]:
        """Calls made with the *same arguments* more than once, by signature.

        De-duplicating by tool name is right for measuring evocation ("did the agent use its
        tools at all") but makes a run that read one file eight times identical to one that
        read it once. That is the distinction needed to tell a runaway loop from legitimate
        work when an agent exhausts its request budget. Only counts above one are returned,
        so a healthy run yields an empty dict.
        """
        return {key: n for key, n in self.signatures.items() if n > 1}


def _arguments(call: ToolCallPart) -> dict | None:
    # By default PydanticAI turns malformed JSON into ``{"INVALID_JSON": raw}``, which would
    # record the raw text as a loaded skill id; malformed arguments must neither break the
    # accounting nor be read as arguments.
    try:
        return call.args_as_dict(raise_if_invalid=True)
    except (ValueError, AssertionError):
        return None


def _signature(name: str, args: dict | None) -> str:
    rendered = (", ".join(f"{k}={args[k]!r}" for k in sorted(args)) if args is not None
                else repr(None))
    return f"{name}({rendered})"


def trace_calls(messages: Sequence[ModelMessage]) -> CallTrace:
    """Trace every function-tool call; output tools (``final_result`` and friends) are excluded."""
    tools: list[str] = []
    skills: list[str] = []
    signatures: Counter[str] = Counter()
    sequence: list[tuple[str, str]] = []
    for call in function_tool_calls(messages):
        name = call.tool_name
        args = _arguments(call)
        signature = _signature(name, args)
        signatures[signature] += 1
        sequence.append((name, signature))
        if name == LOAD_SKILL_TOOL:
            sid = _skill_id(args)
            if sid and sid not in skills:
                skills.append(sid)
        elif name not in tools:
            tools.append(name)
    return CallTrace(tools=tools, skills=skills, signatures=signatures, sequence=sequence)
