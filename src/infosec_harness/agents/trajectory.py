"""What an agent run did: the tools it called and the skills it loaded.

Every AgentOutcome records these, so real runs are auditable and persisted. The eval package
scores them against expectations (``evals.trajectory``); the runtime must not depend on it.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator, Sequence

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
    for call in function_tool_calls(messages):
        name = call.tool_name
        if name == LOAD_SKILL_TOOL:
            sid = _skill_id(call.args_as_dict())
            if sid and sid not in skills:
                skills.append(sid)
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
    for call in function_tool_calls(messages):
        name = call.tool_name
        try:
            args = call.args_as_dict()
        except Exception:  # malformed args from the model must not break accounting
            args = None
        if isinstance(args, dict):
            rendered = ", ".join(f"{k}={args[k]!r}" for k in sorted(args))
        else:
            rendered = repr(args)
        seen[f"{name}({rendered})"] += 1
    return {key: n for key, n in seen.items() if n > 1}
