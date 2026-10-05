"""The one walker over captured pydantic-ai messages that every eval diagnostic shares.

Captured messages carry model- and provider-controlled content, so a diagnostic that reads
them must be bounded in how much it scans and must never echo what it reads. The limits live
here, once; each diagnostic decides what to count, not how far to look.

A :class:`Walk` records whether a bound cut the scan short. Runtime trajectory records use an
unbounded walk (``Walk.unbounded()``) because they describe the whole run, not a sample of it.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from typing import Literal

from pydantic_ai.messages import (
    ModelMessage,
    ModelRequest,
    ModelRequestPart,
    ModelResponse,
    ModelResponsePart,
    RetryPromptPart,
    ToolCallPart,
)

MAX_MESSAGES = 128
MAX_PARTS = 512
MAX_PROPOSALS = 32
MAX_TEXT_CHARS = 131_072
MAX_NODES = 2048
MAX_DEPTH = 8
MAX_INT_BITS = 4096

# PydanticAI's default structured-output tool. Output tools are how an agent answers, not tool
# use, and `_`-prefixed tools are the framework's own.
OUTPUT_TOOL = "final_result"

ArgumentProblem = Literal["bounded_out", "unsupported_shape", "malformed_json"]


def is_function_tool(name: str) -> bool:
    """True for a tool the agent *used*, false for output and framework-internal tools."""
    return not (name.startswith(OUTPUT_TOOL) or name.startswith("_"))


@dataclass
class Walk:
    """Bounds for one scan over a message history, and whether they were hit."""

    max_messages: int | None = MAX_MESSAGES
    max_parts: int | None = MAX_PARTS
    truncated: bool = False

    @classmethod
    def unbounded(cls) -> Walk:
        return cls(max_messages=None, max_parts=None)

    def parts[P: (ModelRequestPart, ModelResponsePart)](
        self, messages: Iterable[ModelMessage], kind: type[ModelRequest] | type[ModelResponse]
    ) -> Iterator[P]:
        """Every part of every message of ``kind``, in order, until a bound is reached.

        Messages of the other kind still count toward the message bound; only parts of the
        selected kind count toward the part bound.
        """
        scanned = 0
        for number, message in enumerate(messages):
            if self.max_messages is not None and number >= self.max_messages:
                self.truncated = True
                return
            if not isinstance(message, kind):
                continue
            for part in message.parts:
                if self.max_parts is not None and scanned >= self.max_parts:
                    self.truncated = True
                    return
                scanned += 1
                yield part

    def limit[T](self, items: Iterable[T], maximum: int) -> Iterator[T]:
        """At most ``maximum`` items; a further item marks the walk truncated."""
        for taken, item in enumerate(items):
            if taken >= maximum:
                self.truncated = True
                return
            yield item


def iter_tool_calls(
    messages: Sequence[ModelMessage], walk: Walk | None = None
) -> Iterator[ToolCallPart]:
    """Calls to function tools (not output or internal tools). Unbounded unless told."""
    walk = walk if walk is not None else Walk.unbounded()
    for part in walk.parts(messages, ModelResponse):
        if isinstance(part, ToolCallPart) and is_function_tool(part.tool_name):
            yield part


def iter_output_proposals(
    messages: Sequence[ModelMessage], walk: Walk
) -> Iterator[ToolCallPart]:
    """The structured-output proposals a model made, at most :data:`MAX_PROPOSALS`."""
    proposals = (
        part
        for part in walk.parts(messages, ModelResponse)
        if isinstance(part, ToolCallPart) and part.tool_name == OUTPUT_TOOL
    )
    yield from walk.limit(proposals, MAX_PROPOSALS)


def iter_retry_prompts(
    messages: Sequence[ModelMessage], walk: Walk, maximum: int
) -> Iterator[RetryPromptPart]:
    """Retry feedback the SDK sent back to the model, at most ``maximum``."""
    retries = (
        part for part in walk.parts(messages, ModelRequest) if isinstance(part, RetryPromptPart)
    )
    yield from walk.limit(retries, maximum)


def bounded_shape(value: object) -> Literal["unsupported_shape", "bounded_out"] | None:
    """Check a decoded argument tree against the bounds without serializing any of it."""
    stack, nodes, chars = [(value, 0)], 0, 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            return "bounded_out"
        if isinstance(item, str):
            chars += len(item)
            if chars > MAX_TEXT_CHARS:
                return "bounded_out"
        elif isinstance(item, dict):
            if len(item) > MAX_NODES:
                return "bounded_out"
            if not all(isinstance(key, str) for key in item):
                return "unsupported_shape"
            stack.extend((child, depth + 1) for pair in item.items() for child in pair)
        elif isinstance(item, list):
            if len(item) > MAX_NODES:
                return "bounded_out"
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, int):
            if item.bit_length() > MAX_INT_BITS:
                return "bounded_out"
        elif item is not None and not isinstance(item, float):
            return "unsupported_shape"
    return None


def shape_size(value: object) -> tuple[int, int]:
    """(nodes, string characters) of a tree that already passed :func:`bounded_shape`."""
    stack, nodes, chars = [value], 0, 0
    while stack:
        item = stack.pop()
        nodes += 1
        if isinstance(item, str):
            chars += len(item)
        elif isinstance(item, dict):
            stack.extend(child for pair in item.items() for child in pair)
        elif isinstance(item, list):
            stack.extend(item)
    return nodes, chars


def decode_arguments(args: object) -> tuple[dict | None, ArgumentProblem | None]:
    """Decode tool-call arguments within the bounds: ``(mapping, None)`` or ``(None, why)``."""
    if isinstance(args, str):
        if len(args) > MAX_TEXT_CHARS:
            return None, "bounded_out"
        try:
            args = json.loads(args)
        except ValueError:
            return None, "malformed_json"
        except Exception:
            return None, "unsupported_shape"
    if not isinstance(args, dict):
        return None, "unsupported_shape"
    problem = bounded_shape(args)
    return (None, problem) if problem is not None else (args, None)
