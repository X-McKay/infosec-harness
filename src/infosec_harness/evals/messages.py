"""The one walker over captured pydantic-ai messages that every eval diagnostic shares.

Captured messages carry model- and provider-controlled content, so a diagnostic that reads
them must be bounded in how much it scans and must never echo what it reads. The limits live
here, once; each diagnostic decides what to count, not how far to look.

A :class:`Walk` records whether a bound cut the scan short. Tool-call accounting
(``agents.trajectory``) scans the whole run instead, because it describes the run, not a sample.
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

from infosec_harness.runtime.trajectory import OUTPUT_TOOL

# How much of a captured history one diagnostic scans.
MAX_MESSAGES = 128
MAX_PARTS = 512
MAX_PROPOSALS = 32
MAX_RETRY_PARTS = 32
# How large a decoded argument tree may be before a diagnostic refuses to look inside it.
MAX_TEXT_CHARS = 131_072
MAX_NODES = 2048
MAX_DEPTH = 8
MAX_INT_BITS = 4096
# The longest retry feedback text classified against the guard's closed sentences.
MAX_RETRY_CONTENT_CHARS = 4096
# How much of a tool trajectory a persisted call summary keeps: distinct tools and sequence
# entries recorded, and the characters of a model-chosen name or label retained or parsed.
MAX_RECORDED_CALLS = 128
MAX_NAME_CHARS = 128

ArgumentProblem = Literal["bounded_out", "unsupported_shape", "malformed_json"]


@dataclass
class Walk:
    """Bounds for one scan over a message history, and whether they were hit."""

    max_messages: int = MAX_MESSAGES
    max_parts: int = MAX_PARTS
    truncated: bool = False

    def parts[P: (ModelRequestPart, ModelResponsePart)](
        self, messages: Iterable[ModelMessage], kind: type[ModelRequest] | type[ModelResponse]
    ) -> Iterator[P]:
        """Every part of every message of ``kind``, in order, until a bound is reached.

        Messages of the other kind still count toward the message bound; only parts of the
        selected kind count toward the part bound.
        """
        scanned = 0
        for number, message in enumerate(messages):
            if number >= self.max_messages:
                self.truncated = True
                return
            if not isinstance(message, kind):
                continue
            for part in message.parts:
                if scanned >= self.max_parts:
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


def measure_shape(value: object) -> tuple[int, int] | Literal["unsupported_shape", "bounded_out"]:
    """``(nodes, string characters)`` of a decoded argument tree, or why it is out of bounds.

    One traversal both enforces the bounds and sizes the tree, without serializing any of it.
    """
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
    measured = measure_shape(args)
    return (None, measured) if isinstance(measured, str) else (args, None)
