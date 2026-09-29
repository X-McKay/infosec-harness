"""Distinguish the evaluator's agent deadline from failures inside an invocation."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable


class AgentRunTimeout(TimeoutError):
    """The evaluator stopped an agent at its declared wall-clock limit."""


async def run_with_timeout[T](invocation: Awaitable[T], seconds: float) -> T:
    deadline = asyncio.timeout(seconds)
    try:
        async with deadline:
            return await invocation
    except TimeoutError as exc:
        if deadline.expired():
            raise AgentRunTimeout("Agent exceeded its configured time budget") from exc
        raise
