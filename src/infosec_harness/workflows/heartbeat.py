"""Deliver Temporal cancellation to long-running async activities while preserving cleanup."""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from contextlib import suppress
from functools import wraps

from temporalio import activity


def with_heartbeat[**P, R](fn: Callable[P, Awaitable[R]]) -> Callable[P, Awaitable[R]]:
    @wraps(fn)
    async def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
        if not activity.in_activity():
            return await fn(*args, **kwargs)

        async def pulse() -> None:
            while True:
                activity.heartbeat()
                await asyncio.sleep(1)

        task = asyncio.create_task(pulse())
        try:
            return await fn(*args, **kwargs)
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
    return wrapped
