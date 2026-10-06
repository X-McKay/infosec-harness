"""The one owned subprocess runner (source checkout and read-only container inspection).

Every child gets its own process group, an explicit environment and no stdin. Output is
captured with a bound per stream. A timeout or cancellation kills the whole group and reaps it
before the caller regains control, including while further cancellation requests arrive: an
owned child must never keep mutating state after its caller has given up on it.
"""

from __future__ import annotations

import asyncio
import os
import signal
from collections.abc import Iterable, Mapping
from contextlib import suppress
from dataclasses import dataclass

_CHUNK = 16_384
# After the group is killed, a reader can only stay blocked if a descendant escaped the group
# and still holds the pipe. Give the pipes this long to close, then abandon them.
_DRAIN_GRACE_S = 5.0


@dataclass(frozen=True)
class ProcessResult:
    """The one result shape for every owned child.

    Output is decoded with replacement characters: it is untrusted text for display and
    parsing, never bytes the harness re-executes. A caller that needs strict decoding has no
    business reading child output.
    """

    exit_code: int | None  # None when the run timed out and the group was killed.
    stdout: str
    stderr: str
    timed_out: bool
    truncated: bool = False  # A stream exceeded capture_limit; only its tail was kept.


class _Tail:
    def __init__(self, limit: int):
        self.limit, self.data, self.truncated = limit, bytearray(), False

    def add(self, chunk: bytes) -> None:
        self.data.extend(chunk)
        if len(self.data) > self.limit:
            del self.data[: len(self.data) - self.limit]
            self.truncated = True


async def finish[T](future: asyncio.Future[T]) -> T:
    """Await an owned operation to completion despite repeated cancellation requests.

    The caller's cancellation is not lost: it stays requested on the calling task, so a
    caller that must still propagate it re-raises its own ``CancelledError`` afterwards.
    """
    while not future.done():
        with suppress(asyncio.CancelledError):
            await asyncio.shield(future)
    return future.result()


async def _drain(stream: asyncio.StreamReader | None, sink: _Tail) -> None:
    if stream is None:
        return
    while chunk := await stream.read(_CHUNK):
        sink.add(chunk)


def _kill_group(process: asyncio.subprocess.Process) -> None:
    with suppress(ProcessLookupError, PermissionError):
        os.killpg(process.pid, signal.SIGKILL)
    with suppress(ProcessLookupError):
        process.kill()


async def _reap(waiter: asyncio.Future, streams: Iterable[asyncio.Future]) -> None:
    """Reap the killed child, then give its pipes a bounded grace period."""
    with suppress(Exception):
        await finish(waiter)
    pending = [task for task in streams if not task.done()]
    if pending:
        bounded = asyncio.ensure_future(asyncio.wait(pending, timeout=_DRAIN_GRACE_S))
        with suppress(Exception):
            await finish(bounded)
        for task in pending:
            task.cancel()


async def run_bounded(
    argv: list[str],
    *,
    env: Mapping[str, str],
    timeout: float,
    capture_limit: int = 64_000,
    cwd: str | None = None,
) -> ProcessResult:
    """Run ``argv`` to completion or to ``timeout`` (then kill its group); never raise on exit.

    Raises ``OSError`` when the executable cannot be started, and re-raises cancellation only
    after the group has been killed and reaped. A timeout is reported in the result.
    """
    spawning = asyncio.ensure_future(
        asyncio.create_subprocess_exec(
            *argv,
            env=dict(env),
            cwd=cwd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
    )
    try:
        process = await asyncio.shield(spawning)
    except asyncio.CancelledError:
        # The spawn may still succeed; an owned child must not outlive this call.
        with suppress(Exception):
            process = await finish(spawning)
            _kill_group(process)
            await finish(asyncio.ensure_future(process.wait()))
        raise
    out, err = _Tail(capture_limit), _Tail(capture_limit)
    readers = [
        asyncio.ensure_future(_drain(process.stdout, out)),
        asyncio.ensure_future(_drain(process.stderr, err)),
    ]
    waiter = asyncio.ensure_future(process.wait())
    timed_out = False
    try:
        async with asyncio.timeout(timeout):
            await asyncio.shield(asyncio.gather(waiter, *readers))
    except TimeoutError:
        timed_out = True
        _kill_group(process)
        await _reap(waiter, readers)
    except BaseException:
        _kill_group(process)
        await _reap(waiter, readers)
        raise
    return ProcessResult(
        exit_code=None if timed_out else process.returncode,
        stdout=out.data.decode(errors="replace"),
        stderr=err.data.decode(errors="replace"),
        timed_out=timed_out,
        truncated=out.truncated or err.truncated,
    )
