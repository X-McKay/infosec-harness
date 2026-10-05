"""Process, file, environment and ledger helpers shared by the qualification runners.

Nothing here grants inference, lifecycle or ledger authority; each helper only bounds or
observes what a runner already owns.
"""
from __future__ import annotations

import asyncio
import os
import shlex
import subprocess
from collections import Counter
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any

from infosec_harness._io import write_json

# Ambient provider, broker and object-store authority never reaches a qualification child.
_STRIPPED_PREFIXES = ("AWS_", "HARNESS_BROKER_")
_STRIPPED_NAMES = frozenset({"OPENAI_API_KEY", "HARNESS_OPENAI_API_KEY", "HARNESS_MODEL_BACKEND",
                             "HARNESS_NATIVE_TEMPORAL_CONFIG"})


def private_write(path: Path, value: Any, *, exclusive: bool = False) -> None:
    """Owner-only JSON, never world-readable at any point.

    ``exclusive`` creates the file once and fails if it exists; otherwise the file is
    replaced atomically.
    """
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    write_json(path, value, sort_keys=True, exclusive=exclusive)


def read_private_environment(path: str | Path) -> dict[str, str]:
    source = Path(path)
    if source.stat().st_mode & 0o077:
        raise ValueError("Credential reference must be owner-only")
    result = {}
    for line in source.read_text().splitlines():
        if line.strip() and not line.lstrip().startswith("#") and "=" in line:
            name, value = line.split("=", 1)
            parts = shlex.split(value)
            if len(parts) == 1:
                result[name.strip()] = parts[0]
    return result


def read_private_key(path: str | Path) -> str:
    """One owner-only, non-symlink credential reference file."""
    source = Path(path)
    if source.is_symlink() or source.stat().st_mode & 0o077:
        raise ValueError("Worker HMAC reference must be owner-only")
    secret = source.read_text().strip()
    if not secret or len(secret) > 4096:
        raise ValueError("Invalid worker credential reference")
    return secret


def child_environment(root: Path, *, models_config: str, database: dict[str, str],
                      worker_key: tuple[str, str] | None = None,
                      broker_config: str | None = None) -> dict[str, str]:
    """A qualification child's environment: live models, actual runsc and no ambient keys.

    ``worker_key`` names the broker channel key's environment variable and its private file;
    only a native child receives it, together with ``broker_config``.
    """
    values = {name: value for name, value in os.environ.items()
              if not name.startswith(_STRIPPED_PREFIXES) and name not in _STRIPPED_NAMES}
    if worker_key is not None:
        values.pop(worker_key[0], None)
    managed = root / ".harness/dev.env"
    if managed.exists():
        for name, value in read_private_environment(managed).items():
            if name.startswith(("HARNESS_SANDBOX_", "HARNESS_BUILD_")) or name == "HARNESS_BUILDX_BUILDER":
                values[name] = value
    values.update(database)
    values.update(HARNESS_MODEL_MODE="live", HARNESS_MODELS_CONFIG=models_config,
                  HARNESS_ALLOW_INSECURE_RUNTIME="false", HARNESS_SANDBOX_RUNTIME="runsc",
                  HARNESS_AGENT_RUN_TIMEOUT_S="600", PYDANTIC_AI_NO_BANNER="1",
                  PYTHONPATH=str(root / "src"))
    values["PATH"] = os.pathsep.join((str(root / ".harness/bin"), str(root / ".venv/bin"),
                                      values.get("PATH", "")))
    if broker_config is not None:
        if worker_key is None:
            raise ValueError("A native child requires its worker channel key")
        values[worker_key[0]] = read_private_key(worker_key[1])
        values["HARNESS_BROKER_CONFIG"] = broker_config
    return values


def reap(process: subprocess.Popen, *, grace: float = 10) -> bool:
    """Stop one exact owned child (never its group): terminate, then kill after ``grace``."""
    with suppress(ProcessLookupError):
        process.terminate()
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        with suppress(ProcessLookupError):
            process.kill()
        process.wait(timeout=grace)
    return process.poll() is not None


async def serve_worker(address: str, queue: str, workflows: Sequence[type], *,
                       activities: Sequence = (), ready: Path | None = None) -> None:
    """One Temporal worker on an owned queue; ``ready`` records its pid once it is built."""
    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from temporalio.client import Client
    from temporalio.worker import Worker

    client = await Client.connect(address, plugins=[PydanticAIPlugin()])
    worker = Worker(client, task_queue=queue, workflows=list(workflows), activities=list(activities))
    if ready is not None:
        ready.write_text(str(os.getpid()))
    await worker.run()


async def ledger_snapshot(root_id: str) -> dict:
    """The root and its request rows; results are summarized, never copied into reports."""
    from sqlalchemy import select

    from infosec_harness.domain.canonical import digest
    from infosec_harness.persistence import db

    async with db.session() as session:
        root = await session.get(db.BudgetLedger, root_id)
        records = (await session.execute(select(db.InferenceRequestRecord).where(
            db.InferenceRequestRecord.root_id == root_id))).scalars().all()
        rows = sorted(records, key=lambda row: row.request_id)
        return {"root_id": root_id, "root_state": root.state if root else None,
            "requests": [{"request_id": row.request_id, "agent": row.request["binding"]["agent"],
                          "state": row.state, "revision": row.revision, "allocation": row.allocation,
                          "overrun": row.overrun,
                          "result_usage": row.result.get("usage") if row.result else None,
                          "result_sha256": digest(row.result) if row.result else None,
                          "payload_digest": row.request["payload_digest"]} for row in rows],
            "request_states": dict(Counter(row.state for row in rows))}


_ABSENT = object()


def _forbidden(message: str):
    async def forbidden(*_args, **_kwargs):
        raise AssertionError(message)
    return forbidden


@contextmanager
def forbid_io(*, synchronous: bool = False) -> Iterator[None]:
    """Make every broker, HTTP, database and subprocess entry point fail during history replay.

    Replay must consume recorded results only. ``synchronous`` additionally forbids database
    sessions and subprocesses, which a production graph replay never needs.
    """
    import httpx
    import httpx2

    from infosec_harness.inference.worker import invocations
    from infosec_harness.inference.worker.transport import BrokerModel
    from infosec_harness.persistence import db

    message = "History replay attempted external I/O"

    def forbidden_sync(*_args, **_kwargs):
        raise AssertionError(message)

    seams: list[tuple[Any, str, Any]] = [
        (BrokerModel, "request", _forbidden(message)),
        (invocations, "request_invocation", _forbidden(message)),
        (httpx.AsyncClient, "request", _forbidden(message)),
        (httpx2.AsyncClient, "request", _forbidden(message)),
    ]
    if synchronous:
        seams += [(db, "session", forbidden_sync), (subprocess, "Popen", forbidden_sync),
                  (asyncio, "create_subprocess_exec", _forbidden(message))]
    # Restore exactly what each owner defined itself; an inherited attribute is not shadowed.
    originals = [(owner, name, vars(owner).get(name, _ABSENT)) for owner, name, _ in seams]
    try:
        for owner, name, replacement in seams:
            setattr(owner, name, replacement)
        yield
    finally:
        for owner, name, original in reversed(originals):
            if original is _ABSENT:
                delattr(owner, name)
            else:
                setattr(owner, name, original)
