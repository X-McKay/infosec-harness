#!/usr/bin/env python3
"""Read-only database/schema and recent Temporal poller checks; no workflow dispatch."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import re
import socket
from datetime import UTC, datetime
from pathlib import Path

from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine
from temporalio.api.enums.v1 import TaskQueueType
from temporalio.api.taskqueue.v1 import TaskQueue
from temporalio.api.workflowservice.v1 import DescribeTaskQueueRequest
from temporalio.client import Client

from infosec_harness.persistence.db import database_connect_args
from infosec_harness.qualification.ledger import read_bytes
from infosec_harness.resources import package_root
from infosec_harness.services import temporal_connection_options
from infosec_harness.settings import get_settings


def gate(status: str, detail: str) -> dict[str, str]:
    return {"status": status, "detail": detail}


def fingerprint(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return hashlib.sha256(read_bytes(path)).hexdigest()
    except Exception:
        return None


async def check_database(settings) -> dict[str, str]:
    engine = None
    try:
        url = make_url(settings.database_url)
        if url.get_backend_name() == "sqlite":
            # A readiness check must never create a missing database, including a race
            # between existence testing and opening it. Explicit URI mode=ro enforces this.
            if not url.database or url.database == ":memory:" or not Path(url.database).is_file():
                return gate("failed", "Existing database unavailable")
            url = url.set(
                database="file:" + str(Path(url.database).resolve()),
                query={"mode": "ro", "uri": "true"},
            )
        engine = create_async_engine(url, connect_args=database_connect_args(str(url), settings))
        async with engine.connect() as connection:
            if await connection.scalar(text("SELECT 1")) != 1:
                return gate("failed", "Database query failed")
            revisions = set(
                (
                    await connection.execute(text("SELECT version_num FROM alembic_version"))
                ).scalars()
            )
            heads = set(ScriptDirectory(package_root() / "persistence/migrations").get_heads())
            if not heads or revisions != heads:
                return gate("failed", "Database schema is not current")
        return gate("passed", "Database query and schema revision passed")
    except Exception:
        return gate("failed", "Database check failed")
    finally:
        if engine is not None:
            await engine.dispose()


def recent_poller(poller, now: datetime, hostname: str | None) -> bool:
    try:
        timestamp = poller.last_access_time.ToDatetime(tzinfo=UTC)
        if timestamp.tzinfo is None or not 0 <= (now - timestamp).total_seconds() <= 60:
            return False
        if hostname is not None:
            # Temporal's default identity is PID@hostname. Substring matches can
            # accidentally accept another worker or a stale deployment's identity.
            prefix, separator, actual = poller.identity.partition("@")
            return bool(separator and prefix.isdecimal() and actual == hostname)
        return True
    except Exception:
        return False


async def check_pollers(settings, timeout: float, hostname: str | None) -> dict:
    labels = {
        "workflow_pollers": TaskQueueType.TASK_QUEUE_TYPE_WORKFLOW,
        "activity_pollers": TaskQueueType.TASK_QUEUE_TYPE_ACTIVITY,
    }
    result = {label: gate("failed", "Temporal connection failed") for label in labels}
    try:
        client = await asyncio.wait_for(
            Client.connect(
                settings.temporal_address,
                namespace=settings.temporal_namespace,
                **temporal_connection_options(settings),
            ),
            timeout,
        )
    except Exception:
        return result
    for label, kind in labels.items():
        try:
            response = await asyncio.wait_for(
                client.workflow_service.describe_task_queue(
                    DescribeTaskQueueRequest(
                        namespace=settings.temporal_namespace,
                        task_queue=TaskQueue(name=settings.task_queue),
                        task_queue_type=kind,
                    )
                ),
                timeout,
            )
            passed = any(
                recent_poller(poller, datetime.now(UTC), hostname) for poller in response.pollers
            )
            detail = (
                "Recent requested worker poller observed"
                if hostname is not None
                else "Recent queue poller observed; worker identity not checked"
            )
            result[label] = (
                gate("passed", detail)
                if passed
                else gate("failed", "Recent matching poller unavailable")
            )
        except Exception:
            result[label] = gate("failed", "Task queue check failed")
    return result


async def check_runtime(timeout: float = 15, worker_hostname: str | None = None) -> dict:
    if not math.isfinite(timeout) or not 1 <= timeout <= 300:
        raise ValueError("Invalid timeout")
    hostname = socket.gethostname() if worker_hostname == "current" else worker_hostname
    if hostname is not None and not re.fullmatch(r"[A-Za-z0-9_.-]{1,253}", hostname):
        raise ValueError("Invalid worker hostname")
    settings = get_settings()
    try:
        database = await asyncio.wait_for(check_database(settings), timeout)
    except TimeoutError:
        database = gate("failed", "Database check timed out")
    pollers = await check_pollers(settings, timeout, hostname)
    model_digest = fingerprint(settings.models_config)
    try:
        import yaml

        from infosec_harness.agents import models
        from infosec_harness.agents.registry import resolved_model_names

        # Reused Python callers can retain a cached catalogue after the file changes.
        # Do not attach a fresh file hash to names resolved through an older cache.
        if settings.model_mode == "live":
            fresh = models.ModelsConfig.model_validate(
                yaml.safe_load(read_bytes(settings.models_config))
            )
            if fresh != models.load_models_config():
                raise ValueError("Cached model configuration differs from current file")
        names = sorted(set(resolved_model_names().values()))
        if any(not re.fullmatch(r"[A-Za-z0-9._:/-]{1,200}", name) for name in names):
            raise ValueError("Invalid model label")
        if fingerprint(settings.models_config) != model_digest:
            raise ValueError("Model configuration changed during resolution")
    except Exception:
        names = []
    profile = {
        "source_commit": settings.git_commit_sha
        if re.fullmatch(r"[a-f0-9]{40}", settings.git_commit_sha)
        else None,
        "mode": settings.model_mode,
        "transport": "brokered" if settings.broker_config else "direct",
        "model_config_sha256": model_digest,
        "broker_config_sha256": fingerprint(settings.broker_config),
        "model_names": names,
    }
    identified = bool(
        profile["source_commit"]
        and profile["model_config_sha256"]
        and names
        and (settings.broker_config is None or profile["broker_config_sha256"])
    )
    identity = (
        gate("passed", "Configured source and profile identified")
        if identified
        else gate("not_checked", "Configured source or profile identity unavailable")
    )
    return {
        "checks": {"database": database, **pollers, "profile_identity": identity},
        "profile": profile,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument(
        "--worker-hostname", help="Exact worker hostname, or current inside its container"
    )
    args = parser.parse_args()
    try:
        result = asyncio.run(check_runtime(args.timeout, args.worker_hostname))
    except Exception:
        print(
            json.dumps(
                {
                    "checks": {
                        label: gate("failed", "Runtime check configuration failed")
                        for label in ("database", "workflow_pollers", "activity_pollers")
                    }
                }
            )
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return int(any(check["status"] != "passed" for check in result["checks"].values()))


if __name__ == "__main__":
    raise SystemExit(main())
