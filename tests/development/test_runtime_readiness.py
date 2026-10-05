"""Readiness uses SELECT-only persistence and actual recent queue observations."""

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from conftest import load_script
from google.protobuf.timestamp_pb2 import Timestamp
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from infosec_harness.settings import Settings

readiness = load_script("runtime_readiness")


def settings(tmp_path, **kwargs):
    return Settings(
        _env_file=None, database_url=f"sqlite+aiosqlite:///{tmp_path / 'database.sqlite'}", **kwargs
    )


@pytest.mark.parametrize("filename", ["missing.sqlite", ":memory:"])
async def test_missing_database_never_created(tmp_path, filename):
    config = Settings(
        _env_file=None,
        database_url=f"sqlite+aiosqlite:///{tmp_path / filename}"
        if filename != ":memory:"
        else "sqlite+aiosqlite:///:memory:",
    )
    assert (await readiness.check_database(config))["status"] == "failed"
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "revision, expected", [("0005", "passed"), ("0004", "failed"), (None, "failed")]
)
async def test_database_revision_and_contents_unchanged(tmp_path, revision, expected):
    config = settings(tmp_path)
    engine = create_async_engine(config.database_url)
    async with engine.begin() as conn:
        await conn.execute(text("CREATE TABLE retained(value TEXT)"))
        await conn.execute(text("INSERT INTO retained VALUES ('unchanged')"))
        if revision is not None:
            await conn.execute(text("CREATE TABLE alembic_version(version_num TEXT)"))
            await conn.execute(
                text("INSERT INTO alembic_version VALUES (:revision)"), {"revision": revision}
            )
    await engine.dispose()
    before = (tmp_path / "database.sqlite").read_bytes()
    assert (await readiness.check_database(config))["status"] == expected
    assert (tmp_path / "database.sqlite").read_bytes() == before


def poller(age=1, identity="42@worker"):
    timestamp = Timestamp()
    timestamp.FromDatetime(datetime.now(UTC) - timedelta(seconds=age))
    return SimpleNamespace(identity=identity, last_access_time=timestamp)


@pytest.mark.parametrize(
    "age, identity, hostname, expected",
    [
        (1, "42@worker", "worker", True),
        (61, "42@worker", "worker", False),
        (-10, "42@worker", "worker", False),
        (1, "42@worker-old", "worker", False),
        (1, "42@prefix-worker", "worker", False),
        (1, "xx@worker", "worker", False),
        (1, "arbitrary-identity", None, True),
    ],
)
def test_pollers_freshness_and_exact_worker(age, identity, hostname, expected):
    assert readiness.recent_poller(poller(age, identity), datetime.now(UTC), hostname) is expected


def test_naive_timestamp_rejected():
    value = SimpleNamespace(
        identity="42@worker",
        last_access_time=SimpleNamespace(ToDatetime=lambda **kwargs: datetime.now()),
    )
    assert not readiness.recent_poller(value, datetime.now(UTC), "worker")


async def test_temporal_shared_options_and_both_queue_types(monkeypatch, tmp_path):
    describe = AsyncMock(return_value=SimpleNamespace(pollers=[poller()]))
    connect = AsyncMock(
        return_value=SimpleNamespace(workflow_service=SimpleNamespace(describe_task_queue=describe))
    )
    monkeypatch.setattr(readiness.Client, "connect", connect)
    monkeypatch.setattr(
        readiness,
        "temporal_connection_options",
        lambda _: {"tls": True, "api_key": "private-token"},
    )
    result = await readiness.check_pollers(settings(tmp_path), 1, "worker")
    assert all(value["status"] == "passed" for value in result.values())
    assert connect.call_args.kwargs == {
        "namespace": "default",
        "tls": True,
        "api_key": "private-token",
    }
    assert {call.args[0].task_queue_type for call in describe.call_args_list} == {1, 2}
    assert "private-token" not in json.dumps(result)
    assert "42@worker" not in json.dumps(result)


async def test_each_queue_has_independent_gate(monkeypatch, tmp_path):
    describe = AsyncMock(
        side_effect=[RuntimeError("secret address"), SimpleNamespace(pollers=[poller()])]
    )
    monkeypatch.setattr(
        readiness.Client,
        "connect",
        AsyncMock(
            return_value=SimpleNamespace(
                workflow_service=SimpleNamespace(describe_task_queue=describe)
            )
        ),
    )
    result = await readiness.check_pollers(settings(tmp_path), 1, None)
    assert result["workflow_pollers"]["status"] == "failed"
    assert result["activity_pollers"]["status"] == "passed"
    assert "identity not checked" in result["activity_pollers"]["detail"]
    assert "secret" not in json.dumps(result)


async def test_connection_failure_sanitized(monkeypatch, tmp_path):
    monkeypatch.setattr(
        readiness.Client,
        "connect",
        AsyncMock(side_effect=RuntimeError("https://user:secret@private")),
    )
    result = await readiness.check_pollers(settings(tmp_path), 1, None)
    assert all(value["status"] == "failed" for value in result.values())
    assert "secret" not in json.dumps(result)


@pytest.mark.parametrize("timeout", [0, 301, float("nan"), float("inf")])
async def test_invalid_timeout_rejected(timeout):
    with pytest.raises(ValueError, match="Invalid timeout"):
        await readiness.check_runtime(timeout)


async def test_profile_unavailable_preserves_actual_gates(monkeypatch, tmp_path):
    config = settings(
        tmp_path,
        git_commit_sha="unavailable",
        model_mode="stub",
        models_config=tmp_path / "missing",
    )
    monkeypatch.setattr(readiness, "get_settings", lambda: config)
    monkeypatch.setattr(
        readiness,
        "check_database",
        AsyncMock(
            return_value=readiness.gate("passed", "Database query and schema revision passed")
        ),
    )
    monkeypatch.setattr(
        readiness,
        "check_pollers",
        AsyncMock(
            return_value={
                name: readiness.gate(
                    "passed", "Recent queue poller observed; worker identity not checked"
                )
                for name in ("workflow_pollers", "activity_pollers")
            }
        ),
    )
    result = await readiness.check_runtime()
    assert result["profile"]["source_commit"] is None
    assert result["profile"]["model_config_sha256"] is None
    assert result["checks"]["profile_identity"]["status"] == "not_checked"
    assert result["checks"]["database"]["status"] == "passed"


async def test_temporal_timeout_bounded_and_sanitized(monkeypatch, tmp_path):
    import asyncio

    async def hang(*args, **kwargs):
        await asyncio.sleep(10)

    monkeypatch.setattr(readiness.Client, "connect", hang)
    result = await readiness.check_pollers(settings(tmp_path), 0.01, None)
    assert all(value["status"] == "failed" for value in result.values())


async def test_database_timeout_remains_independent(monkeypatch, tmp_path):

    async def hang(*args):
        raise TimeoutError("private database address")

    monkeypatch.setattr(readiness, "get_settings", lambda: settings(tmp_path))
    monkeypatch.setattr(readiness, "check_database", hang)
    monkeypatch.setattr(
        readiness,
        "check_pollers",
        AsyncMock(
            return_value={
                name: readiness.gate(
                    "passed", "Recent queue poller observed; worker identity not checked"
                )
                for name in ("workflow_pollers", "activity_pollers")
            }
        ),
    )
    result = await readiness.check_runtime()
    assert result["checks"]["database"] == {
        "status": "failed",
        "detail": "Database check timed out",
    }
    assert result["checks"]["activity_pollers"]["status"] == "passed"
    assert "private" not in json.dumps(result)


async def test_profile_labels_sanitized(monkeypatch, tmp_path):
    from infosec_harness.agents import registry

    config = settings(tmp_path, git_commit_sha="a" * 40, models_config=tmp_path / "models.yaml")
    config.models_config.write_text("profile")
    monkeypatch.setattr(readiness, "get_settings", lambda: config)
    monkeypatch.setattr(
        registry, "resolved_model_names", lambda: {"agent": "https://secret@private"}
    )
    monkeypatch.setattr(
        readiness,
        "check_database",
        AsyncMock(
            return_value=readiness.gate("passed", "Database query and schema revision passed")
        ),
    )
    monkeypatch.setattr(readiness, "check_pollers", AsyncMock(return_value={}))
    result = await readiness.check_runtime()
    assert result["profile"]["model_names"] == []
    assert "secret" not in json.dumps(result)
    assert result["checks"]["profile_identity"]["status"] == "not_checked"


async def test_current_worker_uses_exact_hostname(monkeypatch, tmp_path):
    monkeypatch.setattr(readiness, "get_settings", lambda: settings(tmp_path))
    monkeypatch.setattr(readiness.socket, "gethostname", lambda: "current-worker")
    monkeypatch.setattr(
        readiness,
        "check_database",
        AsyncMock(return_value=readiness.gate("failed", "Existing database unavailable")),
    )
    check = AsyncMock(return_value={})
    monkeypatch.setattr(readiness, "check_pollers", check)
    await readiness.check_runtime(worker_hostname="current")
    assert check.call_args.args[2] == "current-worker"


async def test_cached_catalogue_cannot_claim_new_file_identity(monkeypatch, tmp_path):
    from infosec_harness.agents import models, registry

    baseline = models.load_models_config()
    changed = baseline.model_copy(deep=True)
    changed.default_backend = "changed-backend"
    path = tmp_path / "models.yaml"
    path.write_text(changed.model_dump_json())
    config = settings(tmp_path, model_mode="live", git_commit_sha="a" * 40, models_config=path)
    monkeypatch.setattr(readiness, "get_settings", lambda: config)
    monkeypatch.setattr(models, "load_models_config", lambda: baseline)
    monkeypatch.setattr(registry, "resolved_model_names", lambda: {"agent": "cached:old-model"})
    monkeypatch.setattr(
        readiness,
        "check_database",
        AsyncMock(
            return_value=readiness.gate("passed", "Database query and schema revision passed")
        ),
    )
    monkeypatch.setattr(
        readiness,
        "check_pollers",
        AsyncMock(
            return_value={
                "workflow_pollers": readiness.gate(
                    "passed", "Recent queue poller observed; worker identity not checked"
                )
            }
        ),
    )
    result = await readiness.check_runtime()
    assert result["checks"]["profile_identity"]["status"] == "not_checked"
    assert result["profile"]["model_names"] == []
    assert result["checks"]["database"]["status"] == "passed"
    assert result["checks"]["workflow_pollers"]["status"] == "passed"


async def test_file_changed_during_resolution_is_unavailable(monkeypatch, tmp_path):
    from infosec_harness.agents import registry

    path = tmp_path / "models.yaml"
    path.write_text("initial")
    config = settings(tmp_path, model_mode="stub", git_commit_sha="a" * 40, models_config=path)
    monkeypatch.setattr(readiness, "get_settings", lambda: config)

    def change_file():
        path.write_text("changed")
        return {"agent": "stub:agent:sonnet"}

    monkeypatch.setattr(registry, "resolved_model_names", change_file)
    monkeypatch.setattr(
        readiness,
        "check_database",
        AsyncMock(
            return_value=readiness.gate("passed", "Database query and schema revision passed")
        ),
    )
    monkeypatch.setattr(readiness, "check_pollers", AsyncMock(return_value={}))
    result = await readiness.check_runtime()
    assert result["checks"]["profile_identity"]["status"] == "not_checked"
    assert result["profile"]["model_names"] == []


def test_sixty_second_boundary_is_inclusive():
    now = datetime(2026, 10, 4, tzinfo=UTC)
    stamp = Timestamp()
    stamp.FromDatetime(now - timedelta(seconds=60))
    value = SimpleNamespace(identity="42@worker", last_access_time=stamp)
    assert readiness.recent_poller(value, now, "worker")
    assert not readiness.recent_poller(value, now + timedelta(microseconds=1), "worker")
