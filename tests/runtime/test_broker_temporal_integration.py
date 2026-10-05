"""Layer D: real checkout Temporal, broker HTTPS and own PostgreSQL; native shim only.

Run only by ``scripts/broker_service_check.py --temporal``, which supplies the service manifest.
"""
from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys
import uuid
from contextlib import suppress
from pathlib import Path

import pytest
from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from temporalio.client import Client
    from temporalio.worker import Replayer
    from test_broker_service_integration import services  # noqa: F401

    from infosec_harness.persistence import budgets, db
    from infosec_harness.qualification.broker.service import (
        AGENTS,
        ROOT,
        environment,
        use_service_activity_timeout,
    )
    from infosec_harness.runtime import registry

    if os.environ.get("HARNESS_BROKER_SERVICE_MANIFEST"):
        use_service_activity_timeout()
    from infosec_harness.qualification.broker.service_workflow import BrokerQualificationWorkflow

pytestmark = pytest.mark.requires_service("HARNESS_BROKER_SERVICE_MANIFEST")


def start_worker(manifest: dict, *, direct_stub=False):
    with (Path(manifest["directory"]) / "temporal-worker.log").open("ab") as log:
        process = subprocess.Popen([sys.executable, "-m", "infosec_harness.qualification.broker.service",
            "temporal-worker", "--manifest", manifest["manifest"],
            *(["--direct-stub"] if direct_stub else [])], cwd=ROOT, env=environment(manifest),
            stdout=log, stderr=log, start_new_session=True)
    with (Path(manifest["directory"]) / "pids.jsonl").open("a") as output:
        output.write(json.dumps({"pid": process.pid, "role": "temporal-worker"}) + "\n")
    return process


async def stop_worker(process):
    if process.poll() is not None:
        return
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        await asyncio.to_thread(process.wait, 10)
    except subprocess.TimeoutExpired:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        await asyncio.to_thread(process.wait, 5)


async def seed_root(root_id):
    from infosec_harness.runtime.durable import CONFIGS

    state = budgets.initial_state({"requests": 10000, "tokens": 100_000_000, "cost_usd": 1000.0,
        "tool_calls": 10000, "agent_runs": 100, "execution_seconds": 10_000_000}, elapsed_seconds=240)
    state["agent_config_digests"] = {name: config.digest for name, config in CONFIGS.items()}
    async with db.session() as session:
        session.add(db.BudgetLedger(root_id=root_id, state=state))
        await session.commit()


async def test_real_temporal_worker_restart_saved_activity_and_zero_io_replay(services, monkeypatch):
    values = services.values
    root_id = "brokerqualification-" + uuid.uuid4().hex
    await seed_root(root_id)
    before = len(services.events())
    services.arm("hold_ack")
    directory = Path(values["directory"])
    marker = directory / "executor-result-committed"
    marker.unlink(missing_ok=True)
    release = directory / "release-executor-ack"
    release.unlink(missing_ok=True)
    first = start_worker(values)
    second = None
    handle = None
    try:
        client = await Client.connect(values["temporal_address"], plugins=[PydanticAIPlugin()])
        handle = await client.start_workflow(BrokerQualificationWorkflow.run, {"repo": values["repo"], "root_id": root_id},
            id="batch:" + root_id, task_queue=values["task_queue"])
        for _ in range(600):
            if first.poll() is not None:
                raise RuntimeError("Temporal fixture worker stopped before model completion")
            if marker.exists():
                break
            await asyncio.sleep(0.1)
        else:
            pytest.fail("Temporal model activity never committed its broker result")
        request_id = marker.read_text()
        async with db.session() as session:
            saved = await session.get(db.InferenceRequestRecord, request_id)
            assert saved is not None and saved.state == "completed"
            stored_identity = saved.request["request_id"]
        os.killpg(first.pid, signal.SIGKILL)
        await asyncio.to_thread(first.wait, 5)
        release.write_text("release fixture response")
        second = start_worker(values)
        result = await asyncio.wait_for(handle.result(), 150)
        assert result["summary"] == "qualification context" and result["requests"] == 2
        assert any(name.endswith("read_file") for name in result["tools"])
        events = services.events()[before:]
        assert len(events) == 2 and events[1]["tool_return"]
        history = await handle.fetch_history()
        markers = [event.marker_recorded_event_attributes for event in history.events
                   if event.HasField("marker_recorded_event_attributes")]
        assert any("credential-broker-invocation-v1" in str(value) for value in markers)
        async with db.session() as session:
            root = await session.get(db.BudgetLedger, root_id)
            operations = list(root.state["operations"].values())
            assert len(operations) == 1 and operations[0]["broker_binding"]["run_id"] == handle.first_execution_run_id
            assert operations[0]["broker_allocated"]["requests"] == 2
            assert operations[0]["broker_revoked"] and operations[0]["status"] == "uncertain"
            saved = await session.get(db.InferenceRequestRecord, stored_identity)
            assert saved.state == "completed"
        attempts = [event.activity_task_started_event_attributes.attempt for event in history.events
                    if event.HasField("activity_task_started_event_attributes")]
        assert max(attempts) >= 2
        from infosec_harness.inference.worker import invocations
        from infosec_harness.inference.worker.transport import BrokerModel
        async def forbidden(*_args, **_kwargs):
            pytest.fail("Replay invoked runtime broker I/O")
        monkeypatch.setattr(invocations, "request_invocation", forbidden)
        monkeypatch.setattr(BrokerModel, "request", forbidden)
        count = len(services.events())
        await Replayer(workflows=[BrokerQualificationWorkflow], plugins=[PydanticAIPlugin()]).replay_workflow(history)
        assert len(services.events()) == count
        services.record("temporal_worker_kill_saved_result_retry_replay", before,
            worker_restart=True, root_operations=1, replay_provider_dispatches=0,
            history_events=len(history.events), stable_request_id=stored_identity,
            maximum_activity_attempt=max(attempts), model_activity_timeout_seconds=20)
    finally:
        if handle is not None:
            with suppress(Exception):
                await handle.cancel()
        await stop_worker(first)
        if second is not None:
            await stop_worker(second)


async def test_real_direct_stub_history_replays_under_broker_config_without_io(services, monkeypatch):
    """Record a direct SDK history on a separate stub worker, then replay broker code."""
    root_id = "brokerqualification-direct-" + uuid.uuid4().hex
    await seed_root(root_id)
    before = len(services.events())
    process = start_worker(services.values, direct_stub=True)
    handle = None
    try:
        client = await Client.connect(services.values["temporal_address"], plugins=[PydanticAIPlugin()])
        handle = await client.start_workflow(BrokerQualificationWorkflow.run,
            {"repo": services.values["repo"], "root_id": root_id}, id="batch:" + root_id,
            task_queue=services.values["task_queue"])
        result = await asyncio.wait_for(handle.result(), 60)
        assert result["summary"] == "stub context"
        history = await handle.fetch_history()
        await stop_worker(process)
        markers = [event.marker_recorded_event_attributes for event in history.events
                   if event.HasField("marker_recorded_event_attributes")]
        assert not any("credential-broker-invocation-v1" in str(value) for value in markers)
        from infosec_harness.inference.worker import invocations
        from infosec_harness.inference.worker.transport import BrokerModel
        async def forbidden(*_args, **_kwargs):
            pytest.fail("Replay invoked runtime broker I/O")
        monkeypatch.setattr(invocations, "request_invocation", forbidden)
        monkeypatch.setattr(BrokerModel, "request", forbidden)
        await Replayer(workflows=[BrokerQualificationWorkflow], plugins=[PydanticAIPlugin()]).replay_workflow(history)
        assert len(services.events()) == before
        services.record("direct_stub_history_broker_config_replay", before, replay_provider_dispatches=0,
                        history_events=len(history.events), historical_provider="production deterministic stub")
    finally:
        if handle is not None:
            with suppress(Exception):
                await handle.cancel()
        await stop_worker(process)


async def test_real_temporal_all_registered_agents_execute_and_replay_without_io(services, monkeypatch):
    from sqlalchemy import select

    from infosec_harness.runtime.durable import CONFIGS

    assert set(AGENTS) == set(registry.BINDINGS) == set(CONFIGS)
    root_id = "brokerqualification-all-" + uuid.uuid4().hex
    await seed_root(root_id)
    before = len(services.events())
    process = start_worker(services.values)
    handle = None
    expected_types = {
        "intake": "ExtractedFinding", "recon": "RepoProfile", "env-planner": "EnvironmentSpec",
        "build-repair": "EnvironmentSpec", "partial-build": "PartialEnvironmentOutput",
        "context": "ContextOutput", "probe-planner": "ProbePlan", "probe-author": "ProbeSource",
        "probe-diagnosis": "ProbeDiagnosis", "probe-repair": "ProbeSource", "verdict": "InconclusiveOutput",
    }
    try:
        client = await Client.connect(services.values["temporal_address"], plugins=[PydanticAIPlugin()])
        handle = await client.start_workflow(BrokerQualificationWorkflow.run,
            {"repo": services.values["repo"], "root_id": root_id, "all_agents": True}, id="batch:" + root_id,
            task_queue=services.values["task_queue"])
        result = await asyncio.wait_for(handle.result(), 150)
        assert set(result) == set(expected_types)
        for name, value in result.items():
            assert value["output_type"] == expected_types[name]
            assert value["requests"] == 1
            assert value["input_tokens"] == 100 and value["output_tokens"] == 20
        assert result["intake"]["output"]["file_path"] is None
        assert result["recon"]["output"]["primary_language"] == "unknown"
        for name in ("env-planner", "build-repair", "partial-build"):
            assert result[name]["output"]["base_image"] == "debian:bookworm-slim"
        assert result["partial-build"]["output"]["scope"] == "partial"
        assert result["context"]["output"]["reachability"] == "unknown"
        assert result["probe-planner"]["output"]["oracle"] == "marker_output"
        for name in ("probe-author", "probe-repair"):
            assert result[name]["output"]["test_file_path"] == "harness_probe.sh"
        assert result["probe-diagnosis"]["output"]["kind"] == "environment_issue"
        assert result["verdict"]["output"]["label"] == "inconclusive"
        assert result["verdict"]["output"]["inconclusive_reason"] == "conflicting_evidence"
        events = services.events()[before:]
        assert [event["qualification_agent"] for event in events] == list(AGENTS)
        assert all(event["authorized"] and not event["canary_in_body"] for event in events)
        async with db.session() as session:
            root = await session.get(db.BudgetLedger, root_id)
            assert len(root.state["operations"]) == 11
            assert all(operation["broker_revoked"] and operation["broker_allocated"]["requests"] == 1
                       for operation in root.state["operations"].values())
            records = (await session.execute(select(db.InferenceRequestRecord).where(
                db.InferenceRequestRecord.root_id == root_id))).scalars().all()
            assert len(records) == 11 and all(record.state == "completed" for record in records)
            assert {record.request["binding"]["agent"] for record in records} == set(AGENTS)
        history = await handle.fetch_history()
        await stop_worker(process)
        from infosec_harness.inference.worker import invocations
        from infosec_harness.inference.worker.transport import BrokerModel

        async def forbidden(*_args, **_kwargs):
            pytest.fail("All-agent history replay invoked runtime broker I/O")

        monkeypatch.setattr(invocations, "request_invocation", forbidden)
        monkeypatch.setattr(BrokerModel, "request", forbidden)
        count = len(services.events())
        await Replayer(workflows=[BrokerQualificationWorkflow], plugins=[PydanticAIPlugin()]).replay_workflow(history)
        assert len(services.events()) == count
        services.record("temporal_all_registered_agents_replay", before, agents=list(AGENTS),
            persisted_completed=11, root_operations=11, root_closed=True,
            history_events=len(history.events), replay_provider_dispatches=0,
            accuracy="not_checked", native_confinement="not_checked")
    finally:
        if handle is not None:
            with suppress(Exception):
                await handle.cancel()
        await stop_worker(process)
