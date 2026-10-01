"""Layer D: real checkout Temporal, broker HTTPS and own PostgreSQL; native shim only."""
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
    from datetime import timedelta

    from broker_service_fixture import ROOT, environment
    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from temporalio.client import Client
    from temporalio.worker import Replayer, Worker
    from temporalio.workflow import ActivityConfig
    from test_broker_service_integration import services  # noqa: F401

    from infosec_harness.agents import registry
    from infosec_harness.agents.deps import AgentDeps
    # Qualification shortens only model activity timeout to observe a killed worker
    # retry promptly; retry policy and real registered model/tool construction remain.
    if os.environ.get("HARNESS_BROKER_SERVICE_MANIFEST"):
        registry.MODEL_ACTIVITY = ActivityConfig(start_to_close_timeout=timedelta(seconds=20),
                                                 retry_policy=registry.ACTIVITY_RETRY)
    from infosec_harness.agents.durable import AGENT_LIST, CONFIGS
    from infosec_harness.persistence import budgets, db
    from infosec_harness.workflows.activities import ALL_ACTIVITIES
    from infosec_harness.workflows.temporal_ops import TemporalOps


@workflow.defn(name="BrokerServiceQualificationWorkflow")
class BrokerQualificationWorkflow:
    __pydantic_ai_agents__ = AGENT_LIST

    @workflow.run
    async def run(self, args: dict) -> dict:
        ops = TemporalOps()
        try:
            result = await ops.run_agent("context", ["Inspect sample.py; return unknown reachability."],
                AgentDeps(repo_path=args["repo"]))
            return {"summary": result.output.summary, "requests": result.requests,
                    "tools": result.tools_called}
        finally:
            await ops.close()


async def serve_worker(manifest: dict) -> None:
    client = await Client.connect(manifest["temporal_address"], plugins=[PydanticAIPlugin()])
    worker = Worker(client, task_queue=manifest["task_queue"], workflows=[BrokerQualificationWorkflow],
                    activities=ALL_ACTIVITIES)
    (Path(manifest["directory"]) / "temporal-worker-ready").write_text(str(os.getpid()))
    await worker.run()


def start_worker(manifest: dict, *, direct_stub=False):
    with (Path(manifest["directory"]) / "temporal-worker.log").open("ab") as log:
        process = subprocess.Popen([sys.executable, str(ROOT / "tests" / "runtime" / "broker_service_fixture.py"),
            "temporal-worker", "--manifest", manifest["manifest"],
            *(["--direct-stub"] if direct_stub else [])], env=environment(manifest),
            stdout=log, stderr=log, start_new_session=True)
    with (Path(manifest["directory"]) / "pids.jsonl").open("a") as output:
        output.write(json.dumps({"pid": process.pid, "role": "temporal-worker"}) + "\n")
    return process


async def stop_worker(process):
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        await asyncio.to_thread(process.wait, 10)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        await asyncio.to_thread(process.wait, 5)


async def seed_root(root_id, *, accepted=True):
    state = budgets.initial_state({"requests": 10000, "tokens": 100_000_000, "cost_usd": 1000.0,
        "tool_calls": 10000, "agent_runs": 100, "execution_seconds": 10_000_000}, elapsed_seconds=240)
    if accepted:
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
        handle = await client.start_workflow(BrokerQualificationWorkflow.run, {"repo": values["repo"]},
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
        from infosec_harness.inference import invocations
        from infosec_harness.inference.transport import BrokerModel
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
    # An older root without accepted-config metadata is the supported legacy contract.
    await seed_root(root_id, accepted=False)
    before = len(services.events())
    process = start_worker(services.values, direct_stub=True)
    handle = None
    try:
        client = await Client.connect(services.values["temporal_address"], plugins=[PydanticAIPlugin()])
        handle = await client.start_workflow(BrokerQualificationWorkflow.run,
            {"repo": services.values["repo"]}, id="batch:" + root_id,
            task_queue=services.values["task_queue"])
        result = await asyncio.wait_for(handle.result(), 60)
        assert result["summary"] == "stub context"
        history = await handle.fetch_history()
        await stop_worker(process)
        markers = [event.marker_recorded_event_attributes for event in history.events
                   if event.HasField("marker_recorded_event_attributes")]
        assert not any("credential-broker-invocation-v1" in str(value) for value in markers)
        from infosec_harness.inference import invocations
        from infosec_harness.inference.transport import BrokerModel
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


async def test_prechange_baseline_runtime_history_replays_with_broker_without_io(services, monkeypatch):
    values = services.values
    root_id = "brokerqualification-baseline-" + uuid.uuid4().hex
    await seed_root(root_id, accepted=False)
    before = len(services.events())
    child_env = environment(values)
    child_env["HARNESS_MODEL_MODE"] = "stub"
    child_env["PYTHONPATH"] = os.pathsep.join((str(Path(values["baseline_source"]) / "src"), values["baseline_source"]))
    for key in ("HARNESS_MODELS_CONFIG", "HARNESS_MODEL_BACKEND", "HARNESS_BROKER_CONFIG"):
        child_env.pop(key, None)
    with (Path(values["directory"]) / "baseline-worker.log").open("ab") as log:
        process = subprocess.Popen([sys.executable, "-c",
            "import asyncio,sys; from broker_baseline_fixture import main; asyncio.run(main(sys.argv[1]))",
            values["manifest"]], cwd=values["baseline_source"], env=child_env,
            stdout=log, stderr=log, start_new_session=True)
    with (Path(values["directory"]) / "pids.jsonl").open("a") as output:
        output.write(json.dumps({"pid": process.pid, "role": "temporal-worker"}) + "\n")
    handle = None
    try:
        client = await Client.connect(values["temporal_address"], plugins=[PydanticAIPlugin()])
        handle = await client.start_workflow(BrokerQualificationWorkflow.run,
            {"repo": values["repo"]}, id="batch:" + root_id, task_queue=values["task_queue"])
        result = await asyncio.wait_for(handle.result(), 60)
        assert result["summary"] == "stub context"
        provenance = json.loads((Path(values["directory"]) / "baseline-worker-provenance.json").read_text())
        assert provenance["runtime_from_archive"] is True
        assert provenance["source_revision"] == values["baseline_revision"]
        history = await handle.fetch_history()
        await stop_worker(process)
        markers = [event.marker_recorded_event_attributes for event in history.events
                   if event.HasField("marker_recorded_event_attributes")]
        assert not any("credential-broker-invocation-v1" in str(value) for value in markers)
        from infosec_harness.inference import invocations
        from infosec_harness.inference.transport import BrokerModel
        async def forbidden(*_args, **_kwargs):
            pytest.fail("Pre-change history replay invoked runtime broker I/O")
        monkeypatch.setattr(invocations, "request_invocation", forbidden)
        monkeypatch.setattr(BrokerModel, "request", forbidden)
        await Replayer(workflows=[BrokerQualificationWorkflow], plugins=[PydanticAIPlugin()]).replay_workflow(history)
        assert len(services.events()) == before
        services.record("prechange_baseline_history_broker_config_replay", before,
            source_revision=values["baseline_revision"], pinned_sdk=values["baseline_sdk"],
            runtime_from_archive=True, history_events=len(history.events), replay_provider_dispatches=0)
    finally:
        if handle is not None:
            with suppress(Exception):
                await handle.cancel()
        await stop_worker(process)
