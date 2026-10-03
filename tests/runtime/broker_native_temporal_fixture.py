"""Narrow native Agent[str] Temporal recovery; no registered-graph acceptance claim.

The operator file contains only immutable scope, public contract and credential paths.
Only worker startup reads the owner-only HMAC file. Workflow input contains a prompt.
Native lifecycle and controller ACK barrier remain owned by the native lane.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import subprocess
import sys
import time
import uuid
from contextlib import suppress
from pathlib import Path

from pydantic import Field
from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from datetime import timedelta

    from pydantic_ai import Agent
    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin, TemporalDurability
    from temporalio.client import Client, WorkflowExecutionStatus
    from temporalio.worker import Replayer, Worker
    from temporalio.workflow import ActivityConfig

    from infosec_harness.agents.registry import ACTIVITY_RETRY
    from infosec_harness.inference.protocol import ExecutorContract, ReservationBinding, StrictModel
    from infosec_harness.inference.transport import BrokerModel
    from infosec_harness.inference.unbound import UnboundBrokerModel


class NativeOperatorConfig(StrictModel):
    controller_url: str
    secret_env: str = Field(pattern=r"^[A-Z][A-Z0-9_]+$")
    secret_file: str
    ca_file: str
    client_cert: str | None
    client_key: str | None
    contract: ExecutorContract
    binding: ReservationBinding
    temporal_address: str = "127.0.0.1:7365"
    expected_output: str
    commit_marker: str
    release_marker: str
    provider_count_file: str
    report_file: str
    prompt: str = "Return the local qualification response."


def read_config(path: Path) -> NativeOperatorConfig:
    return NativeOperatorConfig.model_validate_json(path.read_text())


def make_agent(config: NativeOperatorConfig | None):
    model = (BrokerModel(contract=config.contract, binding=config.binding,
        controller_url=config.controller_url, secret_env=config.secret_env,
        ca_file=config.ca_file, client_cert=config.client_cert, client_key=config.client_key,
        timeout=90) if config else UnboundBrokerModel("native-qualification", atomic_intake=False))
    return Agent(model, output_type=str, name="native-temporal-qualification", retries=0,
        model_settings=config.contract.model_settings if config else {},
        capabilities=[TemporalDurability(model_activity_config=ActivityConfig(
            start_to_close_timeout=timedelta(seconds=20), retry_policy=ACTIVITY_RETRY))])


# Host construction only. Temporal sandbox reuses this exact agent via passthrough imports.
with workflow.unsafe.imports_passed_through():
    _operator_path = os.environ.get("HARNESS_NATIVE_TEMPORAL_CONFIG")
    _CONFIG = read_config(Path(_operator_path)) if _operator_path else None
    NATIVE_AGENT = make_agent(_CONFIG)


def workflow_class():
    from test_broker_native_temporal import NativeBrokerTemporalWorkflow
    return NativeBrokerTemporalWorkflow


def worker_credentials(config: NativeOperatorConfig) -> None:
    path = Path(config.secret_file)
    if path.stat().st_mode & 0o077:
        raise RuntimeError("Native worker credential file must be owner-only")
    key = path.read_text().strip()
    if not key or len(key) > 4096:
        raise RuntimeError("Invalid private native worker credential")
    os.environ[config.secret_env] = key


async def run_worker(config: NativeOperatorConfig, queue: str) -> None:
    worker_credentials(config)
    client = await Client.connect(config.temporal_address, plugins=[PydanticAIPlugin()])
    await Worker(client, task_queue=queue, workflows=[workflow_class()]).run()


def count_provider(config: NativeOperatorConfig) -> int:
    value = json.loads(Path(config.provider_count_file).read_text())
    if type(value) is int:
        return value
    if isinstance(value, dict):
        for field in ("provider_admitted", "count"):
            if type(value.get(field)) is int:
                return value[field]
    raise RuntimeError("Native provider observation must be an integer count")


def start_worker(config_path: Path, queue: str, log: Path):
    values = dict(os.environ)
    values["HARNESS_NATIVE_TEMPORAL_CONFIG"] = str(config_path)
    values["PYTHONPATH"] = os.pathsep.join((str(Path(__file__).parent),
        str(Path(__file__).resolve().parents[2] / "src"), values.get("PYTHONPATH", "")))
    with log.open("ab") as output:
        return subprocess.Popen([sys.executable, "-c",
            "from broker_native_temporal_fixture import main; raise SystemExit(main())", "worker", "--config",
            str(config_path), "--queue", queue], env=values, stdout=output, stderr=output,
            start_new_session=True)


async def stop_worker(process) -> None:
    if process.poll() is not None:
        return
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        await asyncio.to_thread(process.wait, 5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        await asyncio.to_thread(process.wait, 5)


async def qualify(config_path: Path, *, replay_forbidden=True) -> dict:
    config = read_config(config_path)
    if config != _CONFIG:
        raise RuntimeError("Native workflow host must load the exact operator config before import")
    suffix = uuid.uuid4().hex
    queue = "broker-native-temporal-" + suffix
    workflow_id = "broker-native-recovery-" + suffix
    report_path = Path(config.report_file)
    log = report_path.with_suffix(".worker.log")
    report = {"gate": "native-agent-string-temporal-recovery", "status": "failed",
        "scope": "single Agent[str]; not full registered graph layer D",
        "paid_dispatches": 0, "workflow_id": workflow_id, "task_queue": queue,
        "model_activity_timeout_seconds": 20, "native_lifecycle_owner": "P4",
        "worker_cleanup": "not_checked", "history_replay": "not_checked"}
    before = count_provider(config)
    first, second, handle = None, None, None
    client = None
    try:
        marker, release = Path(config.commit_marker), Path(config.release_marker)
        if marker.exists() or release.exists():
            raise RuntimeError("Native owner must prepare fresh ACK barrier markers")
        report["phase"] = "first_worker"
        first = start_worker(config_path, queue, log)
        report["worker_pids"] = [first.pid]
        client = await Client.connect(config.temporal_address, plugins=[PydanticAIPlugin()])
        handle = await client.start_workflow(workflow_class().run, config.prompt,
            id=workflow_id, task_queue=queue)
        deadline = time.monotonic() + 90
        while not marker.exists():
            if first.poll() is not None:
                raise RuntimeError("Native Temporal worker exited before committed ACK barrier")
            if time.monotonic() > deadline:
                raise TimeoutError("Native controller committed ACK barrier not observed")
            await asyncio.sleep(0.1)
        marker_value = json.loads(marker.read_text())
        if marker_value.get("state") != "completed" or not marker_value.get("request_id"):
            raise RuntimeError("Native ACK barrier did not attest a committed request")
        report["phase"] = "committed_before_ack"
        request_id = marker_value["request_id"]
        if count_provider(config) != before + 1:
            raise RuntimeError("Native first model request did not dispatch exactly once")
        os.killpg(first.pid, signal.SIGKILL)
        await asyncio.to_thread(first.wait, 5)
        release.write_text("release native qualification ACK")
        report["phase"] = "replacement_worker_saved_retry"
        second = start_worker(config_path, queue, log)
        report["worker_pids"].append(second.pid)
        result = await asyncio.wait_for(handle.result(), 100)
        if result["output"] != config.expected_output or result["requests"] != 1:
            raise RuntimeError("Native saved model response failed the independent output oracle")
        broker = result["broker"]
        if not broker or broker["request_id"] != request_id or broker["state"] != "completed":
            raise RuntimeError("Native saved response provenance differs from committed request")
        if count_provider(config) != before + 1:
            raise RuntimeError("Native activity retry dispatched again")
        report["phase"] = "capture_and_replay"
        history = await handle.fetch_history()
        attempts = [event.activity_task_started_event_attributes.attempt for event in history.events
                    if event.HasField("activity_task_started_event_attributes")]
        if max(attempts) < 2:
            raise RuntimeError("Native history contains no retried model activity")
        history_path = report_path.with_suffix(".history.json")
        history_path.write_text(history.to_json())
        history_path.chmod(0o600)
        original = BrokerModel.request
        async def forbidden(*_args, **_kwargs):
            raise AssertionError("Native history replay attempted runtime broker I/O")
        if replay_forbidden:
            BrokerModel.request = forbidden
        try:
            await Replayer(workflows=[workflow_class()], plugins=[PydanticAIPlugin()]).replay_workflow(history)
        finally:
            BrokerModel.request = original
        if count_provider(config) != before + 1:
            raise RuntimeError("Native history replay dispatched upstream")
        secret = Path(config.secret_file).read_text().strip()
        if secret in history_path.read_text() or secret in log.read_text(errors="replace"):
            raise RuntimeError("Native worker secret appeared in history or logs")
        report.update(phase="complete", status="passed", provider_dispatches=1, replay_provider_dispatches=0,
            request_id=request_id, saved_response=result, maximum_activity_attempt=max(attempts),
            history_events=len(history.events), history_file=str(history_path), history_replay="passed",
            secret_history_log_scan="passed", same_persisted_request=True)
    except Exception as exc:
        report["failure_class"] = type(exc).__name__
        report["provider_dispatches"] = count_provider(config) - before
    finally:
        if handle is not None:
            try:
                description = await handle.describe()
                if description.status == WorkflowExecutionStatus.RUNNING:
                    await handle.terminate(reason="Owned native qualification cleanup")
                report["workflow_cleanup"] = "passed" if (await handle.describe()).status != WorkflowExecutionStatus.RUNNING else "failed"
            except Exception as exc:
                report["workflow_cleanup"] = "failed"
                report["workflow_cleanup_failure_class"] = type(exc).__name__
        if first is not None:
            await stop_worker(first)
        if second is not None:
            await stop_worker(second)
        report["worker_cleanup"] = "passed" if all(process is None or process.poll() is not None
                                                   for process in (first, second)) else "failed"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        report_path.chmod(0o600)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("worker", "qualify"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--queue")
    args = parser.parse_args()
    config = read_config(args.config)
    if args.role == "worker":
        asyncio.run(run_worker(config, args.queue))
        return 0
    report = asyncio.run(qualify(args.config))
    print(json.dumps({key: value for key, value in report.items() if key != "saved_response"}, sort_keys=True))
    return 0 if report["status"] == report["worker_cleanup"] == report["workflow_cleanup"] == "passed" else 1


if __name__ == "__main__":
    # Import the named module so Temporal sandbox/replay never resolves __main__.
    from broker_native_temporal_fixture import main as module_main
    raise SystemExit(module_main())
