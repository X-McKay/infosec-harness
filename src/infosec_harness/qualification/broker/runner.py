"""One real-provider qualification phase: no model mocks, prompt markers or lifecycle shims.

Run only by ``pilot`` with a frozen manifest and an explicit inference handoff::

    python -m infosec_harness.qualification.broker.runner {direct,local,temporal,worker} --manifest ...
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
import uuid
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path

from infosec_harness.qualification.broker.support import (
    child_environment,
    forbid_io,
    ledger_snapshot,
    private_write,
    read_private_environment,
    reap,
    serve_worker,
)
from infosec_harness.qualification.broker.validators import (
    AGENTS_DIR,
    CASES,
    ROOT,
    ROOT_PREFIX,
    WORKFLOW_NAME,
    RealProviderManifest,
    compare_baseline,
    selected_phases,
    verify_configuration,
)


def phase_environment(manifest: RealProviderManifest, phase: str) -> dict[str, str]:
    """Child environment: no ambient provider keys; broker authority only for native phases."""
    worker_key = (manifest.worker_hmac_env, manifest.worker_hmac_file)
    if phase == "direct":
        return child_environment(ROOT, models_config=manifest.direct_models_config,
                                 database={"HARNESS_DATABASE_URL": "sqlite+aiosqlite:///:memory:"},
                                 worker_key=worker_key)
    private = read_private_environment(manifest.database_env_file)
    if "HARNESS_DATABASE_URL" not in private:
        raise ValueError("Private database reference must define HARNESS_DATABASE_URL")
    return child_environment(ROOT, models_config=manifest.broker_models_config,
                             database={"HARNESS_DATABASE_URL": private["HARNESS_DATABASE_URL"]},
                             worker_key=worker_key, broker_config=manifest.broker_config)


def prepare_case(agent: str, manifest: RealProviderManifest):
    """Public workflow input plus host-only scorer and expected label for one frozen case."""
    import yaml

    from infosec_harness.agents.render import render_intake_prompt, render_prompt
    from infosec_harness.evals.adapters import ADAPTERS
    from infosec_harness.inference.wire.protocol import digest
    path = AGENTS_DIR / agent / "evals/dataset.yaml"
    frozen = manifest.datasets[agent]
    if Path(frozen.path).resolve() != path.resolve():
        raise ValueError("Frozen dataset provenance changed: path differs")
    if frozen.case != manifest.cases[agent]:
        raise ValueError("Frozen dataset provenance changed: case differs")
    if hashlib.sha256(path.read_bytes()).hexdigest() != frozen.sha256:
        raise ValueError("Frozen dataset provenance changed: content differs")
    dataset = yaml.safe_load(path.read_text())
    if str(dataset["version"]) != frozen.version:
        raise ValueError("Frozen dataset version changed")
    matching = [case for case in dataset["cases"] if case["name"] == manifest.cases[agent]]
    if len(matching) != 1:
        raise ValueError("Frozen case is absent or ambiguous")
    case = matching[0]
    case_digest = digest(case)
    if manifest.case_digests and case_digest != manifest.case_digests[agent]:
        raise ValueError("Frozen case content changed")
    adapted = ADAPTERS[agent](case)
    prompt = (render_intake_prompt(adapted.task, adapted.payload) if agent == "intake"
              else render_prompt(adapted.task, adapted.payload))
    # Expected labels and scorer callbacks remain host-only, never in the workflow input.
    return ({"agent": agent, "prompt": prompt, "deps": adapted.deps}, adapted.predict,
            case["expected"], case_digest)


def output_class(agent: str):
    from infosec_harness.agents.outputs import (
        ContextOutput,
        InconclusiveOutput,
        PartialEnvironmentOutput,
        PlannedEnvironmentOutput,
    )
    from infosec_harness.agents.registry import BINDINGS
    if agent == "verdict":
        return InconclusiveOutput
    return {"env-planner": PlannedEnvironmentOutput, "context": ContextOutput,
            "partial-build": PartialEnvironmentOutput}.get(agent, BINDINGS[agent].domain_type)


def score_output(agent: str, output, predict, expected) -> dict:
    from pydantic import BaseModel

    from infosec_harness.agents.outputs import InconclusiveOutput, NegativeOutput, PositiveOutput
    expected_type = output_class(agent)
    valid = (isinstance(output, (InconclusiveOutput, NegativeOutput, PositiveOutput)) if agent == "verdict"
             else type(output) is expected_type)
    if not valid or not isinstance(output, BaseModel):
        raise ValueError("Registered output type differs from the current contract")
    predicted = predict(output)
    return {"output_type": type(output).__name__, "typed_output": output.model_dump(mode="json"),
            "predicted": predicted, "expected": expected,
            "semantic_score": "passed" if predicted == expected else "failed"}


def workflow_input(inputs: dict) -> dict:
    from pydantic_ai.messages import CachePoint
    content = []
    for part in inputs["prompt"]:
        if isinstance(part, str):
            content.append(part)
        elif type(part) is CachePoint:
            content.append({"kind": "cache-point", "ttl": part.ttl})
        else:
            raise ValueError("Unexpected public prompt content")
    return {"agent": inputs["agent"], "prompt": content, "deps": inputs["deps"].model_dump(mode="json")}


def check_resolved_model(manifest: RealProviderManifest, phase: str, model) -> None:
    """The resolved runtime route must be the manifest's endpoint, model and transport."""
    if model.endpoint != manifest.endpoint:
        raise ValueError("Resolved model endpoint differs from the manifest endpoint")
    if model.resolved_model.split(":", 1)[-1] != manifest.model:
        raise ValueError("Resolved model differs from the manifest model")
    if phase == "direct" and model.broker_contract is not None:
        raise ValueError("Direct phase resolved a brokered model transport")
    if phase != "direct" and model.broker_contract is None:
        raise ValueError("Native phase resolved a direct model transport")


async def run_local_case(manifest: RealProviderManifest, phase: str, agent: str,
                         checkpoint: Callable[[dict], None] | None = None) -> dict:
    """One unchanged production LocalOps case; the caller owns its finite scope."""
    from pydantic_ai import capture_run_messages

    from infosec_harness.agents.registry import load_spec, resolve_agent_config
    from infosec_harness.graph.ops import LocalOps
    from infosec_harness.inference.wire.protocol import digest

    inputs, predict, expected, case_digest = prepare_case(agent, manifest)
    ops = LocalOps(sandbox=True, recipe_cache=False)
    row = {"agent": agent, "case": manifest.cases[agent], "case_digest": case_digest,
           "execution": "failed", "cleanup": "not_checked"}
    started = time.monotonic()
    messages = []
    try:
        config = resolve_agent_config(agent, load_spec(agent), source_files=inputs["deps"].source_files, durable=False)
        row["config"] = config.model_dump(mode="json")
        check_resolved_model(manifest, phase, config.model)
        if phase != "direct":
            row["baseline_comparison"] = compare_baseline(agent, row["config"], case_digest, cases=manifest.cases)
        with capture_run_messages() as messages:
            outcome = await ops.run_agent(agent, inputs["prompt"], inputs["deps"])
        row.update(score_output(agent, outcome.output, predict, expected))
        row.update(execution="passed", requests=outcome.requests, input_tokens=outcome.input_tokens,
            output_tokens=outcome.output_tokens, tools_called=outcome.tools_called,
            effective_config=outcome.effective_config)
    except asyncio.CancelledError:
        row["failure_type"] = "CancelledError"
        raise
    except Exception as error:
        from infosec_harness.evals.errors import failure_diagnostic
        from infosec_harness.evals.intake_fields import intake_field_summary
        from infosec_harness.evals.output_retries import output_retry_summary
        row["failure_diagnostic"] = failure_diagnostic(error)
        row["output_retry_summary"] = output_retry_summary(messages, agent=agent)
        row["intake_field_summary"] = intake_field_summary(
            messages, report=getattr(inputs["deps"], "report_text", None), agent=agent)
        row["failure_type"] = type(error).__name__
        row["broker_error_code"] = getattr(error, "code", None)
    finally:
        try:
            await ops.close()
            row["cleanup"] = "passed"
        except Exception as error:
            row["cleanup"] = "failed"
            row["cleanup_failure_type"] = type(error).__name__
        if phase != "direct":
            row["ledger"] = await ledger_snapshot(digest({"local_run": ops._broker_run_id}))
        row["elapsed_seconds"] = round(time.monotonic() - started, 3)
        if checkpoint is not None:
            checkpoint(row)
    return row


def _summarize(report: dict, gates: tuple[str, ...]) -> None:
    rows = report["cases"]
    complete = len(rows) == len(CASES)
    report["execution_status"] = "passed" if complete and all(
        row.get(gate) == "passed" for row in rows for gate in gates) else "failed"
    report["semantic_status"] = "passed" if complete and all(
        row.get("semantic_score") == "passed" for row in rows) else "failed"


async def run_local(manifest: RealProviderManifest, phase: str, report_path: Path) -> dict:
    from infosec_harness.agents.registry import BINDINGS
    if set(CASES) != set(BINDINGS):
        raise ValueError("Every registered agent must have a frozen case")
    report = {"phase": phase, "status": "running", "provider": manifest.endpoint, "model": manifest.model,
              "cases": [], "accuracy_scope": "one frozen case per agent; not a release-quality accuracy gate"}
    private_write(report_path, report)

    def checkpoint(row):
        report["cases"].append(row)
        private_write(report_path, report)

    for agent in CASES:
        await run_local_case(manifest, phase, agent, checkpoint=checkpoint)
    _summarize(report, ("execution", "cleanup"))
    report["status"] = "passed" if report["execution_status"] == report["semantic_status"] == "passed" else "failed"
    private_write(report_path, report)
    return report


async def seed_root(root_id: str, manifest: RealProviderManifest) -> None:
    from infosec_harness.agents.durable import CONFIGS
    from infosec_harness.agents.registry import ACTIVITY_MAX_ATTEMPTS
    from infosec_harness.persistence import budgets, db
    # Derive the existing RootAccounting retry envelope from the exact accepted configs.
    totals = dict.fromkeys(("requests", "tokens", "cost_usd", "tool_calls", "agent_runs", "execution_seconds"), 0)
    for config in CONFIGS.values():
        bounds = config.budget.effective
        factor = ACTIVITY_MAX_ATTEMPTS * (config.model.transport_retries + 1)
        totals["requests"] += bounds.max_requests * factor
        totals["tokens"] += (bounds.max_input_tokens + bounds.max_output_tokens) * factor
        totals["tool_calls"] += bounds.max_tool_calls * factor
        totals["agent_runs"] += 1
        totals["execution_seconds"] += bounds.max_tool_calls * 300 * ACTIVITY_MAX_ATTEMPTS
        totals["cost_usd"] += 0 if config.model.pricing_status == "known_zero" else bounds.max_cost_usd * factor
    state = budgets.initial_state(totals, elapsed_seconds=manifest.root_duration_seconds)
    state["agent_config_digests"] = {name: config.digest for name, config in CONFIGS.items()}
    async with db.session() as session:
        if await session.get(db.BudgetLedger, root_id) is not None:
            raise ValueError("Qualification root already exists")
        session.add(db.BudgetLedger(root_id=root_id, state=state))
        await session.commit()


async def recover_owned_submission(client, workflow_id: str, queue: str):
    """Recover a submitted run only after checking its declared ownership scope."""
    description = await asyncio.wait_for(client.get_workflow_handle(workflow_id).describe(), 10)
    if description.id != workflow_id:
        raise ValueError("Submitted workflow ownership differs: workflow id")
    if description.task_queue != queue:
        raise ValueError("Submitted workflow ownership differs: task queue")
    if description.workflow_type != WORKFLOW_NAME:
        raise ValueError("Submitted workflow ownership differs: workflow type")
    if not description.run_id:
        raise ValueError("Submitted workflow ownership differs: missing run id")
    return client.get_workflow_handle(workflow_id, run_id=description.run_id,
                                      first_execution_run_id=description.run_id)


def temporal_case_config(agent: str, inputs: dict):
    """Match the production per-run repository-size budget resolution."""
    from infosec_harness.agents.durable import CONFIGS
    return CONFIGS[agent].for_source_files(inputs["deps"].source_files)


def start_worker(manifest_path: str, queue: str, log) -> subprocess.Popen:
    return subprocess.Popen([sys.executable, "-m", "infosec_harness.qualification.broker.runner", "worker",
        "--manifest", manifest_path, "--queue", queue], stdout=log, stderr=log)


async def _replay_without_io(history, root_id: str) -> dict:
    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from temporalio.worker import Replayer

    from infosec_harness.qualification.broker.workflow import RealProviderWorkflow

    before = await ledger_snapshot(root_id)
    with forbid_io():
        await Replayer(workflows=[RealProviderWorkflow], plugins=[PydanticAIPlugin()]).replay_workflow(history)
    if await ledger_snapshot(root_id) != before:
        raise AssertionError("History replay changed durable ledger")
    return before


async def run_temporal(manifest: RealProviderManifest, report_path: Path) -> dict:
    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from temporalio.client import Client

    from infosec_harness.agents.outputs import InconclusiveOutput, NegativeOutput, PositiveOutput
    from infosec_harness.inference.worker import invocations
    from infosec_harness.qualification.broker.workflow import RealProviderWorkflow
    for agent in CASES:
        inputs, _predict, _expected, case_digest = prepare_case(agent, manifest)
        config = temporal_case_config(agent, inputs)
        check_resolved_model(manifest, "temporal", config.model)
        compare_baseline(agent, config.model_dump(mode="json"), case_digest, cases=manifest.cases)
    queue = "broker-real-provider-" + uuid.uuid4().hex
    report = {"phase": "temporal", "status": "running", "task_queue": queue,
              "worker_cleanup": "not_checked", "cases": []}
    process = None
    try:
        with report_path.with_suffix(".worker.log").open("ab") as log:
            process = start_worker(os.environ["HARNESS_REAL_PROVIDER_MANIFEST"], queue, log)
        report["worker_pid"] = process.pid
        private_write(report_path, report)
        client = await Client.connect(manifest.temporal_address, plugins=[PydanticAIPlugin()])
        for agent in CASES:
            inputs, predict, expected, case_digest = prepare_case(agent, manifest)
            root_id = ROOT_PREFIX + uuid.uuid4().hex
            await seed_root(root_id, manifest)
            workflow_id = "batch:" + root_id
            row = {"agent": agent, "case": manifest.cases[agent], "case_digest": case_digest,
                   "execution": "failed", "history_replay": "not_checked", "workflow_id": workflow_id,
                   "config": temporal_case_config(agent, inputs).model_dump(mode="json")}
            row["baseline_comparison"] = compare_baseline(agent, row["config"], case_digest, cases=manifest.cases)
            started = time.monotonic()
            handle = None
            try:
                handle = await client.start_workflow(RealProviderWorkflow.run,
                    {**workflow_input(inputs), "root_id": root_id}, id=workflow_id, task_queue=queue)
                result = await asyncio.wait_for(handle.result(), 1200)
                output_type = output_class(agent)
                if agent == "verdict":
                    output_type = {"InconclusiveOutput": InconclusiveOutput, "PositiveOutput": PositiveOutput,
                                   "NegativeOutput": NegativeOutput}[result["output_type"]]
                row.update(score_output(agent, output_type.model_validate(result["output"]), predict, expected))
                row.update(execution="passed", requests=result["requests"], input_tokens=result["input_tokens"],
                           output_tokens=result["output_tokens"], tools_called=result["tools_called"])
            except (Exception, asyncio.CancelledError) as error:
                row["failure_type"] = type(error).__name__
                if handle is None:
                    try:
                        handle = await recover_owned_submission(client, workflow_id, queue)
                        row["submission_recovery"] = "passed"
                    except Exception as recovery_error:
                        row["submission_recovery"] = "failed"
                        row["submission_recovery_failure_type"] = type(recovery_error).__name__
                if handle is not None:
                    with suppress(Exception):
                        await handle.terminate("Bounded real-provider qualification ended")
                if isinstance(error, asyncio.CancelledError):
                    raise
            finally:
                row["elapsed_seconds"] = round(time.monotonic() - started, 3)
                if handle is None:
                    row["ledger"] = await ledger_snapshot(root_id)
                else:
                    try:
                        # Termination skips workflow finally; close only a proven owned binding.
                        snapshot = await ledger_snapshot(root_id)
                        owned = [operation for operation in (snapshot["root_state"] or {}).get("operations", {}).values()
                                 if operation.get("broker_binding", {}).get("run_id") == handle.first_execution_run_id]
                        if owned:
                            await invocations.close_run(handle.first_execution_run_id, root_id)
                            row["cleanup"] = "passed"
                        else:
                            row["cleanup"] = "not_applicable"
                        history = await handle.fetch_history()
                        private_write(report_path.parent / f"{root_id}.history.json", json.loads(history.to_json()))
                        row["ledger"] = await _replay_without_io(history, root_id)
                        row.update(history_replay="passed", history_events=len(history.events), workflow_id=handle.id)
                    except Exception as error:
                        row["history_replay"] = "failed"
                        row["replay_failure_type"] = type(error).__name__
                        row["ledger"] = await ledger_snapshot(root_id)
                report["cases"].append(row)
                private_write(report_path, report)
    except (Exception, asyncio.CancelledError) as error:
        report["failure_type"] = type(error).__name__
        report["interrupted"] = isinstance(error, asyncio.CancelledError)
        report["status"] = "failed"
    finally:
        if process is not None:
            report["worker_cleanup"] = "passed" if await asyncio.to_thread(reap, process) else "failed"
        private_write(report_path, report)
    _summarize(report, ("execution", "history_replay"))
    report["status"] = ("passed" if report["execution_status"] == report["semantic_status"]
                        == report["worker_cleanup"] == "passed" else "failed")
    private_write(report_path, report)
    return report


async def phase_main(manifest: RealProviderManifest, args):
    verify_configuration(manifest)
    if args.phase != "worker":
        selected_phases(manifest, args.phase)
    task = asyncio.current_task()
    for termination_signal in (signal.SIGTERM, signal.SIGINT):
        asyncio.get_running_loop().add_signal_handler(termination_signal, task.cancel)
    if args.phase == "worker":
        from infosec_harness.qualification.broker.workflow import RealProviderWorkflow
        from infosec_harness.workflows.activities import ALL_ACTIVITIES

        await serve_worker(manifest.temporal_address, args.queue, [RealProviderWorkflow],
                           activities=ALL_ACTIVITIES)
        return None
    if args.phase == "temporal":
        return await run_temporal(manifest, args.report)
    return await run_local(manifest, args.phase, args.report)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("direct", "local", "temporal", "worker"))
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--queue")
    args = parser.parse_args(argv)
    manifest = RealProviderManifest.model_validate_json(args.manifest.read_text())
    if args.phase == "worker":
        if not args.queue:
            parser.error("A worker requires its owned --queue")
        asyncio.run(phase_main(manifest, args))
        return 0
    if args.report is None:
        parser.error("A phase requires --report")
    try:
        selected_phases(manifest, args.phase)
    except ValueError as error:
        parser.error(str(error))
    try:
        result = asyncio.run(phase_main(manifest, args))
    except (Exception, asyncio.CancelledError) as error:
        report = json.loads(args.report.read_text()) if args.report.exists() else {"phase": args.phase}
        report.update(status="failed", failure_type=type(error).__name__)
        private_write(args.report, report)
        return 1
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
