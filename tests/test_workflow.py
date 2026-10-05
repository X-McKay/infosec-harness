"""Real Temporal histories: replay, worker restart, cancellation, and failure cleanup."""

import asyncio
import uuid
from datetime import timedelta
from types import SimpleNamespace

import pytest
from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
from pydantic_ai.messages import ModelResponse, ToolCallPart
from pydantic_ai.models.function import FunctionModel
from temporalio.client import WorkflowFailureError
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Replayer, Worker
from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner, SandboxRestrictions
from test_agent import FakeOpenShell, final_response

from infosec_harness.agent import InvestigationDeps, build_agent
from infosec_harness.models import Citation, Finding, InvestigationRequest, Limits, Verdict
from infosec_harness.workflow import (
    FinalizeInvestigation,
    InvestigationActivities,
    InvestigationWorkflow,
    PreparedInvestigation,
    bind_investigator,
)


def runner():
    return SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules(
            "infosec_harness.workflow", "annotated_types", "typing_inspection"
        )
    )


async def test_finalize_rejects_invented_receipt_and_source_lines(tmp_path):
    shell = FakeOpenShell()
    activities = InvestigationActivities(shell, None, "fixture")
    request = InvestigationRequest(finding=Finding(title="Sink", repo_url="fixture"))
    prepared = PreparedInvestigation(
        deps=InvestigationDeps(
            run_id="run",
            sandbox=await shell.create("run"),
            source_digest="digest",
            snapshot_path="/fixture",
            request=request,
        ),
        snapshot_path=str(tmp_path),
    )
    verdict = Verdict(label="inconclusive", summary="Evidence absent", evidence_ids=["invented"])
    with pytest.raises(ValueError, match="trusted OpenShell receipt"):
        await activities.finalize(
            FinalizeInvestigation(prepared=prepared, verdict=verdict, usage={})
        )
    (tmp_path / "sink.py").write_text("source\n")
    verdict = Verdict(
        label="inconclusive",
        summary="Line absent",
        citations=[Citation(path="sink.py", start_line=1, end_line=2)],
    )
    with pytest.raises(ValueError, match="exceeds source"):
        await activities.finalize(
            FinalizeInvestigation(prepared=prepared, verdict=verdict, usage={})
        )


@pytest.mark.requires_temporal
async def test_real_temporal_replay_and_restart(temporal_cli, tmp_path):
    from pydantic_ai.messages import ModelRequest, RetryPromptPart

    shell = FakeOpenShell()
    model_calls = []
    command_done = asyncio.Event()
    release_command = asyncio.Event()
    native_execute = shell.execute

    async def execute(sandbox, command, **kwargs):
        command_done.set()
        await release_command.wait()
        return await native_execute(sandbox, command, **kwargs)

    shell.execute = execute

    async def respond(messages, info):
        model_calls.append(len(messages))
        if not shell.executions:
            return ModelResponse(
                parts=[
                    ToolCallPart("execute", {"command": "python regression.py"}, tool_call_id="cmd")
                ]
            )
        if len(model_calls) == 2:
            return final_response(info, evidence_ids=["execute:1"])
        assert any(
            isinstance(part, RetryPromptPart) and "exact full Evidence.id" in part.content
            for message in messages
            if isinstance(message, ModelRequest)
            for part in message.parts
        )
        return final_response(info, evidence_ids=[shell._receipts[0].operation_id])

    agent = build_agent(shell, FunctionModel(respond))
    bind_investigator(agent)

    async def snapshot(finding, run_id):
        return SimpleNamespace(path=str(tmp_path), digest="digest")

    activities = InvestigationActivities(shell, snapshot, "fixture")
    queue = f"investigate-{uuid.uuid4()}"
    async with await WorkflowEnvironment.start_local(  # noqa: SIM117
        dev_server_existing_path=temporal_cli, plugins=[PydanticAIPlugin()]
    ) as env:
        worker_args = dict(
            task_queue=queue,
            workflows=[InvestigationWorkflow],
            activities=[activities.prepare, activities.finalize, activities.cleanup],
            workflow_runner=runner(),
            graceful_shutdown_timeout=timedelta(seconds=30),
        )
        worker = Worker(env.client, **worker_args)
        task = asyncio.create_task(worker.run())
        handle = await env.client.start_workflow(
            InvestigationWorkflow.run,
            InvestigationRequest(finding=Finding(title="Sink", repo_url="fixture")),
            id=queue,
            task_queue=queue,
        )
        await asyncio.wait_for(command_done.wait(), 30)
        assert (await handle.query(InvestigationWorkflow.state)).phase == "investigating"
        # Stop polling before the command completes, then record the in-flight completion.
        shutdown = asyncio.create_task(worker.shutdown())
        await asyncio.sleep(0.1)
        release_command.set()
        await shutdown
        await task
        assert len(model_calls) == 1
        assert (await handle.describe()).status.name == "RUNNING"
        async with Worker(env.client, **worker_args):
            result = await asyncio.wait_for(handle.result(), 30)
            assert result.verdict.evidence_ids == ["execute:1:cmd"]
            assert shell.closed == [queue]
        calls_before = list(model_calls)
        commands_before = list(shell.executions)
        history = await handle.fetch_history()
        await Replayer(
            workflows=[InvestigationWorkflow],
            plugins=[PydanticAIPlugin()],
            workflow_runner=runner(),
        ).replay_workflow(history)
        assert model_calls == calls_before
        assert shell.executions == commands_before
        assert len(shell.executions) == 1
        assert len(model_calls) == 3


@pytest.mark.requires_temporal
@pytest.mark.parametrize("mode", ["caller", "deadline"])
async def test_real_temporal_cancel_cleans_owned_sandboxes(temporal_cli, tmp_path, mode):
    shell = FakeOpenShell()
    entered = asyncio.Event()
    cancelled = asyncio.Event()

    async def respond(messages, info):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    bind_investigator(build_agent(shell, FunctionModel(respond)))

    async def snapshot(finding, run_id):
        return SimpleNamespace(path=str(tmp_path), digest="digest")

    activities = InvestigationActivities(shell, snapshot, "fixture")
    queue = f"cancel-{uuid.uuid4()}"
    async with await WorkflowEnvironment.start_local(  # noqa: SIM117
        dev_server_existing_path=temporal_cli, plugins=[PydanticAIPlugin()]
    ) as env:
        async with Worker(
            env.client,
            task_queue=queue,
            workflows=[InvestigationWorkflow],
            activities=[activities.prepare, activities.finalize, activities.cleanup],
            workflow_runner=runner(),
        ):
            handle = await env.client.start_workflow(
                InvestigationWorkflow.run,
                InvestigationRequest(
                    finding=Finding(title="Sink", repo_url="fixture"),
                    limits=Limits(timeout_seconds=1 if mode == "deadline" else 1800),
                ),
                id=queue,
                task_queue=queue,
            )
            await asyncio.wait_for(entered.wait(), 30)
            if mode == "caller":
                await handle.cancel()
            with pytest.raises(WorkflowFailureError):
                await asyncio.wait_for(handle.result(), 30)
            assert shell.closed == [queue]
            assert (await handle.query(InvestigationWorkflow.state)).status == (
                "cancelled" if mode == "caller" else "failed"
            )
            await asyncio.wait_for(cancelled.wait(), 30)


@pytest.mark.requires_temporal
@pytest.mark.parametrize("stage", ["model", "tool"])
async def test_real_temporal_unknown_side_effect_is_never_retried(temporal_cli, tmp_path, stage):
    shell = FakeOpenShell()
    model_calls = []

    async def execute(sandbox, command, **kwargs):
        shell.executions.append(command)
        raise RuntimeError("Dispatch outcome is unknown")

    shell.execute = execute

    def respond(messages, info):
        model_calls.append(messages)
        if stage == "model":
            raise RuntimeError("Provider response is unknown")
        return ModelResponse(
            parts=[ToolCallPart("execute", {"command": "side_effect"}, tool_call_id="x")]
        )

    bind_investigator(build_agent(shell, FunctionModel(respond)))

    async def snapshot(finding, run_id):
        return SimpleNamespace(path=str(tmp_path), digest="digest")

    activities = InvestigationActivities(shell, snapshot, "fixture")
    queue = f"failure-{uuid.uuid4()}"
    async with await WorkflowEnvironment.start_local(  # noqa: SIM117
        dev_server_existing_path=temporal_cli, plugins=[PydanticAIPlugin()]
    ) as env:
        async with Worker(
            env.client,
            task_queue=queue,
            workflows=[InvestigationWorkflow],
            activities=[activities.prepare, activities.finalize, activities.cleanup],
            workflow_runner=runner(),
        ):
            handle = await env.client.start_workflow(
                InvestigationWorkflow.run,
                InvestigationRequest(finding=Finding(title="Sink", repo_url="fixture")),
                id=queue,
                task_queue=queue,
            )
            with pytest.raises(WorkflowFailureError):
                await asyncio.wait_for(handle.result(), 30)
            assert len(model_calls) == 1
            assert len(shell.executions) == (1 if stage == "tool" else 0)
            assert shell.closed == [queue]


@pytest.mark.parametrize("label", ["likely_not_exploitable", "potentially_exploitable"])
async def test_definitive_verdict_without_execution_becomes_inconclusive(tmp_path, label):
    shell = FakeOpenShell()
    request = InvestigationRequest(finding=Finding(title="Sink", repo_url="fixture"))
    prepared = PreparedInvestigation(
        deps=InvestigationDeps(
            run_id="run",
            sandbox=await shell.create("run"),
            source_digest="digest",
            snapshot_path="/fixture",
            request=request,
        ),
        snapshot_path=str(tmp_path),
    )
    verdict = Verdict(label=label, summary="No tests ran.")
    result = await InvestigationActivities(shell, None, "fixture").finalize(
        FinalizeInvestigation(prepared=prepared, verdict=verdict, usage={})
    )
    assert result.verdict.label == "inconclusive"
    assert "lacked a cited successful offline probe" in result.limitations[0]


@pytest.mark.parametrize("negative_control", [True, False])
async def test_negative_verdict_requires_both_declared_controls(tmp_path, negative_control):
    import json

    from infosec_harness.openshell import CommandResult

    shell = FakeOpenShell()
    request = InvestigationRequest(finding=Finding(title="Sink", repo_url="fixture"))
    prepared = PreparedInvestigation(
        deps=InvestigationDeps(
            run_id="run",
            sandbox=await shell.create("run"),
            source_digest="digest",
            snapshot_path="/fixture",
            request=request,
        ),
        snapshot_path=str(tmp_path),
    )
    (tmp_path / "sink.py").write_text("source\n")
    probe = await shell.create("run", profile="probe")
    shell._receipts.append(
        SimpleNamespace(
            sandbox=probe,
            command=["python", "probe.py"],
            operation_id="probe:1:x",
            workspace_digest="checked-archive-digest",
            source_verified=True,
            result=CommandResult(
                0,
                "HARNESS_PROBE "
                + json.dumps(
                    {
                        "target_reached": True,
                        "oracle_valid": True,
                        "positive_control": True,
                        "negative_control": negative_control,
                        "vulnerability_observed": False,
                    }
                ),
                "",
            ),
        )
    )
    verdict = Verdict(
        label="likely_not_exploitable",
        summary="Blocked at source check.",
        evidence_ids=["probe:1:x"],
        citations=[Citation(path="sink.py", start_line=1, end_line=1)],
    )
    result = await InvestigationActivities(shell, None, "fixture").finalize(
        FinalizeInvestigation(prepared=prepared, verdict=verdict, usage={})
    )
    assert result.verdict.label == (
        "likely_not_exploitable" if negative_control else "inconclusive"
    )
    assert result.evidence[0].observations["origin"] == "self_reported"
    assert any("not independently verified" in limitation for limitation in result.limitations)


async def test_report_excerpts_do_not_invalidate_complete_native_probe(tmp_path):
    import json

    from infosec_harness.openshell import CommandResult

    shell = FakeOpenShell()
    request = InvestigationRequest(finding=Finding(title="Sink", repo_url="fixture"))
    prepared = PreparedInvestigation(
        deps=InvestigationDeps(
            run_id="run",
            sandbox=await shell.create("run"),
            source_digest="digest",
            snapshot_path=str(tmp_path),
            request=request,
        ),
        snapshot_path=str(tmp_path),
    )
    (tmp_path / "sink.py").write_text("source\n")
    marker = {
        "target_reached": True,
        "oracle_valid": True,
        "positive_control": True,
        "negative_control": True,
        "vulnerability_observed": False,
    }
    shell._receipts.append(
        SimpleNamespace(
            sandbox=await shell.create("run", profile="probe"),
            command=["probe"],
            operation_id="probe:1:x",
            workspace_digest="checked-digest",
            source_verified=True,
            result=CommandResult(
                0, "large context\n" * 10000 + "HARNESS_PROBE " + json.dumps(marker), ""
            ),
        )
    )
    verdict = Verdict(
        label="likely_not_exploitable",
        summary="Guard blocked the tested payload.",
        evidence_ids=["probe:1:x"],
        citations=[Citation(path="sink.py", start_line=1, end_line=1)],
    )
    result = await InvestigationActivities(shell, None, "fixture").finalize(
        FinalizeInvestigation(prepared=prepared, verdict=verdict, usage={})
    )
    assert result.verdict.label == "likely_not_exploitable"
    assert result.evidence[0].output_truncated is False
    assert len(result.evidence[0].stdout.encode()) <= 4096
    assert result.evidence[0].observations["report_excerpted"] is True


@pytest.mark.requires_temporal
async def test_history_budget_fails_before_oversized_schedule_and_cleans_up(temporal_cli, tmp_path):
    from pydantic_ai.messages import ThinkingPart

    shell = FakeOpenShell()
    model_calls = []

    def respond(messages, info):
        model_calls.append(len(messages))
        return ModelResponse(
            parts=[
                ThinkingPart("x" * 400_000),
                ToolCallPart("execute", {"command": "true"}, tool_call_id=f"cmd{len(model_calls)}"),
            ]
        )

    bind_investigator(build_agent(shell, FunctionModel(respond)))

    async def snapshot(finding, run_id):
        return SimpleNamespace(path=str(tmp_path), digest="digest")

    activities = InvestigationActivities(shell, snapshot, "fixture")
    queue = f"budget-{uuid.uuid4()}"
    async with await WorkflowEnvironment.start_local(
        dev_server_existing_path=temporal_cli, plugins=[PydanticAIPlugin()]
    ) as env:
        async with Worker(
            env.client,
            task_queue=queue,
            workflows=[InvestigationWorkflow],
            activities=[activities.prepare, activities.finalize, activities.cleanup],
            workflow_runner=runner(),
        ):
            handle = await env.client.start_workflow(
                InvestigationWorkflow.run,
                InvestigationRequest(
                    finding=Finding(title="Sink", repo_url="fixture"),
                    limits=Limits(total_tokens=2_000_000),
                ),
                id=queue,
                task_queue=queue,
            )
            with pytest.raises(WorkflowFailureError) as error:
                await asyncio.wait_for(handle.result(), 30)
            assert "durable payload budget" in str(error.value.cause)
            assert len(model_calls) == 3
            assert len(shell.executions) == 3
            assert shell.closed == [queue]
            assert (await handle.query(InvestigationWorkflow.state)).status == "failed"
        history = await handle.fetch_history()
        await Replayer(
            workflows=[InvestigationWorkflow],
            plugins=[PydanticAIPlugin()],
            workflow_runner=runner(),
        ).replay_workflow(history)
        assert len(model_calls) == 3


@pytest.mark.requires_temporal
async def test_total_history_guard_stops_mixed_tool_batch_and_replays(
    temporal_cli, tmp_path, monkeypatch
):
    from temporalio import workflow

    from infosec_harness.agent import DurablePayloadLimit

    # Large valid finding repeats in native activity dependencies; lower the test guard
    # to cross it in one batch, rather than constructing tens of megabytes of history.
    monkeypatch.setattr("infosec_harness.agent.MAX_HISTORY_BYTES", 2_000_000)
    shell = FakeOpenShell()
    observed = []
    before = DurablePayloadLimit.before_tool_execute

    async def observe(self, ctx, *, call, tool_def, args):
        observed.append(
            (
                call.tool_name,
                workflow.info().get_current_history_size(),
                ctx.tool_manager.get_parallel_execution_mode(),
            )
        )
        return await before(self, ctx, call=call, tool_def=tool_def, args=args)

    monkeypatch.setattr(DurablePayloadLimit, "before_tool_execute", observe)
    calls = []

    def respond(messages, info):
        calls.append(len(messages))
        return ModelResponse(
            parts=[
                ToolCallPart("load_capability", {"id": "investigate"}, tool_call_id="skill-first"),
                ToolCallPart("execute", {"command": "true"}, tool_call_id="first"),
                ToolCallPart("load_capability", {"id": "probe"}, tool_call_id="skill-after"),
                ToolCallPart("execute", {"command": "true"}, tool_call_id="after"),
            ]
        )

    bind_investigator(build_agent(shell, FunctionModel(respond)))

    async def snapshot(finding, run_id):
        return SimpleNamespace(path=str(tmp_path), digest="digest")

    activities = InvestigationActivities(shell, snapshot, "fixture")
    queue = f"history-{uuid.uuid4()}"
    async with await WorkflowEnvironment.start_local(
        dev_server_existing_path=temporal_cli, plugins=[PydanticAIPlugin()]
    ) as env:
        async with Worker(
            env.client,
            task_queue=queue,
            workflows=[InvestigationWorkflow],
            activities=[activities.prepare, activities.finalize, activities.cleanup],
            workflow_runner=runner(),
        ):
            handle = await env.client.start_workflow(
                InvestigationWorkflow.run,
                InvestigationRequest(
                    finding=Finding(
                        title="Large finding", repo_url="fixture", description="\U0001f63a" * 90_000
                    ),
                    limits=Limits(total_tokens=2_000_000),
                ),
                id=queue,
                task_queue=queue,
            )
            with pytest.raises(WorkflowFailureError) as error:
                await asyncio.wait_for(handle.result(), 30)
            assert "durable history budget" in str(error.value.cause)
            assert len(calls) == 1
            assert len(shell.executions) == 1
            assert shell.closed == [queue]
            assert [item[0] for item in observed] == [
                "load_capability",
                "execute",
                "load_capability",
            ]
            assert all(item[2] == "sequential" for item in observed)
            assert observed[1][1] < 2_000_000 <= observed[2][1]
            assert (await handle.query(InvestigationWorkflow.state)).status == "failed"
        history = await handle.fetch_history()
        await Replayer(
            workflows=[InvestigationWorkflow],
            plugins=[PydanticAIPlugin()],
            workflow_runner=runner(),
        ).replay_workflow(history)
        assert len(calls) == 1 and len(shell.executions) == 1


@pytest.mark.requires_temporal
async def test_model_finding_prompt_excludes_host_variant_path(temporal_cli, tmp_path):
    import json

    from pydantic_ai.messages import ModelRequest, UserPromptPart

    shell = FakeOpenShell()
    prompts = []

    def respond(messages, info):
        prompts.extend(
            part.content
            for message in messages
            if isinstance(message, ModelRequest)
            for part in message.parts
            if isinstance(part, UserPromptPart)
        )
        return final_response(info)

    bind_investigator(build_agent(shell, FunctionModel(respond)))

    async def snapshot(finding, run_id):
        assert finding.repo_url == "/operator/private/eval-corpus/python/cmdi/fixed"
        return SimpleNamespace(path=str(tmp_path), digest="digest")

    activities = InvestigationActivities(shell, snapshot, "fixture")
    finding = Finding(
        title="Command input",
        repo_url="/operator/private/eval-corpus/python/cmdi/fixed",
        description="Inspect the target handler.",
        cwe="CWE-78",
    )
    queue = f"prompt-{uuid.uuid4()}"
    async with (
        await WorkflowEnvironment.start_local(
            dev_server_existing_path=temporal_cli, plugins=[PydanticAIPlugin()]
        ) as env,
        Worker(
            env.client,
            task_queue=queue,
            workflows=[InvestigationWorkflow],
            activities=[activities.prepare, activities.finalize, activities.cleanup],
            workflow_runner=runner(),
        ),
    ):
        result = await asyncio.wait_for(
            env.client.execute_workflow(
                InvestigationWorkflow.run,
                InvestigationRequest(finding=finding),
                id=queue,
                task_queue=queue,
            ),
            30,
        )
    assert len(prompts) == 1
    assert "repo_url" not in json.loads(prompts[0])
    assert "fixed" not in prompts[0] and "/operator/private" not in prompts[0]
    assert json.loads(prompts[0])["description"] == finding.description
    assert result.finding == finding
    assert shell.closed == [queue]


@pytest.mark.parametrize("label", ["potentially_exploitable", "likely_not_exploitable"])
@pytest.mark.parametrize("both_cited", [False, True])
async def test_complete_contrary_probe_prevents_definitive_verdict_even_when_uncited(
    tmp_path, label, both_cited
):
    import json

    from infosec_harness.openshell import CommandResult

    shell = FakeOpenShell()
    request = InvestigationRequest(finding=Finding(title="Sink", repo_url="fixture"))
    prepared = PreparedInvestigation(
        deps=InvestigationDeps(
            run_id="run",
            sandbox=await shell.create("run"),
            source_digest="digest",
            snapshot_path=str(tmp_path),
            request=request,
        ),
        snapshot_path=str(tmp_path),
    )
    (tmp_path / "sink.py").write_text("source\n")
    expected = label == "potentially_exploitable"
    for name, observed in (("matching", expected), ("contrary", not expected)):
        marker = {
            key: True
            for key in ("target_reached", "oracle_valid", "positive_control", "negative_control")
        }
        marker["vulnerability_observed"] = observed
        shell._receipts.append(
            SimpleNamespace(
                sandbox=await shell.create("run", profile="probe", slot=name),
                command=["python", name + ".py"],
                operation_id=f"probe:1:{name}",
                workspace_digest="native-source-checked-archive",
                source_verified=True,
                result=CommandResult(0, "HARNESS_PROBE " + json.dumps(marker), ""),
            )
        )
    verdict = Verdict(
        label=label,
        summary="Proposed conclusion.",
        evidence_ids=["probe:1:matching", "probe:1:contrary"]
        if both_cited
        else ["probe:1:matching"],
        citations=[Citation(path="sink.py", start_line=1, end_line=1)],
    )
    result = await InvestigationActivities(shell, None, "fixture").finalize(
        FinalizeInvestigation(prepared=prepared, verdict=verdict, usage={})
    )
    assert result.verdict.label == "inconclusive"
    assert "contradictory" in result.verdict.summary
    assert any(
        "probe:1:contrary" in limitation and "contradictory" in limitation
        for limitation in result.limitations
    )
    assert {item.id for item in result.evidence} == {"probe:1:matching", "probe:1:contrary"}


@pytest.mark.parametrize("defect", ["failed", "truncated", "unverified", "control_failed"])
async def test_incomplete_contrary_probe_is_not_a_qualified_observation(tmp_path, defect):
    import json

    from infosec_harness.openshell import CommandResult

    shell = FakeOpenShell()
    request = InvestigationRequest(finding=Finding(title="Sink", repo_url="fixture"))
    prepared = PreparedInvestigation(
        deps=InvestigationDeps(
            run_id="run",
            sandbox=await shell.create("run"),
            source_digest="digest",
            snapshot_path=str(tmp_path),
            request=request,
        ),
        snapshot_path=str(tmp_path),
    )
    (tmp_path / "sink.py").write_text("source\n")
    for name, observed in (("matching", False), ("contrary", True)):
        contrary = name == "contrary"
        marker = {
            key: True
            for key in ("target_reached", "oracle_valid", "positive_control", "negative_control")
        }
        marker["vulnerability_observed"] = observed
        if contrary and defect == "control_failed":
            marker["negative_control"] = False
        shell._receipts.append(
            SimpleNamespace(
                sandbox=await shell.create("run", profile="probe", slot=name),
                command=["probe"],
                operation_id=f"probe:1:{name}",
                workspace_digest="checked",
                source_verified=not (contrary and defect == "unverified"),
                result=CommandResult(
                    1 if contrary and defect == "failed" else 0,
                    "HARNESS_PROBE " + json.dumps(marker),
                    "",
                    contrary and defect == "truncated",
                ),
            )
        )
    verdict = Verdict(
        label="likely_not_exploitable",
        summary="Blocked tested payload.",
        evidence_ids=["probe:1:matching"],
        citations=[Citation(path="sink.py", start_line=1, end_line=1)],
    )
    result = await InvestigationActivities(shell, None, "fixture").finalize(
        FinalizeInvestigation(prepared=prepared, verdict=verdict, usage={})
    )
    assert result.verdict.label == "likely_not_exploitable"
    assert not any("contradictory" in limitation for limitation in result.limitations)
