import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from infosec_harness import evaluation
from infosec_harness.config import get_settings
from infosec_harness.models import Finding, InvestigationResult, Verdict


def test_real_corpus_labels_and_sources_are_preserved():
    path = Path("eval-corpus/manifest.json")
    original = json.loads(path.read_text())["cases"]
    cases = evaluation.corpus_cases(path)
    assert len(cases) == len(original) > 0
    assert [expected for _, expected, _ in cases] == [
        case["truth"]["expected_verdict"] for case in original
    ]
    assert all(finding.source_mode == "working_snapshot" for finding, _, _ in cases)


async def test_failed_external_effect_is_not_retried_or_hidden(tmp_path, monkeypatch):
    finding = Finding(title="case", repo_url="repo")
    monkeypatch.setattr(evaluation, "source_identity", lambda: "commit")
    monkeypatch.setattr(
        evaluation,
        "corpus_cases",
        lambda path: [
            (finding, "potentially_exploitable", "a"),
            (finding, "likely_not_exploitable", "b"),
        ],
    )
    config = tmp_path / "runtime.json"
    config.write_text("{}")
    settings = get_settings()
    settings.openshell_config = config
    client = SimpleNamespace(start_workflow=AsyncMock(side_effect=RuntimeError("unknown effect")))
    monkeypatch.setattr(evaluation, "connect", AsyncMock(return_value=client))
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    report = tmp_path / "report.json"
    result = await evaluation.evaluate_corpus(manifest, report, get_settings())
    assert result["status"] == "failed"
    assert [case["status"] for case in result["cases"]] == ["failed", "unstarted"]
    client.start_workflow.assert_awaited_once()
    assert client.start_workflow.call_args.kwargs[
        "execution_timeout"
    ] == evaluation.execution_timeout(settings.limits)
    with pytest.raises(ValueError, match="preserve"):
        await evaluation.evaluate_corpus(manifest, report, get_settings())


async def test_false_negative_blocks_release_even_above_accuracy_threshold(
    tmp_path, monkeypatch, fixture_worker_identity
):
    finding = Finding(title="case", repo_url="repo")
    monkeypatch.setattr(evaluation, "source_identity", lambda: "commit")
    cases = [(finding, "likely_not_exploitable", str(i)) for i in range(4)]
    cases[-1] = (finding, "potentially_exploitable", "3")
    monkeypatch.setattr(evaluation, "corpus_cases", lambda path: cases)
    config = tmp_path / "runtime.json"
    config.write_text("{}")
    get_settings().openshell_config = config
    result = InvestigationResult(
        finding=finding,
        verdict=Verdict(label="likely_not_exploitable", summary="fixture"),
        evidence=[],
        source_digest="hash",
        model=get_settings().model_name,
        worker_identity=fixture_worker_identity,
    )
    client = SimpleNamespace(
        start_workflow=AsyncMock(
            return_value=SimpleNamespace(result=AsyncMock(return_value=result))
        )
    )
    monkeypatch.setattr(evaluation, "connect", AsyncMock(return_value=client))
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    report = await evaluation.evaluate_corpus(manifest, tmp_path / "report.json", get_settings())
    assert report["task_success_rate"] == 0.75 and report["unsafe_negatives"] == 1
    assert report["status"] == "failed"


async def test_cancellation_preserves_report_and_cancels_owned_workflow(tmp_path, monkeypatch):
    import asyncio

    finding = Finding(title="case", repo_url="repo")
    monkeypatch.setattr(evaluation, "source_identity", lambda: "commit")
    monkeypatch.setattr(
        evaluation, "corpus_cases", lambda path: [(finding, "inconclusive", "case")]
    )
    config = tmp_path / "runtime.json"
    config.write_text("{}")
    get_settings().openshell_config = config
    handle = SimpleNamespace(
        result=AsyncMock(side_effect=asyncio.CancelledError()), cancel=AsyncMock()
    )
    client = SimpleNamespace(
        start_workflow=AsyncMock(return_value=handle), get_workflow_handle=lambda run_id: handle
    )
    monkeypatch.setattr(evaluation, "connect", AsyncMock(return_value=client))
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    output = tmp_path / "report.json"
    with pytest.raises(asyncio.CancelledError):
        await evaluation.evaluate_corpus(manifest, output, get_settings())
    persisted = json.loads(output.read_text())
    assert persisted["status"] == "failed"
    assert persisted["cases"][0]["cancellation"] == "requested"
    assert persisted["cases"][0]["error_type"] == "CancelledError"
    client.start_workflow.assert_awaited_once()
    handle.cancel.assert_awaited_once()


def test_source_identity_ignores_caller_directory_and_ambient_git_configuration(
    tmp_path, monkeypatch
):
    calls = []

    def read(argv, **kwargs):
        calls.append((argv, kwargs))
        if "--show-toplevel" in argv:
            return str(Path(evaluation.__file__).resolve().parents[2]) + "\n"
        if "status" in argv:
            return ""
        return "commit\n"

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setattr(evaluation.subprocess, "check_output", read)
    assert evaluation.source_identity() == "commit"
    assert all(
        kwargs["cwd"] == Path(evaluation.__file__).resolve().parents[2] for _, kwargs in calls
    )
    assert all("GIT_CONFIG_COUNT" not in kwargs["env"] for _, kwargs in calls)
    assert all("core.fsmonitor=false" in argv for argv, _ in calls)


def test_release_policy_preserves_existing_gates_and_has_content_identity():
    import hashlib

    policy, digest = evaluation.release_policy()
    assert policy.minimum_task_success_rate == 0.75
    assert policy.maximum_unsafe_negatives == 0
    assert (
        digest
        == hashlib.sha256(
            Path(evaluation.__file__).with_name("release-policy.yaml").read_bytes()
        ).hexdigest()
    )


async def test_unavailable_temporal_preserves_failed_cohort_and_unchecked_quality(
    tmp_path, monkeypatch
):
    finding = Finding(title="case", repo_url="repo")
    monkeypatch.setattr(evaluation, "source_identity", lambda: "commit")
    monkeypatch.setattr(
        evaluation, "corpus_cases", lambda path: [(finding, "inconclusive", "case")]
    )
    config = tmp_path / "runtime.json"
    config.write_text("{}")
    get_settings().openshell_config = config
    monkeypatch.setattr(evaluation, "connect", AsyncMock(side_effect=RuntimeError("unavailable")))
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    output = tmp_path / "report.json"
    with pytest.raises(RuntimeError, match="unavailable"):
        await evaluation.evaluate_corpus(manifest, output, get_settings())
    persisted = json.loads(output.read_text())
    assert persisted["status"] == "failed"
    assert persisted["cases"][0]["status"] == "unstarted"
    assert persisted["gates"] == {
        "complete_corpus": "failed",
        "task_success_rate": "not_checked",
        "unsafe_negatives": "not_checked",
    }


@pytest.fixture(autouse=True)
def fixture_worker_identity(monkeypatch):
    from infosec_harness.models import WorkerIdentity

    identity = WorkerIdentity(
        fingerprint="a" * 64,
        code_sha256="b" * 64,
        config_sha256="c" * 64,
        dependencies={"fixture": "1"},
    )
    monkeypatch.setattr(evaluation, "worker_identity", lambda settings: identity)
    return identity


@pytest.mark.parametrize("mismatch", ["model", "worker"])
async def test_mismatched_worker_cannot_qualify_candidate(
    tmp_path, monkeypatch, fixture_worker_identity, mismatch
):
    finding = Finding(title="case", repo_url="repo")
    monkeypatch.setattr(evaluation, "source_identity", lambda: "commit")
    monkeypatch.setattr(evaluation, "corpus_cases", lambda path: [(finding, "inconclusive", "a")])
    config = tmp_path / "runtime.json"
    config.write_text("{}")
    settings = get_settings()
    settings.openshell_config = config
    result = InvestigationResult(
        finding=finding,
        verdict=Verdict(label="inconclusive", summary="fixture"),
        evidence=[],
        source_digest="hash",
        model="wrong" if mismatch == "model" else settings.model_name,
        worker_identity=None if mismatch == "worker" else fixture_worker_identity,
    )
    client = SimpleNamespace(
        start_workflow=AsyncMock(
            return_value=SimpleNamespace(result=AsyncMock(return_value=result))
        )
    )
    monkeypatch.setattr(evaluation, "connect", AsyncMock(return_value=client))
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    report = await evaluation.evaluate_corpus(manifest, tmp_path / "report.json", get_settings())
    assert report["status"] == "failed"
    assert report["cases"][0]["error_type"] == "ValueError"
    assert report["gates"]["task_success_rate"] == "not_checked"
    assert (
        client.start_workflow.call_args.args[1].expected_worker_identity
        == fixture_worker_identity.fingerprint
    )


@pytest.mark.parametrize("cancellation_unavailable", [False, True])
async def test_result_transport_outage_is_bounded_and_cancelled_once(
    tmp_path, monkeypatch, cancellation_unavailable
):
    import asyncio
    from datetime import timedelta

    finding = Finding(title="case", repo_url="repo")
    monkeypatch.setattr(evaluation, "source_identity", lambda: "commit")
    monkeypatch.setattr(
        evaluation,
        "corpus_cases",
        lambda path: [(finding, "inconclusive", "first"), (finding, "inconclusive", "second")],
    )
    monkeypatch.setattr(evaluation, "execution_timeout", lambda limits: timedelta(seconds=0.02))
    monkeypatch.setattr(evaluation, "RPC_TIMEOUT", timedelta(seconds=0.01))
    config = tmp_path / "runtime.json"
    config.write_text("{}")
    get_settings().openshell_config = config
    result_wait_stopped = asyncio.Event()

    async def unavailable_result():
        try:
            await asyncio.Event().wait()
        finally:
            result_wait_stopped.set()

    async def unavailable_cancel(**kwargs):
        await asyncio.Event().wait()

    handle = SimpleNamespace(
        result=AsyncMock(side_effect=unavailable_result),
        cancel=AsyncMock(side_effect=unavailable_cancel if cancellation_unavailable else None),
    )
    client = SimpleNamespace(
        start_workflow=AsyncMock(return_value=handle), get_workflow_handle=lambda run_id: handle
    )
    monkeypatch.setattr(evaluation, "connect", AsyncMock(return_value=client))
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    output = tmp_path / "report.json"
    report = await asyncio.wait_for(evaluation.evaluate_corpus(manifest, output, get_settings()), 1)
    assert result_wait_stopped.is_set()
    assert report == json.loads(output.read_text())
    assert report["status"] == "failed"
    assert report["cases"][0]["error_type"] == "TimeoutError"
    assert report["cases"][0]["cancellation"] == (
        "unconfirmed" if cancellation_unavailable else "requested"
    )
    assert report["cases"][1]["status"] == "unstarted"
    assert report["gates"]["task_success_rate"] == "not_checked"
    if cancellation_unavailable:
        assert report["cases"][0]["cancellation_error_type"] == "TimeoutError"
    client.start_workflow.assert_awaited_once()
    handle.result.assert_awaited_once()
    handle.cancel.assert_awaited_once()


def test_native_receipt_counts_include_unknown_and_do_not_double_count_replay(tmp_path):
    from infosec_harness.sandbox import native_operation_accounting

    sandbox = {"run_id": "run", "id": "native-id"}
    records = {
        "sandboxes": [{"sandbox": sandbox}, {"sandbox": {"run_id": "run", "id": ""}}],
        "qualification": [{"binding": {"sandbox": sandbox}, "workload": {}},
                          {"binding": {"sandbox": sandbox}}],
        "operations": [{"sandbox": sandbox, "result": {}}, {"sandbox": sandbox},
                       {"sandbox": {"run_id": "other"}, "result": {}}],
        "transfers": [{"source": sandbox, "sha256": "digest"}, {"source": sandbox}],
    }
    for folder, values in records.items():
        directory = tmp_path / folder
        directory.mkdir()
        for index, value in enumerate(values):
            (directory / f"{index}.json").write_text(json.dumps(value))
    first = native_operation_accounting(tmp_path, "run")
    assert first["total"] == {"completed": 4, "unknown": 4}
    assert first["categories"]["exec"] == {"completed": 1, "unknown": 1}
    assert first["native_ledger_occupancy"] == "not_checked"
    assert native_operation_accounting(tmp_path, "run") == first


def test_cohort_estimate_preserves_failed_observations_and_uses_completed_samples():
    def row(status, completed, unknown):
        return {"status": status, "native_operations": {
            "status": "observed", "total": {"completed": completed, "unknown": unknown}}}

    rows = [row("completed", 4, 0), row("completed", 6, 1),
            row("failed", 30, 2), {"status": "unstarted"}]
    estimate = evaluation.cohort_operation_estimate(rows)
    assert estimate["observed_totals"] == {"completed": 40, "unknown": 3}
    assert estimate["observed_attempt_range_per_case"] == [4, 7]
    assert estimate["estimated_cohort_attempt_range"] == [47, 50]
    assert estimate["native_capacity"] == "not_checked"
    assert evaluation.cohort_operation_estimate([row("failed", 2, 1)])["status"] == "not_checked"


def prepared_cohort(tmp_path, monkeypatch, cases):
    monkeypatch.setattr(evaluation, "source_identity", lambda: "commit")
    monkeypatch.setattr(evaluation, "corpus_cases", lambda path: cases)
    config = tmp_path / "runtime.json"
    config.write_text("{}")
    get_settings().openshell_config = config
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    return manifest


def workflow_failure(*links):
    from temporalio.client import WorkflowFailureError
    from temporalio.exceptions import ApplicationError

    errors = [ApplicationError(message, type=kind) for kind, message in links]
    for outer, inner in zip(errors, errors[1:], strict=False):
        outer.__cause__ = inner
    return WorkflowFailureError(cause=errors[0])


def test_keep_going_continues_only_after_terminal_agent_level_failure():
    from temporalio.service import RPCError, RPCStatusCode

    assert evaluation.agent_level(workflow_failure(("UsageLimitExceeded", "budget")))
    assert evaluation.agent_level(workflow_failure(("UnexpectedModelBehavior", "bad output")))
    # Observed live 2026-10-05: the executor exited 1 on a sandbox DNS failure before any
    # request was sent; its receipt is complete, so the next fresh case may proceed.
    assert evaluation.agent_level(workflow_failure(
        ("ModelExecutorError", "OpenShell model executor returned no complete response (exit 1")))
    # Live cohort 2, case 7: output corrections exhausted; the workflow names the outer type.
    assert evaluation.agent_level(workflow_failure(
        ("UnexpectedModelBehavior", "UnexpectedModelBehavior: Exceeded maximum output retries (2) "
         "<- ModelRetry: Complete probes probe:8 contradict potentially_exploitable")))
    for stop in (
        workflow_failure(("ModelExecutorError", "ModelExecutorError: executor exit <- "
                          "ExecutionUnknown: native execution outcome unknown; sandbox closed")),
        workflow_failure(("ActivityError", "Activity task failed")),
        workflow_failure(("UsageLimitExceeded", "budget"), ("ExecutionUnknown", "unknown")),
        workflow_failure(("OpenShellError", "native")),
        workflow_failure((None, "Owned sandbox cleanup failed: closed")),
        workflow_failure(("UsageLimitExceeded", "then cleanup failed")),
        workflow_failure(("CancelledError", "cancelled")),
        TimeoutError(),
        RPCError("unavailable", RPCStatusCode.UNAVAILABLE, b""),
        ValueError("Evaluation result does not match the requested worker/model identity"),
    ):
        assert not evaluation.agent_level(stop), stop
    deep = workflow_failure(*[("UsageLimitExceeded", "x" * 900)] * 12)
    chain = evaluation.failure_chain(deep)
    assert len(chain) == 5 and all(len(link["message"]) <= 500 for link in chain)
    assert not evaluation.agent_level(deep)


@pytest.mark.parametrize("keep_going", [False, True])
async def test_keep_going_never_reruns_and_cannot_pass_incomplete_cohort(
    tmp_path, monkeypatch, fixture_worker_identity, keep_going
):
    finding = Finding(title="case", repo_url="repo")
    manifest = prepared_cohort(
        tmp_path, monkeypatch,
        [(finding, "inconclusive", "a"), (finding, "inconclusive", "b"),
         (finding, "inconclusive", "c")],
    )
    result = InvestigationResult(
        finding=finding,
        verdict=Verdict(label="inconclusive", summary="fixture"),
        evidence=[],
        source_digest="hash",
        model=get_settings().model_name,
        worker_identity=fixture_worker_identity,
    )
    outcomes = [workflow_failure(("UsageLimitExceeded", "budget")), result,
                workflow_failure(("ActivityError", "Activity task failed"))]
    client = SimpleNamespace(start_workflow=AsyncMock(side_effect=[
        SimpleNamespace(result=AsyncMock(side_effect=[outcome])) for outcome in outcomes
    ]))
    monkeypatch.setattr(evaluation, "connect", AsyncMock(return_value=client))
    receipt = SimpleNamespace(operation_id="execute:1", result=SimpleNamespace(
        exit_code=2, output_truncated=True))
    monkeypatch.setattr(evaluation, "OpenShellConfig", SimpleNamespace(load=lambda path: path))
    monkeypatch.setattr(evaluation, "OpenShell", lambda config: SimpleNamespace(
        receipts=lambda run_id: [receipt]))
    report = await evaluation.evaluate_corpus(
        manifest, tmp_path / "report.json", get_settings(), keep_going=keep_going
    )
    statuses = [row["status"] for row in report["cases"]]
    assert statuses == (["failed", "completed", "failed"] if keep_going
                        else ["failed", "unstarted", "unstarted"])
    from datetime import datetime

    for row in report["cases"]:
        if row["status"] == "unstarted":
            assert not {"started_at", "finished_at", "duration_seconds"} & set(row)
            continue
        started, finished = (datetime.fromisoformat(row[key])
                             for key in ("started_at", "finished_at"))
        assert started.utcoffset().total_seconds() == 0  # UTC
        assert datetime.fromisoformat(report["started_at"]) <= started <= finished
        assert finished <= datetime.fromisoformat(report["finished_at"])
        assert row["duration_seconds"] == round((finished - started).total_seconds(), 3) >= 0
    timed = [row for row in report["cases"] if row["status"] != "unstarted"]
    assert all(datetime.fromisoformat(earlier["finished_at"])
               <= datetime.fromisoformat(later["started_at"])
               for earlier, later in zip(timed, timed[1:], strict=False))
    first = report["cases"][0]
    assert first["failure_chain"][1] == {"type": "UsageLimitExceeded",
                                        "message": "UsageLimitExceeded: budget"}
    assert first["receipts"]["items"] == [
        {"operation_id": "execute:1", "exit_code": 2, "output_truncated": True}]
    assert "cancellation" not in first  # A terminal workflow has nothing left to reconcile.
    started = [call.kwargs["id"] for call in client.start_workflow.call_args_list]
    assert len(started) == len(set(started)) == (3 if keep_going else 1)
    assert report["status"] == "failed"
    assert report["gates"] == {"complete_corpus": "failed", "task_success_rate": "not_checked",
                               "unsafe_negatives": "not_checked"}


async def test_named_cases_are_a_diagnostic_that_never_qualifies(
    tmp_path, monkeypatch, fixture_worker_identity, capsys
):
    finding = Finding(title="case", repo_url="repo")
    manifest = prepared_cohort(
        tmp_path, monkeypatch,
        [(finding, "potentially_exploitable", "a"), (finding, "inconclusive", "b")],
    )
    result = InvestigationResult(
        finding=finding,
        verdict=Verdict(label="inconclusive", summary="fixture"),
        evidence=[],
        source_digest="hash",
        model=get_settings().model_name,
        worker_identity=fixture_worker_identity,
    )
    client = SimpleNamespace(start_workflow=AsyncMock(
        return_value=SimpleNamespace(result=AsyncMock(return_value=result))))
    monkeypatch.setattr(evaluation, "connect", AsyncMock(return_value=client))
    with pytest.raises(ValueError, match="Unknown corpus case: z"):
        await evaluation.evaluate_corpus(manifest, tmp_path / "x.json", get_settings(),
                                         names=("z",))
    report = await evaluation.evaluate_corpus(
        manifest, tmp_path / "report.json", get_settings(), names=("b",)
    )
    assert report["kind"] == "diagnostic"
    assert [(row["name"], row["status"], row["passed"]) for row in report["cases"]] == [
        ("b", "completed", True)]
    assert set(report["gates"].values()) == {"not_checked"}
    assert report["status"] == "completed"
    run_id = report["cases"][0]["workflow_id"]
    assert f"[1/1] b {run_id} completed" in capsys.readouterr().err


def owned_worker_factory(monkeypatch, tmp_path, shell, respond, identity, created):
    """Test-only create_worker: real Temporal worker, fake OpenShell and fake model.

    A mocked model proves lifecycle and cleanup ordering only; it is never quality evidence.
    """
    from pydantic_ai.models.function import FunctionModel
    from temporalio.worker import Worker
    from test_workflow import runner

    from infosec_harness import workflow
    from infosec_harness.agents.investigator import build_agent

    def create(client, settings):
        workflow.bind_investigator(build_agent(shell, FunctionModel(respond)))

        async def snapshot(finding, run_id):
            return SimpleNamespace(path=str(tmp_path), digest="digest")

        activities = workflow.InvestigationActivities(
            shell, snapshot, settings.model_name, identity=lambda: identity
        )
        created.append(settings)
        return Worker(
            client,
            task_queue=settings.task_queue,
            workflows=[workflow.InvestigationWorkflow],
            activities=[activities.prepare, activities.finalize, activities.cleanup],
            workflow_runner=runner(),
        )

    monkeypatch.setattr(workflow, "create_worker", create)


@pytest.mark.requires_temporal
async def test_owned_worker_keeps_going_after_agent_failure_and_replays(
    temporal_cli, tmp_path, monkeypatch, fixture_worker_identity
):
    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from pydantic_ai.messages import ModelResponse, ToolCallPart
    from temporalio.client import WorkflowExecutionStatus
    from temporalio.testing import WorkflowEnvironment
    from test_agent import FakeOpenShell, final_response

    from infosec_harness.models import Limits

    shell = FakeOpenShell()
    created = []

    def respond(messages, info):
        if "over-budget" in str(messages[0]):
            return ModelResponse(parts=[ToolCallPart("execute", {"command": "true"},
                                                     tool_call_id=f"c{len(messages)}")])
        return final_response(info)

    owned_worker_factory(monkeypatch, tmp_path, shell, respond, fixture_worker_identity, created)
    manifest = prepared_cohort(tmp_path, monkeypatch, [
        (Finding(title="over-budget", repo_url="fixture"), "inconclusive", "a"),
        (Finding(title="answers", repo_url="fixture"), "inconclusive", "b"),
    ])
    settings = get_settings()
    settings.limits = Limits(max_requests=1)
    async with await WorkflowEnvironment.start_local(
        dev_server_existing_path=temporal_cli, plugins=[PydanticAIPlugin()]
    ) as env:
        monkeypatch.setattr(evaluation, "connect", AsyncMock(return_value=env.client))
        report = await asyncio.wait_for(evaluation.evaluate_corpus(
            manifest, tmp_path / "report.json", settings, owned_worker=True, keep_going=True
        ), 60)
        first, second = report["cases"]
        assert report["task_queue"] == created[0].task_queue
        assert report["task_queue"].startswith("investigate-v11-eval-")
        assert settings.task_queue == "investigate-v11"  # The operator's settings are unchanged.
        assert first["status"] == "failed" and second["status"] == "completed"
        assert first["failure_chain"][1]["type"] == "UsageLimitExceeded"
        assert shell.closed == [first["workflow_id"], second["workflow_id"]]
        assert report["status"] == "failed" and report["gates"]["complete_corpus"] == "failed"
        executions = list(shell.executions)
        replayed = await evaluation.replay_history(second["workflow_id"], settings, env.client)
        assert replayed["status"] == "passed" and replayed["verdict"] == "inconclusive"
        assert replayed["history_events"] > 0 and len(replayed["history_sha256"]) == 64
        assert shell.executions == executions
        description = await env.client.get_workflow_handle(second["workflow_id"]).describe()
        assert description.status == WorkflowExecutionStatus.COMPLETED


@pytest.mark.requires_temporal
async def test_owned_worker_stays_up_until_cancelled_run_cleans_up(
    temporal_cli, tmp_path, monkeypatch, fixture_worker_identity
):
    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from temporalio.client import WorkflowExecutionStatus
    from temporalio.testing import WorkflowEnvironment
    from test_agent import FakeOpenShell

    shell = FakeOpenShell()
    entered = asyncio.Event()

    async def respond(messages, info):
        entered.set()
        await asyncio.Event().wait()

    owned_worker_factory(monkeypatch, tmp_path, shell, respond, fixture_worker_identity, [])
    manifest = prepared_cohort(tmp_path, monkeypatch, [
        (Finding(title="blocks", repo_url="fixture"), "inconclusive", "a"),
        (Finding(title="never", repo_url="fixture"), "inconclusive", "b"),
    ])
    output = tmp_path / "report.json"
    async with await WorkflowEnvironment.start_local(
        dev_server_existing_path=temporal_cli, plugins=[PydanticAIPlugin()]
    ) as env:
        monkeypatch.setattr(evaluation, "connect", AsyncMock(return_value=env.client))
        task = asyncio.create_task(evaluation.evaluate_corpus(
            manifest, output, get_settings(), owned_worker=True))
        await asyncio.wait_for(entered.wait(), 30)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 60)
        persisted = json.loads(output.read_text())
        row = persisted["cases"][0]
        # Cleanup completed before evaluate_corpus (and its owned worker) returned.
        assert shell.closed == [row["workflow_id"]]
        assert row["cancellation"] == "terminal"
        assert persisted["cases"][1]["status"] == "unstarted"
        description = await env.client.get_workflow_handle(row["workflow_id"]).describe()
        assert description.status == WorkflowExecutionStatus.CANCELED
