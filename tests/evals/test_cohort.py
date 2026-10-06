import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from infosec_harness.config import get_settings
from infosec_harness.contracts import Finding, InvestigationResult, Limits, Verdict
from infosec_harness.evals import cohort

# The checkout that holds this test file, found independently of the module under test.
CHECKOUT = Path(__file__).resolve().parents[2]


def test_real_corpus_labels_and_sources_are_preserved():
    path = Path("eval-corpus/manifest.json")
    original = json.loads(path.read_text())["cases"]
    cases = cohort.corpus_cases(path)
    assert len(cases) == len(original) > 0
    assert [expected for _, expected, _ in cases] == [
        case["truth"]["expected_verdict"] for case in original
    ]
    assert all(finding.source_mode == "working_snapshot" for finding, _, _ in cases)


async def test_failed_external_effect_is_not_retried_or_hidden(tmp_path, monkeypatch):
    finding = Finding(title="case", repo_url="repo")
    monkeypatch.setattr(cohort, "source_identity", lambda: "commit")
    monkeypatch.setattr(
        cohort,
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
    monkeypatch.setattr(cohort, "connect", AsyncMock(return_value=client))
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    report = tmp_path / "report.json"
    result = await cohort.evaluate_corpus(manifest, report, get_settings())
    assert result["status"] == "failed"
    assert [case["status"] for case in result["cases"]] == ["failed", "unstarted"]
    client.start_workflow.assert_awaited_once()
    assert client.start_workflow.call_args.kwargs[
        "execution_timeout"
    ] == cohort.execution_timeout(settings.limits)
    with pytest.raises(ValueError, match="preserve"):
        await cohort.evaluate_corpus(manifest, report, get_settings())


async def test_false_negative_blocks_release_even_above_accuracy_threshold(
    tmp_path, monkeypatch, fixture_worker_identity
):
    finding = Finding(title="case", repo_url="repo")
    monkeypatch.setattr(cohort, "source_identity", lambda: "commit")
    cases = [(finding, "likely_not_exploitable", str(i)) for i in range(4)]
    cases[-1] = (finding, "potentially_exploitable", "3")
    monkeypatch.setattr(cohort, "corpus_cases", lambda path: cases)
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
    monkeypatch.setattr(cohort, "connect", AsyncMock(return_value=client))
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    report = await cohort.evaluate_corpus(manifest, tmp_path / "report.json", get_settings())
    assert report["task_success_rate"] == 0.75 and report["unsafe_negatives"] == 1
    assert report["status"] == "failed"


async def test_cancellation_preserves_report_and_cancels_owned_workflow(tmp_path, monkeypatch):
    import asyncio

    finding = Finding(title="case", repo_url="repo")
    monkeypatch.setattr(cohort, "source_identity", lambda: "commit")
    monkeypatch.setattr(
        cohort, "corpus_cases", lambda path: [(finding, "inconclusive", "case")]
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
    monkeypatch.setattr(cohort, "connect", AsyncMock(return_value=client))
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    output = tmp_path / "report.json"
    with pytest.raises(asyncio.CancelledError):
        await cohort.evaluate_corpus(manifest, output, get_settings())
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
            return str(CHECKOUT) + "\n"
        if "status" in argv:
            return ""
        return "commit\n"

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setattr(cohort.subprocess, "check_output", read)
    assert cohort.source_identity() == "commit"
    assert cohort.REPOSITORY_ROOT == CHECKOUT
    assert all(kwargs["cwd"] == CHECKOUT for _, kwargs in calls)
    assert all("GIT_CONFIG_COUNT" not in kwargs["env"] for _, kwargs in calls)
    assert all("core.fsmonitor=false" in argv for argv, _ in calls)


def test_release_policy_preserves_existing_gates_and_has_content_identity():
    import hashlib

    policy, digest = cohort.release_policy()
    assert policy.minimum_task_success_rate == 0.75
    assert policy.maximum_unsafe_negatives == 0
    assert (
        digest
        == hashlib.sha256(
            Path(cohort.__file__).with_name("release-policy.yaml").read_bytes()
        ).hexdigest()
    )


async def test_unavailable_temporal_preserves_failed_cohort_and_unchecked_quality(
    tmp_path, monkeypatch
):
    finding = Finding(title="case", repo_url="repo")
    monkeypatch.setattr(cohort, "source_identity", lambda: "commit")
    monkeypatch.setattr(
        cohort, "corpus_cases", lambda path: [(finding, "inconclusive", "case")]
    )
    config = tmp_path / "runtime.json"
    config.write_text("{}")
    get_settings().openshell_config = config
    monkeypatch.setattr(cohort, "connect", AsyncMock(side_effect=RuntimeError("unavailable")))
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    output = tmp_path / "report.json"
    with pytest.raises(RuntimeError, match="unavailable"):
        await cohort.evaluate_corpus(manifest, output, get_settings())
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
    from infosec_harness.contracts import WorkerIdentity

    identity = WorkerIdentity(
        fingerprint="a" * 64,
        code_sha256="b" * 64,
        config_sha256="c" * 64,
        dependencies={"fixture": "1"},
    )
    monkeypatch.setattr(cohort, "worker_identity", lambda settings: identity)
    return identity


@pytest.mark.parametrize("mismatch", ["model", "worker"])
async def test_mismatched_worker_cannot_qualify_candidate(
    tmp_path, monkeypatch, fixture_worker_identity, mismatch
):
    finding = Finding(title="case", repo_url="repo")
    monkeypatch.setattr(cohort, "source_identity", lambda: "commit")
    monkeypatch.setattr(cohort, "corpus_cases", lambda path: [(finding, "inconclusive", "a")])
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
    monkeypatch.setattr(cohort, "connect", AsyncMock(return_value=client))
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    report = await cohort.evaluate_corpus(manifest, tmp_path / "report.json", get_settings())
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
    monkeypatch.setattr(cohort, "source_identity", lambda: "commit")
    monkeypatch.setattr(
        cohort,
        "corpus_cases",
        lambda path: [(finding, "inconclusive", "first"), (finding, "inconclusive", "second")],
    )
    monkeypatch.setattr(cohort, "execution_timeout", lambda limits: timedelta(seconds=0.02))
    monkeypatch.setattr(cohort, "RPC_TIMEOUT", timedelta(seconds=0.01))
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
    monkeypatch.setattr(cohort, "connect", AsyncMock(return_value=client))
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    output = tmp_path / "report.json"
    report = await asyncio.wait_for(cohort.evaluate_corpus(manifest, output, get_settings()), 1)
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
    estimate = cohort.cohort_operation_estimate(rows)
    assert estimate["observed_totals"] == {"completed": 40, "unknown": 3}
    assert estimate["observed_attempt_range_per_case"] == [4, 7]
    assert estimate["estimated_cohort_attempt_range"] == [47, 50]
    assert estimate["native_capacity"] == "not_checked"
    assert cohort.cohort_operation_estimate([row("failed", 2, 1)])["status"] == "not_checked"


def prepared_cohort(tmp_path, monkeypatch, cases):
    monkeypatch.setattr(cohort, "source_identity", lambda: "commit")
    monkeypatch.setattr(cohort, "corpus_cases", lambda path: cases)
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

    assert cohort.agent_level(workflow_failure(("UsageLimitExceeded", "budget")))
    assert cohort.agent_level(workflow_failure(("UnexpectedModelBehavior", "bad output")))
    # Observed live 2026-10-05: the executor exited 1 on a sandbox DNS failure before any
    # request was sent; its receipt is complete, so the next fresh case may proceed.
    assert cohort.agent_level(workflow_failure(
        ("ModelExecutorError", "OpenShell model executor returned no complete response (exit 1")))
    # Live cohort 2, case 7: output corrections exhausted; the workflow names the outer type.
    assert cohort.agent_level(workflow_failure(
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
        assert not cohort.agent_level(stop), stop
    deep = workflow_failure(*[("UsageLimitExceeded", "x" * 900)] * 12)
    chain = cohort.failure_chain(deep)
    assert len(chain) == 5 and all(len(link["message"]) <= 500 for link in chain)
    assert not cohort.agent_level(deep)


def test_keep_going_classifies_from_the_untruncated_chain_with_an_allowlist():
    # The shape the workflow writes: ActivityError around the named type, all links embedded.
    assert cohort.agent_level(workflow_failure(
        ("ModelExecutorError", "ActivityError: Activity task failed <- ModelExecutorError: "
         "OpenShell model executor returned no complete response (exit 1)")))
    # Regression: the report view cuts each message at 500 characters; a marker past the cut
    # was invisible to the classifier and --keep-going continued after unknown dispatch.
    hidden = ("UnexpectedModelBehavior: " + "x" * 400 + " <- ModelRetry: " + "y" * 400
              + " <- ExecutionUnknown: native execution outcome unknown; sandbox closed")
    assert len(hidden) > 800 and "ExecutionUnknown" not in hidden[:500]
    past_cut = workflow_failure(("UnexpectedModelBehavior", hidden))
    assert "ExecutionUnknown" not in str(cohort.failure_chain(past_cut))
    # Regression: a substring denylist let inner types it did not name through.
    for stop in (
        past_cut,
        workflow_failure(("UnexpectedModelBehavior",
                          "UnexpectedModelBehavior: x <- TimeoutError: rpc deadline")),
        workflow_failure(("ModelExecutorError", "ModelExecutorError: x <- RpcError: unavailable")),
        workflow_failure(("UsageLimitExceeded",
                          "UsageLimitExceeded: x <- UnsafeSnapshotMetadata: y")),
        workflow_failure(("UsageLimitExceeded", "budget"), ("TimeoutError", "rpc deadline")),
        # A separator not followed by a label fails closed.
        workflow_failure(("UnexpectedModelBehavior", "UnexpectedModelBehavior: x <- y")),
        # The workflow embeds at most eight links; a full message may have lost deeper ones.
        workflow_failure(("UsageLimitExceeded", " <- ".join(["ModelRetry: x"] * 8))),
    ):
        assert not cohort.agent_level(stop), stop


def test_drain_is_the_workflow_cleanup_reserve():
    from infosec_harness.workflows.investigation import CLEANUP_RESERVE

    assert cohort.DRAIN == CLEANUP_RESERVE


@pytest.mark.xfail(strict=True, reason="api.execution_timeout still reserves 600 s; the "
                   "toplevel owner derives it from CLEANUP_RESERVE (remove this mark then)")
def test_execution_timeout_reserves_owned_cleanup():
    from datetime import timedelta

    from infosec_harness.workflows.investigation import CLEANUP_RESERVE

    limits = Limits()
    reserve = cohort.execution_timeout(limits) - timedelta(seconds=limits.timeout_seconds)
    assert reserve >= CLEANUP_RESERVE


@pytest.mark.parametrize("ended", ["timed_out", "terminated"])
async def test_server_ended_run_records_unconfirmed_cleanup_and_stops(
    tmp_path, monkeypatch, ended
):
    from temporalio.client import WorkflowFailureError
    from temporalio.exceptions import TerminatedError, TimeoutError, TimeoutType

    finding = Finding(title="case", repo_url="repo")
    manifest = prepared_cohort(tmp_path, monkeypatch, [(finding, "inconclusive", "a"),
                                                        (finding, "inconclusive", "b")])
    cause = (TimeoutError("Workflow execution timed out", type=TimeoutType.START_TO_CLOSE,
                          last_heartbeat_details=[])
             if ended == "timed_out" else TerminatedError("Workflow execution terminated"))
    handle = SimpleNamespace(result=AsyncMock(side_effect=WorkflowFailureError(cause=cause)),
                             cancel=AsyncMock())
    client = SimpleNamespace(start_workflow=AsyncMock(return_value=handle),
                             get_workflow_handle=lambda run_id: handle)
    monkeypatch.setattr(cohort, "connect", AsyncMock(return_value=client))
    report = await cohort.evaluate_corpus(
        manifest, tmp_path / "report.json", get_settings(), keep_going=True)
    first, second = report["cases"]
    assert first["status"] == "failed"
    assert first["cleanup"] == "unconfirmed"
    assert "close_run" in first["cleanup_next_step"]
    assert "cancellation" not in first  # A closed run cannot be cancelled.
    handle.cancel.assert_not_awaited()
    assert second["status"] == "unstarted"  # Never agent-level, even with --keep-going.


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
    monkeypatch.setattr(cohort, "connect", AsyncMock(return_value=client))
    receipt = SimpleNamespace(operation_id="execute:1", result=SimpleNamespace(
        exit_code=2, output_truncated=True))
    monkeypatch.setattr(cohort, "OpenShellConfig", SimpleNamespace(load=lambda path: path))
    monkeypatch.setattr(cohort, "OpenShell", lambda config: SimpleNamespace(
        receipts=lambda run_id: [receipt]))
    report = await cohort.evaluate_corpus(
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


class ParallelClient:
    """Fake Temporal client: one handle per started ID, each case scripted by title.

    ``script[title]`` is ``(release, outcome)``: the result waits for ``release`` and then
    returns or raises ``outcome``. Tracks the peak number of results awaited at once.
    """

    def __init__(self, script):
        self.script, self.started, self.handles = script, [], {}
        self.in_flight = self.peak = 0
        self.cancelled = []

    async def start_workflow(self, workflow, request, *, id, **kwargs):
        title = request.finding.title
        self.started.append((title, id))
        release, outcome = self.script[title]
        client = self
        cancel_requested = asyncio.Event()

        async def result(**kwargs):
            client.in_flight += 1
            client.peak = max(client.peak, client.in_flight)
            try:
                waiters = {asyncio.ensure_future(release.wait()),
                           asyncio.ensure_future(cancel_requested.wait())}
                try:
                    await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
                finally:
                    for waiter in waiters:
                        waiter.cancel()
            finally:
                client.in_flight -= 1
            if cancel_requested.is_set():
                raise workflow_failure(("CancelledError", "Workflow cancelled"))
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome

        async def cancel(**kwargs):
            client.cancelled.append(title)
            cancel_requested.set()

        handle = SimpleNamespace(result=result, cancel=cancel)
        self.handles[id] = handle
        return handle

    def get_workflow_handle(self, run_id):
        return self.handles[run_id]


def parallel_cohort(tmp_path, monkeypatch, identity, titles, outcomes):
    finding = Finding(title="case", repo_url="repo")
    manifest = prepared_cohort(tmp_path, monkeypatch, [
        (finding.model_copy(update={"title": title}), "inconclusive", title) for title in titles])
    completed = InvestigationResult(
        finding=finding, verdict=Verdict(label="inconclusive", summary="fixture"), evidence=[],
        source_digest="hash", model=get_settings().model_name, worker_identity=identity)
    releases = {title: asyncio.Event() for title in titles}
    client = ParallelClient({title: (releases[title], outcomes.get(title, completed))
                             for title in titles})
    monkeypatch.setattr(cohort, "connect", AsyncMock(return_value=client))
    return manifest, client, releases


async def until(condition):
    async with asyncio.timeout(5):
        while not condition():
            await asyncio.sleep(0.005)


async def test_parallel_runs_at_most_n_cases_and_keeps_manifest_order(
    tmp_path, monkeypatch, fixture_worker_identity
):
    titles = list("abcdefg")
    manifest, client, releases = parallel_cohort(
        tmp_path, monkeypatch, fixture_worker_identity, titles, {})
    task = asyncio.create_task(cohort.evaluate_corpus(
        manifest, tmp_path / "report.json", get_settings(), parallel=3))
    await until(lambda: client.in_flight == 3)
    # Cases start in manifest order; finishing out of order frees slots for the next ones.
    assert [title for title, _ in client.started] == ["a", "b", "c"]
    for title in reversed(titles):
        releases[title].set()
    report = await asyncio.wait_for(task, 5)
    assert client.peak == 3
    assert [title for title, _ in client.started] == titles
    assert [row["name"] for row in report["cases"]] == titles
    assert all(row["status"] == "completed" for row in report["cases"])
    assert report["parallel"] == 3 and report["limitations"] == [cohort.PARALLEL_LIMITATION]
    assert report["status"] == "passed"
    assert report == json.loads((tmp_path / "report.json").read_text())


@pytest.mark.parametrize("keep_going", [False, True])
async def test_parallel_stop_latch_lets_in_flight_cases_finish_and_starts_no_more(
    tmp_path, monkeypatch, fixture_worker_identity, keep_going
):
    # b fails with a non-agent failure while a and c are still running.
    titles = list("abcdef")
    manifest, client, releases = parallel_cohort(
        tmp_path, monkeypatch, fixture_worker_identity, titles,
        {"b": workflow_failure(("ActivityError", "Activity task failed"))})
    task = asyncio.create_task(cohort.evaluate_corpus(
        manifest, tmp_path / "report.json", get_settings(), parallel=3, keep_going=keep_going))
    await until(lambda: client.in_flight == 3)
    releases["b"].set()
    await until(lambda: client.in_flight == 2)
    await asyncio.sleep(0.05)
    assert [title for title, _ in client.started] == ["a", "b", "c"]  # Latched: no d.
    releases["a"].set()
    releases["c"].set()
    for title in "def":
        releases[title].set()
    report = await asyncio.wait_for(task, 5)
    assert [row["status"] for row in report["cases"]] == [
        "completed", "failed", "completed", "unstarted", "unstarted", "unstarted"]
    # The failed case is never re-run and every started ID is fresh.
    started_ids = [run_id for _, run_id in client.started]
    assert len(started_ids) == len(set(started_ids)) == 3
    assert client.cancelled == []  # A sibling's failure never cancels in-flight work.
    assert report["gates"]["complete_corpus"] == "failed" and report["status"] == "failed"


async def test_parallel_keep_going_continues_past_agent_failures_without_rerunning(
    tmp_path, monkeypatch, fixture_worker_identity
):
    titles = list("abcde")
    manifest, client, releases = parallel_cohort(
        tmp_path, monkeypatch, fixture_worker_identity, titles,
        {"a": workflow_failure(("UsageLimitExceeded", "budget")),
         "d": workflow_failure(("UnexpectedModelBehavior", "bad output"))})
    for release in releases.values():
        release.set()
    report = await asyncio.wait_for(cohort.evaluate_corpus(
        manifest, tmp_path / "report.json", get_settings(), parallel=3, keep_going=True), 5)
    assert [row["status"] for row in report["cases"]] == [
        "failed", "completed", "completed", "failed", "completed"]
    assert [title for title, _ in client.started] == titles  # Each case exactly once.


async def test_parallel_cancellation_reconciles_every_in_flight_run_before_the_worker_stops(
    tmp_path, monkeypatch, fixture_worker_identity
):
    from contextlib import asynccontextmanager

    from infosec_harness.workflows import worker

    titles = list("abcde")
    manifest, client, _ = parallel_cohort(
        tmp_path, monkeypatch, fixture_worker_identity, titles, {})
    worker_stopped_after = []

    @asynccontextmanager
    async def owned(client_, settings):
        try:
            yield
        finally:
            worker_stopped_after.append(sorted(client.cancelled))

    monkeypatch.setattr(worker, "create_worker", owned)
    output = tmp_path / "report.json"
    task = asyncio.create_task(cohort.evaluate_corpus(
        manifest, output, get_settings(), owned_worker=True, parallel=3))
    await until(lambda: client.in_flight == 3)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 5)
    # Each in-flight run was cancelled and drained concurrently, before the worker stopped.
    assert worker_stopped_after == [["a", "b", "c"]]
    persisted = json.loads(output.read_text())
    assert [row["status"] for row in persisted["cases"]] == [
        "failed", "failed", "failed", "unstarted", "unstarted"]
    assert all(row["cancellation"] == "terminal" for row in persisted["cases"][:3])
    assert [title for title, _ in client.started] == ["a", "b", "c"]


@pytest.mark.parametrize("parallel", [0, cohort.MAX_PARALLEL + 1])
async def test_parallel_is_bounded(tmp_path, parallel):
    with pytest.raises(ValueError, match="parallel must be between 1 and"):
        await cohort.evaluate_corpus(tmp_path / "m.json", tmp_path / "r.json", get_settings(),
                                     parallel=parallel)


async def test_named_cases_are_a_diagnostic_that_never_qualifies(
    tmp_path, monkeypatch, fixture_worker_identity, caplog
):
    caplog.set_level("INFO", logger=cohort.__name__)
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
    monkeypatch.setattr(cohort, "connect", AsyncMock(return_value=client))
    with pytest.raises(ValueError, match="Unknown corpus case: z"):
        await cohort.evaluate_corpus(manifest, tmp_path / "x.json", get_settings(),
                                         names=("z",))
    report = await cohort.evaluate_corpus(
        manifest, tmp_path / "report.json", get_settings(), names=("b",)
    )
    assert report["kind"] == "diagnostic"
    # The report names the generation its workflow ran under (AGENTS.md: v11).
    assert report["generation"] == "v11"
    assert [(row["name"], row["status"], row["passed"]) for row in report["cases"]] == [
        ("b", "completed", True)]
    assert set(report["gates"].values()) == {"not_checked"}
    assert report["status"] == "completed"
    run_id = report["cases"][0]["workflow_id"]
    assert f"event=case_end position=1/1 case=b run_id={run_id} status=completed" in caplog.text


def owned_worker_factory(monkeypatch, tmp_path, shell, respond, identity, created):
    """Test-only create_worker: real Temporal worker, fake OpenShell and fake model.

    A mocked model proves lifecycle and cleanup ordering only; it is never quality evidence.
    """
    from pydantic_ai.models.function import FunctionModel
    from temporalio.worker import Worker

    from infosec_harness.agents.investigator import build_agent
    from infosec_harness.workflows import investigation, worker
    from infosec_harness.workflows.worker import workflow_runner

    def create(client, settings):
        investigation.bind_investigator(build_agent(shell, FunctionModel(respond)))

        async def snapshot(finding, run_id):
            return SimpleNamespace(path=str(tmp_path), digest="digest")

        activities = investigation.InvestigationActivities(
            shell, snapshot, settings.model_name, identity=lambda: identity
        )
        created.append(settings)
        return Worker(
            client,
            task_queue=settings.task_queue,
            workflows=[investigation.InvestigationWorkflow],
            activities=[activities.prepare, activities.finalize, activities.cleanup],
            workflow_runner=workflow_runner(),
        )

    monkeypatch.setattr(worker, "create_worker", create)


@pytest.mark.requires_temporal
async def test_owned_worker_keeps_going_after_agent_failure_and_replays(
    temporal_env, tmp_path, monkeypatch, fixture_worker_identity
):
    from fakes import FakeOpenShell, final_response
    from pydantic_ai.messages import ModelResponse, ToolCallPart
    from temporalio.client import WorkflowExecutionStatus

    from infosec_harness.contracts import Limits

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
    env = temporal_env
    monkeypatch.setattr(cohort, "connect", AsyncMock(return_value=env.client))
    report = await asyncio.wait_for(cohort.evaluate_corpus(
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
    replayed = await cohort.replay_history(second["workflow_id"], settings, env.client)
    assert replayed["status"] == "passed" and replayed["verdict"] == "inconclusive"
    assert replayed["history_events"] > 0 and len(replayed["history_sha256"]) == 64
    assert shell.executions == executions
    description = await env.client.get_workflow_handle(second["workflow_id"]).describe()
    assert description.status == WorkflowExecutionStatus.COMPLETED


@pytest.mark.requires_temporal
async def test_owned_worker_stays_up_until_cancelled_run_cleans_up(
    temporal_env, tmp_path, monkeypatch, fixture_worker_identity
):
    from fakes import FakeOpenShell
    from temporalio.client import WorkflowExecutionStatus

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
    env = temporal_env
    monkeypatch.setattr(cohort, "connect", AsyncMock(return_value=env.client))
    task = asyncio.create_task(cohort.evaluate_corpus(
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


def occupancy_command(output: str, exit_code: int = 0) -> list[str]:
    return [sys.executable, "-c", f"import sys; print({output!r}); sys.exit({exit_code})"]


def test_case_operation_ceiling_covers_the_largest_live_observation():
    # Private run 8 (cohort-8.json): 1,670 receipts equalled the 1,670 ledger claims it added,
    # and perl-sqli-vulnerable retained 96 at budget exhaustion under 40 requests / 100 calls.
    assert cohort.case_operation_ceiling(Limits(max_requests=40, max_tool_calls=100)) >= 96
    assert cohort.case_operation_ceiling(Limits()) == 30 + 100 + cohort.CASE_LIFECYCLE_OPERATIONS


@pytest.mark.parametrize(
    ("command", "error_type", "detail"),
    [
        (occupancy_command(json.dumps({"retained": 1, "quota": 20000, "read_only": False})),
         "ValueError", "read_only: value_error"),
        (occupancy_command(json.dumps({"retained": 1, "quota": 20000})),
         "ValueError", "read_only: missing"),
        (occupancy_command("not json"), "ValueError", "json_invalid"),
        (occupancy_command(json.dumps({"retained": 1, "quota": 20000, "read_only": True}), 1),
         "RuntimeError", "exited 1"),
        (["/nonexistent/occupancy-command"], "FileNotFoundError", "occupancy-command"),
        # Strict: an integer is not a read-only claim and a string is not a count.
        (occupancy_command(json.dumps({"retained": 1, "quota": 20000, "read_only": 1})),
         "ValueError", "read_only: value_error"),
        (occupancy_command(json.dumps({"retained": "5", "quota": 20000, "read_only": True})),
         "ValueError", "retained: int_type"),
        ([sys.executable, "-c", "pass"], "ValueError", "no observation line"),
    ],
)
async def test_capacity_preflight_fails_closed_without_a_read_only_observation(
    monkeypatch, command, error_type, detail
):
    settings = get_settings()
    monkeypatch.setattr(settings, "native_occupancy_command", command)
    report = await cohort.native_capacity_preflight(settings, 36)
    assert report["status"] == "failed"
    assert "retained" not in report
    assert report["error_type"] == error_type
    assert detail in report["error"] and len(report["error"]) <= cohort.ERROR_CHARS


async def test_capacity_preflight_records_exit_code_and_a_bounded_stderr_tail(monkeypatch):
    settings = get_settings()
    noisy = "import sys; sys.stderr.write('\\x1b[31m' + 'e' * 5000 + 'gateway down'); sys.exit(3)"
    monkeypatch.setattr(settings, "native_occupancy_command", [sys.executable, "-c", noisy])
    monkeypatch.setenv("HARNESS_TEMPORAL_API_KEY", "never-passed-on")
    report = await cohort.native_capacity_preflight(settings, 1)
    assert (report["status"], report["exit_code"]) == ("failed", 3)
    assert report["stderr_tail"].endswith("gateway down")
    assert len(report["stderr_tail"]) <= cohort.ERROR_CHARS
    assert "\x1b" not in report["stderr_tail"]


async def test_capacity_preflight_kills_the_whole_command_group_at_its_bound(monkeypatch):
    import time

    settings = get_settings()
    # A grandchild keeps the pipes open; only a process-group kill ends the wait.
    hang = [sys.executable, "-c",
            "import subprocess, sys, time; subprocess.Popen([sys.executable, '-c', "
            "'import time; time.sleep(60)']); time.sleep(60)"]
    monkeypatch.setattr(settings, "native_occupancy_command", hang)
    monkeypatch.setattr(cohort, "OCCUPANCY_TIMEOUT", 0.5)
    began = time.monotonic()
    report = await cohort.native_capacity_preflight(settings, 1)
    assert time.monotonic() - began < 5
    assert (report["status"], report["error_type"]) == ("failed", "TimeoutError")
    assert report["exit_code"] is None


async def test_capacity_preflight_passes_only_the_non_harness_environment(monkeypatch, tmp_path):
    settings = get_settings()
    probe = ("import json, os; print(json.dumps({'retained': 0, 'quota': 10 ** 6, "
             "'read_only': True, 'observed_at_ms': len([k for k in os.environ "
             "if k.startswith('HARNESS_')])}))")
    monkeypatch.setattr(settings, "native_occupancy_command", [sys.executable, "-c", probe])
    monkeypatch.setenv("HARNESS_TEMPORAL_API_KEY", "never-passed-on")
    report = await cohort.native_capacity_preflight(settings, 1)
    assert report["status"] == "passed" and report["observed_at_ms"] == 0


async def test_capacity_preflight_is_unchecked_only_when_unconfigured(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "native_occupancy_command", [])
    report = await cohort.native_capacity_preflight(settings, 36)
    assert report["status"] == "not_checked"
    assert report["required_headroom"] == 36 * cohort.case_operation_ceiling(settings.limits)
    monkeypatch.setattr(settings, "native_occupancy_command", occupancy_command(
        json.dumps({"retained": 8344, "quota": 20000, "read_only": True, "observed_at_ms": 5})))
    report = await cohort.native_capacity_preflight(settings, 36)
    assert report["status"] == "passed"
    assert (report["retained"], report["quota"], report["headroom"]) == (8344, 20000, 11656)
    assert report["exit_code"] == 0


async def test_saturated_ledger_refuses_the_cohort_before_any_dispatch(tmp_path, monkeypatch):
    finding = Finding(title="case", repo_url="repo")
    monkeypatch.setattr(cohort, "source_identity", lambda: "commit")
    monkeypatch.setattr(
        cohort, "corpus_cases",
        lambda path: [(finding, "inconclusive", "a"), (finding, "inconclusive", "b")],
    )
    settings = get_settings()
    config = tmp_path / "runtime.json"
    config.write_text("{}")
    monkeypatch.setattr(settings, "openshell_config", config)
    required = 2 * cohort.case_operation_ceiling(settings.limits)
    monkeypatch.setattr(settings, "native_occupancy_command", occupancy_command(
        json.dumps({"retained": 20000 - required + 1, "quota": 20000, "read_only": True})))
    connect = AsyncMock(side_effect=AssertionError("the cohort must not connect"))
    monkeypatch.setattr(cohort, "connect", connect)
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    output = tmp_path / "report.json"
    with pytest.raises(ValueError, match="capacity preflight failed"):
        await cohort.evaluate_corpus(manifest, output, settings, owned_worker=True)
    connect.assert_not_awaited()
    persisted = json.loads(output.read_text())
    budget = persisted["native_operation_budget"]
    assert budget["status"] == "failed"
    assert (budget["headroom"], budget["required_headroom"]) == (required - 1, required)
    assert persisted["status"] == "failed"
    assert persisted["gates"]["complete_corpus"] == "failed"
    assert [case["status"] for case in persisted["cases"]] == ["unstarted", "unstarted"]
    # One more claim of headroom starts the cohort (which then meets the unavailable client).
    monkeypatch.setattr(settings, "native_occupancy_command", occupancy_command(
        json.dumps({"retained": 20000 - required, "quota": 20000, "read_only": True})))
    monkeypatch.setattr(cohort, "connect", AsyncMock(side_effect=RuntimeError("unavailable")))
    with pytest.raises(RuntimeError, match="unavailable"):
        await cohort.evaluate_corpus(manifest, tmp_path / "second.json", settings)
    assert json.loads((tmp_path / "second.json").read_text())["native_operation_budget"]["status"] == "passed"
