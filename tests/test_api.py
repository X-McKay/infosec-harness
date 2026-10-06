import json
import os
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from temporalio.api.common.v1 import ActivityType, Payload, Payloads, WorkflowType
from temporalio.api.enums.v1 import EventType, TimeoutType
from temporalio.api.failure.v1 import ApplicationFailureInfo, Failure, TimeoutFailureInfo
from temporalio.api.history import v1 as history_pb
from temporalio.api.history.v1 import HistoryEvent
from temporalio.client import WorkflowExecutionStatus
from temporalio.service import RPCError, RPCStatusCode

from infosec_harness import api
from infosec_harness.config import Settings
from infosec_harness.contracts import Finding, InvestigationResult, Verdict


@pytest.fixture
def client():
    backend = SimpleNamespace(start_workflow=AsyncMock())
    api.app.dependency_overrides[api.temporal] = lambda: backend
    yield backend
    api.app.dependency_overrides.clear()


async def request(method, path, **kwargs):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.app), base_url="http://test"
    ) as client:
        return await client.request(method, path, **kwargs)


async def test_submit_records_native_workflow_and_server_limits(client):
    response = await request(
        "POST", "/api/runs", json={"title": "SQL injection", "repo_url": "https://example.org/repo"}
    )
    assert response.status_code == 202
    args, kwargs = client.start_workflow.call_args
    assert args[0] == "InvestigationWorkflow"
    assert kwargs["task_queue"] == "investigate-v11"
    assert kwargs["id"] == response.json()["id"]
    assert args[1].limits.max_requests == 30
    assert kwargs["execution_timeout"] == timedelta(seconds=args[1].limits.timeout_seconds + 600)
    invalid = await request(
        "POST",
        "/api/runs",
        json={"title": "a", "repo_url": "repo", "limits": {"max_requests": 9999}},
    )
    assert invalid.status_code == 422
    assert client.start_workflow.await_count == 1


async def test_terminal_cancellation_never_rewrites_completed_outcome(client):
    handle = SimpleNamespace(
        describe=AsyncMock(return_value=SimpleNamespace(status=WorkflowExecutionStatus.COMPLETED)),
        cancel=AsyncMock(),
    )
    client.get_workflow_handle = lambda *args, **kwargs: handle
    response = await request("POST", "/api/runs/investigate-v11-test/cancel")
    assert response.json()["status"] == "completed"
    handle.cancel.assert_not_awaited()
    handle.describe.return_value.status = WorkflowExecutionStatus.RUNNING
    response = await request("POST", "/api/runs/investigate-v11-test/cancel")
    assert response.json()["status"] == "cancellation_requested"
    handle.cancel.assert_awaited_once()


async def test_completed_result_comes_from_temporal_not_a_shadow_database(client):
    finding = Finding(title="Finding", repo_url="repo")
    result = InvestigationResult(
        finding=finding,
        verdict=Verdict(label="inconclusive", summary="No execution"),
        evidence=[],
        source_digest="abc",
        model="fixture",
    )
    description = SimpleNamespace(
        status=WorkflowExecutionStatus.COMPLETED,
        memo=AsyncMock(return_value={"finding": finding.model_dump()}),
    )
    handle = SimpleNamespace(
        describe=AsyncMock(return_value=description), result=AsyncMock(return_value=result)
    )
    client.get_workflow_handle = lambda *args, **kwargs: handle
    response = await request("GET", "/api/runs/investigate-v11-test")
    assert response.status_code == 200
    assert response.json()["result"]["verdict"]["label"] == "inconclusive"
    assert (await request("GET", "/api/runs/old-batch")).status_code == 404


@pytest.mark.parametrize(
    ("status", "code", "detail"),
    [
        (RPCStatusCode.NOT_FOUND, 404, "Investigation not found"),
        (RPCStatusCode.INVALID_ARGUMENT, 400, "Temporal rejected the request as invalid"),
        (
            RPCStatusCode.DEADLINE_EXCEEDED,
            504,
            "No worker answered within 10s: is `harness worker` serving task queue "
            "investigate-v11?",
        ),
        (RPCStatusCode.UNAVAILABLE, 503, "Workflow service unavailable (UNAVAILABLE)"),
        (RPCStatusCode.PERMISSION_DENIED, 503, "Workflow service unavailable (PERMISSION_DENIED)"),
    ],
)
async def test_temporal_rpc_failures_map_to_operator_errors(client, caplog, status, code, detail):
    failure = RPCError("payload: attacker text", status, b"")
    handle = SimpleNamespace(describe=AsyncMock(side_effect=failure))
    client.get_workflow_handle = lambda *args, **kwargs: handle
    with caplog.at_level("WARNING", logger="infosec_harness.api"):
        response = await request("GET", "/api/runs/investigate-v11-test")
    assert response.status_code == code
    assert response.json() == {"detail": detail}
    assert "attacker" not in response.text
    [record] = [item for item in caplog.records if item.name == "infosec_harness.api"]
    assert record.getMessage() == (
        f"event=temporal_rpc_failed status={status.name} http_status={code} "
        "path=/api/runs/investigate-v11-test"
    )


async def test_pagination_bounded_and_invalid_token_never_reaches_temporal(client):
    row = SimpleNamespace(
        id="investigate-v11-test",
        status=WorkflowExecutionStatus.RUNNING,
        start_time=datetime.now(UTC),
        close_time=None,
        memo=AsyncMock(return_value={"finding": {"title": "A"}}),
    )
    page = SimpleNamespace(fetch_next_page=AsyncMock(), current_page=[row], next_page_token=b"next")
    called = []

    def listing(*args, **kwargs):
        called.append(kwargs)
        return page

    client.list_workflows = listing
    response = await request("GET", "/api/runs")
    assert response.json()["next_page_token"] == "bmV4dA=="
    assert called[0]["page_size"] == 50
    assert (await request("GET", "/api/runs?page_token=!!!")).status_code == 400
    assert len(called) == 1


async def test_health_is_temporal_connectivity_only(client):
    client.workflow_service = SimpleNamespace(get_system_info=AsyncMock())
    response = await request("GET", "/api/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "control_plane_ready",
        "temporal": True,
        "runtime": "not_checked",
        "generation": "v11",
        "task_queue": "investigate-v11",
    }
    client.workflow_service.get_system_info.side_effect = RPCError(
        "connection refused", RPCStatusCode.UNAVAILABLE, b""
    )
    response = await request("GET", "/api/health")
    assert response.status_code == 503
    assert response.json()["temporal"] is False
    assert response.json()["status"] == "temporal_unavailable"


def history_event(event_id, event_type, **attributes):
    event = HistoryEvent(event_id=event_id, event_type=event_type, **attributes)
    event.event_time.FromDatetime(datetime(2026, 10, 6, 12, 0, event_id % 60, tzinfo=UTC))
    return event


def json_payloads(value):
    return Payloads(
        payloads=[Payload(metadata={"encoding": b"json/plain"}, data=json.dumps(value).encode())]
    )


def events_handle(client, events):
    async def history(**kwargs):
        assert kwargs["rpc_timeout"] == api.RPC_TIMEOUT
        for event in events:
            yield event

    handles = []

    def handle(workflow_id, **kwargs):
        handles.append(workflow_id)
        return SimpleNamespace(fetch_history_events=history)

    client.get_workflow_handle = handle
    return handles


async def test_run_events_project_kinds_without_payloads(client):
    secret = "attacker stdout: rm -rf / " * 20
    failure = Failure(
        message=secret,
        application_failure_info=ApplicationFailureInfo(type="UnknownExecutionError"),
    )
    events = [
        history_event(
            1,
            EventType.EVENT_TYPE_WORKFLOW_EXECUTION_STARTED,
            workflow_execution_started_event_attributes=history_pb.WorkflowExecutionStartedEventAttributes(
                workflow_type=WorkflowType(name="InvestigationWorkflow"),
                input=json_payloads({"finding": secret}),
            ),
        ),
        history_event(2, EventType.EVENT_TYPE_WORKFLOW_TASK_COMPLETED),
        history_event(
            5,
            EventType.EVENT_TYPE_ACTIVITY_TASK_SCHEDULED,
            activity_task_scheduled_event_attributes=history_pb.ActivityTaskScheduledEventAttributes(
                activity_type=ActivityType(name="agent__investigator__call_tool")
            ),
        ),
        history_event(
            6,
            EventType.EVENT_TYPE_ACTIVITY_TASK_STARTED,
            activity_task_started_event_attributes=history_pb.ActivityTaskStartedEventAttributes(
                scheduled_event_id=5, attempt=2
            ),
        ),
        history_event(
            7,
            EventType.EVENT_TYPE_ACTIVITY_TASK_COMPLETED,
            activity_task_completed_event_attributes=history_pb.ActivityTaskCompletedEventAttributes(
                scheduled_event_id=5,
                result=json_payloads(
                    {"kind": "tool_return", "result": {"exit_code": 137, "stdout": secret}}
                ),
            ),
        ),
        history_event(
            8,
            EventType.EVENT_TYPE_ACTIVITY_TASK_SCHEDULED,
            activity_task_scheduled_event_attributes=history_pb.ActivityTaskScheduledEventAttributes(
                activity_type=ActivityType(name="prepare_investigation")
            ),
        ),
        history_event(
            9,
            EventType.EVENT_TYPE_ACTIVITY_TASK_FAILED,
            activity_task_failed_event_attributes=history_pb.ActivityTaskFailedEventAttributes(
                scheduled_event_id=8, failure=failure
            ),
        ),
        history_event(
            10,
            EventType.EVENT_TYPE_ACTIVITY_TASK_TIMED_OUT,
            activity_task_timed_out_event_attributes=history_pb.ActivityTaskTimedOutEventAttributes(
                scheduled_event_id=8,
                failure=Failure(
                    timeout_failure_info=TimeoutFailureInfo(
                        timeout_type=TimeoutType.TIMEOUT_TYPE_START_TO_CLOSE
                    )
                ),
            ),
        ),
        history_event(11, EventType.EVENT_TYPE_TIMER_FIRED),
        history_event(
            12,
            EventType.EVENT_TYPE_WORKFLOW_EXECUTION_FAILED,
            workflow_execution_failed_event_attributes=history_pb.WorkflowExecutionFailedEventAttributes(
                failure=failure
            ),
        ),
        history_event(13, EventType.EVENT_TYPE_WORKFLOW_EXECUTION_CANCELED),
        history_event(14, EventType.EVENT_TYPE_WORKFLOW_EXECUTION_COMPLETED),
    ]
    events_handle(client, events)
    response = await request("GET", "/api/runs/investigate-v11-test/events")
    assert response.status_code == 200
    body = response.json()
    assert body["run_id"] == "investigate-v11-test" and body["truncated"] is False
    projected = [(event["kind"], event["name"], event["detail"]) for event in body["events"]]
    assert projected == [
        ("workflow_started", "InvestigationWorkflow", ""),
        ("other", None, "workflow_task_completed"),
        ("activity_scheduled", "agent__investigator__call_tool", ""),
        ("other", "agent__investigator__call_tool", "activity_task_started attempt=2"),
        ("activity_completed", "agent__investigator__call_tool", "exit_code=137"),
        ("activity_scheduled", "prepare_investigation", ""),
        ("activity_failed", "prepare_investigation", "UnknownExecutionError"),
        ("activity_timed_out", "prepare_investigation", "start_to_close"),
        ("timer", None, "fired"),
        ("workflow_failed", None, "UnknownExecutionError"),
        ("workflow_cancelled", None, ""),
        ("workflow_completed", None, ""),
    ]
    assert body["events"][0]["at"] == "2026-10-06T12:00:01+00:00"
    # Payloads and failure messages are untrusted and never projected.
    assert "attacker" not in response.text


@pytest.mark.parametrize(
    ("document", "label"),
    [
        ({"kind": "tool_return", "result": {"exit_code": 0}}, "exit_code=0"),
        ({"kind": "tool_return", "result": {"exit_code": -9}}, "exit_code=-9"),
        # A refused command has no exit code; probe observations never supply one.
        (
            {"kind": "tool_return", "result": {"exit_code": None, "observations": {"exit_code": 0}}},
            "",
        ),
        ({"kind": "tool_return", "result": {"exit_code": True}}, ""),
        ({"kind": "tool_return", "result": {"exit_code": "1"}}, ""),
        ({"kind": "tool_return", "result": "text"}, ""),
        ({"kind": "model_retry", "result": {"exit_code": 1}}, ""),
        ({"exit_code": 1}, ""),
        ({"return_value": {"exit_code": 1}}, ""),
        ([{"exit_code": 1}], ""),
    ],
)
def test_exit_code_label_is_read_from_one_fixed_location(document, label):
    assert api.exit_code(json_payloads(document)) == label


async def test_exit_code_location_matches_the_recorded_tool_return():
    # Pins the wire shape: PydanticAI's own wrapper and converter, not a hand-written payload.
    from pydantic_ai.durable_exec._toolset import wrap_tool_call_result
    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from temporalio.converter import DataConverter

    from infosec_harness.contracts import Evidence

    async def tool():
        return Evidence(
            id="execute:1:a", kind="command", command="c", exit_code=137,
            sandbox_id="s", source_digest="d", observations={"exit_code": 0},
        )

    converter = PydanticAIPlugin().configure_client({"data_converter": DataConverter.default})
    encoded = await converter["data_converter"].encode([await wrap_tool_call_result(tool())])
    assert api.exit_code(Payloads(payloads=encoded)) == "exit_code=137"


async def test_run_events_are_capped_and_run_id_is_validated(client):
    events = [
        history_event(index, EventType.EVENT_TYPE_WORKFLOW_TASK_SCHEDULED)
        for index in range(1, 601)
    ]
    handles = events_handle(client, events)
    body = (await request("GET", "/api/runs/investigate-v11-test/events")).json()
    assert len(body["events"]) == api.MAX_EVENTS == 500
    assert body["truncated"] is True
    events_handle(client, events[:500])
    body = (await request("GET", "/api/runs/investigate-v11-test/events")).json()
    assert len(body["events"]) == 500 and body["truncated"] is False
    assert (await request("GET", "/api/runs/old-batch/events")).status_code == 404
    assert (await request("GET", f"/api/runs/{api.PREFIX}{'a' * 100}/events")).status_code == 404
    assert handles == ["investigate-v11-test"]


async def test_run_summaries_carry_verdicts_and_survive_a_failed_result(client):
    finding = Finding(title="SQLi", repo_url="https://example.org/repo", cwe="CWE-89")
    result = InvestigationResult(
        finding=finding,
        verdict=Verdict(label="likely_not_exploitable", summary="Parameterized"),
        evidence=[],
        source_digest="abc",
        model="fixture",
    )

    def row(run_id, status):
        return SimpleNamespace(
            id=run_id,
            run_id=f"{run_id}-run",
            status=status,
            start_time=datetime.now(UTC),
            close_time=None if status == WorkflowExecutionStatus.RUNNING else datetime.now(UTC),
            memo=AsyncMock(return_value={"finding": finding.model_dump(mode="json")}),
        )

    rows = [
        row("investigate-v11-good", WorkflowExecutionStatus.COMPLETED),
        row("investigate-v11-broken", WorkflowExecutionStatus.COMPLETED),
        row("investigate-v11-running", WorkflowExecutionStatus.RUNNING),
    ]
    rows.append(
        SimpleNamespace(
            id="investigate-v11-legacy",
            status=WorkflowExecutionStatus.FAILED,
            start_time=datetime.now(UTC),
            close_time=datetime.now(UTC),
            memo=AsyncMock(return_value={"finding": {"title": "Legacy", "cwe": "not-a-cwe"}}),
        )
    )
    client.list_workflows = lambda *args, **kwargs: SimpleNamespace(
        fetch_next_page=AsyncMock(), current_page=rows, next_page_token=None
    )
    fetched = []

    def handle(workflow_id, **kwargs):
        fetched.append((workflow_id, kwargs["run_id"]))
        failing = RPCError("deadline exceeded", RPCStatusCode.DEADLINE_EXCEEDED, b"")
        broken = workflow_id.endswith("broken")
        return SimpleNamespace(
            result=AsyncMock(return_value=result, side_effect=failing if broken else None)
        )

    client.get_workflow_handle = handle
    response = await request("GET", "/api/runs")
    assert response.status_code == 200
    items = {item["id"]: item for item in response.json()["items"]}
    assert items["investigate-v11-good"]["verdict"] == "likely_not_exploitable"
    assert items["investigate-v11-good"]["cwe"] == "CWE-89"
    assert items["investigate-v11-good"]["repo_url"] == "https://example.org/repo"
    assert items["investigate-v11-broken"]["verdict"] is None
    assert items["investigate-v11-running"]["verdict"] is None
    assert items["investigate-v11-legacy"]["title"] == "Legacy"
    assert items["investigate-v11-legacy"]["cwe"] is None
    # Only completed runs are fetched, each pinned to its listed run.
    assert sorted(fetched) == [
        ("investigate-v11-broken", "investigate-v11-broken-run"),
        ("investigate-v11-good", "investigate-v11-good-run"),
    ]


async def test_slow_verdicts_are_bounded(client, monkeypatch):
    import asyncio

    monkeypatch.setattr(api, "VERDICT_DEADLINE_SECONDS", 0.05)
    running = 0
    peak = 0

    async def slow(**kwargs):
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        try:
            await asyncio.sleep(30)
        finally:
            running -= 1

    rows = [
        SimpleNamespace(
            id=f"investigate-v11-{index}",
            status=WorkflowExecutionStatus.COMPLETED,
            start_time=datetime.now(UTC),
            close_time=datetime.now(UTC),
            memo=AsyncMock(return_value={}),
        )
        for index in range(20)
    ]
    client.list_workflows = lambda *args, **kwargs: SimpleNamespace(
        fetch_next_page=AsyncMock(), current_page=rows, next_page_token=None
    )
    client.get_workflow_handle = lambda *args, **kwargs: SimpleNamespace(result=slow)
    response = await request("GET", "/api/runs")
    assert response.status_code == 200
    assert all(item["verdict"] is None for item in response.json()["items"])
    assert peak == api.VERDICT_CONCURRENCY and running == 0


@pytest.fixture
def reports_dir(tmp_path, monkeypatch):
    root = tmp_path / "reports"
    root.mkdir()
    monkeypatch.setattr(api, "get_settings", lambda: Settings(reports_dir=root))
    return root


def write_report(path, value, mtime):
    path.write_text(value if isinstance(value, str) else json.dumps(value))
    os.utime(path, (mtime, mtime))


async def test_reports_listing_is_defensive_and_newest_first(reports_dir, tmp_path):
    model = {
        "version": 1,
        "kind": "cohort",
        "commit": "0" * 40,
        "model": "fixture-model",
        "started_at": "2026-10-05T00:00:00+00:00",
        "finished_at": "2026-10-05T01:00:00+00:00",
        "status": "failed",
        "gates": {"complete_corpus": "passed", "task_success_rate": "failed", "bad": 3},
        "planned": 30,
        "completed": 30,
        "task_success_rate": 0.8,
        "unsafe_negatives": 0,
        "cases": [{"name": "case", "stdout": "untrusted"}],
    }
    write_report(reports_dir / "model-20261005T000000Z.json", model, 3_000)
    write_report(reports_dir / "openshell-20261004T000000Z.json", "{not json", 2_000)
    write_report(reports_dir / "replay-x.json", "[1, 2]", 1_000)
    write_report(reports_dir / "notes-nan.json", '{"status": NaN}', 500)
    write_report(
        reports_dir / "diagnostic-shape.json",
        {"status": ["odd"], "planned": True, "task_success_rate": "high", "gates": []},
        400,
    )
    write_report(reports_dir / ".hidden.json", {}, 9_000)
    write_report(reports_dir / "notes.txt", {}, 9_000)
    (reports_dir / "nested.json").mkdir()
    outside = tmp_path / "secret.json"
    outside.write_text('{"secret": true}')
    (reports_dir / "link.json").symlink_to(outside)

    response = await request("GET", "/api/reports")
    assert response.status_code == 200
    body = response.json()
    assert body["truncated"] is False
    items = body["items"]
    assert [item["name"] for item in items] == [
        "model-20261005T000000Z.json",
        "openshell-20261004T000000Z.json",
        "replay-x.json",
        "notes-nan.json",
        "diagnostic-shape.json",
    ]
    first = items[0]
    assert first["kind"] == "model"
    assert first["status"] == "failed"
    assert first["planned"] == 30 and first["completed"] == 30
    assert first["task_success_rate"] == 0.8 and first["unsafe_negatives"] == 0
    assert first["gates"] == {"complete_corpus": "passed", "task_success_rate": "failed"}
    assert first["bytes"] == (reports_dir / "model-20261005T000000Z.json").stat().st_size
    assert [item["status"] for item in items[1:4]] == ["unreadable"] * 3
    assert [item["kind"] for item in items[1:]] == ["openshell", "replay", "unknown", "diagnostic"]
    odd = items[4]
    assert odd["status"] is None and odd["planned"] is None
    assert odd["task_success_rate"] is None and odd["gates"] == {}
    assert "untrusted" not in response.text and "secret" not in response.text


async def test_report_document_is_confined_to_reports_dir(reports_dir, tmp_path):
    write_report(reports_dir / "model-a.json", {"status": "passed", "cases": []}, 1_000)
    write_report(reports_dir / "replay-list.json", "[1]", 1_000)
    outside = tmp_path / "secret.json"
    outside.write_text('{"secret": true}')
    (reports_dir / "link.json").symlink_to(outside)
    # Served exactly as listed: an in-root symlink and a directory are not reports either.
    (reports_dir / "alias.json").symlink_to(reports_dir / "model-a.json")
    (reports_dir / "nested.json").mkdir()
    response = await request("GET", "/api/reports/model-a.json")
    assert response.status_code == 200
    assert response.json() == {"status": "passed", "cases": []}
    listed = [item["name"] for item in (await request("GET", "/api/reports")).json()["items"]]
    assert sorted(listed) == ["model-a.json", "replay-list.json"]
    for name in (
        "link.json",
        "alias.json",
        "nested.json",
        "..%2Fsecret.json",
        "%2E%2E%2Fsecret.json",
        "..secret.json",
        ".hidden.json",
        "missing.json",
        "model-a.txt",
        "model-a.json%00.txt",
    ):
        response = await request("GET", f"/api/reports/{name}")
        assert response.status_code == 404, name
        assert "secret" not in response.text
    assert (await request("GET", "/api/reports/replay-list.json")).status_code == 422


async def test_report_size_is_bounded(reports_dir, monkeypatch):
    monkeypatch.setattr(api, "MAX_REPORT_BYTES", 64)
    write_report(reports_dir / "model-big.json", {"padding": "x" * 100}, 2_000)
    write_report(reports_dir / "model-small.json", {"status": "passed"}, 1_000)
    assert (await request("GET", "/api/reports/model-big.json")).status_code == 413
    assert (await request("GET", "/api/reports/model-small.json")).status_code == 200
    items = (await request("GET", "/api/reports")).json()["items"]
    assert [(item["name"], item["status"]) for item in items] == [
        ("model-big.json", "too_large"),
        ("model-small.json", "passed"),
    ]


async def test_report_listing_is_capped_and_survives_a_missing_directory(
    reports_dir, monkeypatch
):
    monkeypatch.setattr(api, "MAX_REPORTS", 3)
    monkeypatch.setattr(api, "REPORT_LISTING_BUDGET", 40)
    for index in range(5):
        write_report(reports_dir / f"model-{index}.json", {"status": "passed"}, 1_000 + index)
    body = (await request("GET", "/api/reports")).json()
    assert body["truncated"] is True
    assert [item["name"] for item in body["items"]] == [
        "model-4.json",
        "model-3.json",
        "model-2.json",
    ]
    # Listing parse work is bounded: files beyond the byte budget are not summarized.
    assert [item["status"] for item in body["items"]] == ["passed", "passed", "not_summarized"]
    monkeypatch.setattr(api, "get_settings", lambda: Settings(reports_dir=reports_dir / "none"))
    assert (await request("GET", "/api/reports")).json() == {"items": [], "truncated": False}


async def test_unreadable_reports_dir_is_logged_not_silent(tmp_path, monkeypatch, caplog):
    not_a_directory = tmp_path / "reports"
    not_a_directory.write_text("")
    monkeypatch.setattr(api, "get_settings", lambda: Settings(reports_dir=not_a_directory))
    with caplog.at_level("WARNING", logger="infosec_harness.api"):
        response = await request("GET", "/api/reports")
    assert response.json() == {"items": [], "truncated": False}
    [record] = [item for item in caplog.records if item.name == "infosec_harness.api"]
    assert record.levelname == "WARNING"
    assert record.getMessage().startswith(
        f"event=reports_dir_unreadable path={not_a_directory.resolve()} error="
    )


@pytest.mark.requires_temporal
async def test_real_temporal_submit_query_and_cancellation(temporal_cli, tmp_path):
    import asyncio

    from fakes import FakeOpenShell
    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from pydantic_ai.models.function import FunctionModel
    from temporalio.client import WorkflowFailureError
    from temporalio.testing import WorkflowEnvironment
    from temporalio.worker import Worker

    from infosec_harness.agents.investigator import build_agent
    from infosec_harness.workflows.investigation import (
        InvestigationActivities,
        InvestigationWorkflow,
        bind_investigator,
    )
    from infosec_harness.workflows.worker import workflow_runner

    entered = asyncio.Event()
    shell = FakeOpenShell()

    async def model(messages, info):
        entered.set()
        await asyncio.Event().wait()

    async def snapshot(finding, run_id):
        return SimpleNamespace(path=str(tmp_path), digest="fixture")

    bind_investigator(build_agent(shell, FunctionModel(model)))
    activities = InvestigationActivities(shell, snapshot, "fixture")
    async with await WorkflowEnvironment.start_local(
        dev_server_existing_path=temporal_cli, plugins=[PydanticAIPlugin()]
    ) as env:
        api.app.dependency_overrides[api.temporal] = lambda: env.client
        try:
            async with Worker(
                env.client,
                task_queue=api.get_settings().task_queue,
                workflows=[InvestigationWorkflow],
                activities=[activities.prepare, activities.finalize, activities.cleanup],
                workflow_runner=workflow_runner(),
            ):
                started = await request(
                    "POST",
                    "/api/runs",
                    json={"title": "Native HTTP finding", "repo_url": "fixture"},
                )
                assert started.status_code == 202
                run_id = started.json()["id"]
                await asyncio.wait_for(entered.wait(), 30)
                progress = await request("GET", f"/api/runs/{run_id}")
                assert progress.status_code == 200
                assert progress.json()["status"] == "running"
                assert progress.json()["phase"] == "investigating"
                assert progress.json()["finding"]["title"] == "Native HTTP finding"
                cancelled = await request("POST", f"/api/runs/{run_id}/cancel")
                assert cancelled.json()["status"] == "cancellation_requested"
                with pytest.raises(WorkflowFailureError):
                    await asyncio.wait_for(env.client.get_workflow_handle(run_id).result(), 30)
                final = await request("GET", f"/api/runs/{run_id}")
                assert final.json()["status"] == "cancelled"
                assert shell.closed == [run_id]
                history = (await request("GET", f"/api/runs/{run_id}/events")).json()
                kinds = [event["kind"] for event in history["events"]]
                assert kinds[0] == "workflow_started" and kinds[-1] == "workflow_cancelled"
                assert {
                    "name": "prepare_investigation",
                    "kind": "activity_completed",
                } in [
                    {"name": event["name"], "kind": event["kind"]}
                    for event in history["events"]
                ]
                assert history["truncated"] is False
        finally:
            api.app.dependency_overrides.clear()


@pytest.mark.requires_temporal
async def test_queued_run_has_server_deadline_without_a_worker(temporal_cli, monkeypatch):
    import asyncio

    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from temporalio.client import WorkflowFailureError
    from temporalio.testing import WorkflowEnvironment

    monkeypatch.setattr(api, "execution_timeout", lambda limits: timedelta(seconds=1))
    async with await WorkflowEnvironment.start_local(
        dev_server_existing_path=temporal_cli, plugins=[PydanticAIPlugin()]
    ) as env:
        api.app.dependency_overrides[api.temporal] = lambda: env.client
        try:
            submitted = await request(
                "POST", "/api/runs", json={"title": "Queued", "repo_url": "fixture"}
            )
            run_id = submitted.json()["id"]
            handle = env.client.get_workflow_handle(run_id)
            with pytest.raises(WorkflowFailureError):
                await asyncio.wait_for(handle.result(), 10)
            assert (await handle.describe()).status == WorkflowExecutionStatus.TIMED_OUT
            state = (await request("GET", f"/api/runs/{run_id}")).json()
            assert state["status"] == "failed"
            assert state["error"] == "timed_out"
        finally:
            api.app.dependency_overrides.clear()
