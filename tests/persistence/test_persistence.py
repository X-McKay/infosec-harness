from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from infosec_harness.domain.models import (
    AgentOutcome,
    Finding,
    FindingInput,
    PriorityBand,
    TriageResult,
    TriageRunOutput,
    Verdict,
    VerdictLabel,
)
from infosec_harness.persistence import budgets, db, lifecycle, store
from infosec_harness.persistence.run_telemetry import RunTelemetry


def _input(title: str) -> FindingInput:
    return FindingInput(title=title, repo_url="/r", cwe="CWE-89")


def _output(title="t1", label=VerdictLabel.potentially_exploitable):
    finding = Finding.from_input(_input(title))
    verdict = Verdict(label=label, confidence=0.8, rationale="r")
    result = TriageResult(fingerprint=finding.fingerprint, verdict=verdict, priority_score=0.5,
                          priority=PriorityBand.p2)
    inv = AgentOutcome(output=None, agent="verdict", model_name="stub", config_hash="abc",
                       input_tokens=100, output_tokens=20, cache_read_tokens=40, cost_usd=0.01,
                       requests=7, repeated_tool_calls={"read_file({'path': 'app.py'})": 3})
    return TriageRunOutput(finding=finding, result=result, prepared_status="ready", invocations=[inv])


async def _accept(batch_id: str, *titles: str) -> None:
    await db.create_all()
    await lifecycle.accept_batch(batch_id, [_input(t) for t in titles], "test", None,
                                 agent_config_digests={})


async def test_save_and_query_run():
    await _accept("b1", "t1")
    run_id = await store.save_run_output("b1", _output())
    rows = await store.list_runs(batch_id="b1")
    assert len(rows) == 1 and rows[0]["verdict"] == "potentially_exploitable"
    detail = await store.get_run(run_id)
    # No ledger operation accounted the call, so the cost is known only as a lower bound.
    assert detail["cost_usd"] is None
    assert detail["telemetry"]["known_cost_usd"] == pytest.approx(0.01)
    assert detail["invocations"][0]["agent"] == "verdict"
    assert detail["cache_read_tokens"] == 40
    # Request accounting survives the round trip, so a request_limit breach stays
    # diagnosable from the stored run rather than needing a live re-run.
    assert detail["invocations"][0]["requests"] == 7
    assert detail["invocations"][0]["repeated_tool_calls"] == {"read_file({'path': 'app.py'})": 3}
    assert detail["evidence"]["manifest"]["schema_version"] == 3
    assert len(detail["evidence"]["manifest"]["harness"]["packaged_source_sha256"]) == 64


async def test_persisted_execution_carries_its_origins():
    """Regression: executions were persisted without the origin of each part of their record,
    which existed only inside the encoded log artifact, so no reader could tell a controller
    observation from a marker the probe printed."""
    from infosec_harness.domain.models import ExecutionOrigins, ProbeExecution
    from infosec_harness.sandbox import evidence

    record = evidence.execution_record(
        image_tag="image", test_file_path="tests/test_probe.py", test_command="pytest",
        content="probe", nonce="n", attempt=1, exit_code=0, timed_out=False, duration_s=1.5,
        oracle_fired=True, precondition_reached=True, sink_returned=True, no_tests=None)
    out = _output(title="origins")
    out.executions = [ProbeExecution(
        attempt=1, exit_code=0, oracle_fired=True, precondition_reached=True,
        sink_returned=True,
        origins=ExecutionOrigins.model_validate({k: record[k] for k in ("process", "observations",
                                                                        "runner")}))]
    await _accept("origins", "origins")
    detail = await store.get_run(await store.save_run_output("origins", out))
    [execution] = detail["evidence"]["executions"]
    assert execution["origins"]["process"]["origin"] == "controller"
    assert execution["origins"]["observations"]["origin"] == "self_reported_marker"
    assert execution["origins"]["runner"]["origin"] == "parsed_untrusted_output"
    assert execution["origins"]["process"]["exit_code"] == 0


async def test_review_roundtrip():
    await _accept("b2", "t2")
    run_id = await store.save_run_output("b2", _output(title="t2"))
    assert await store.save_review(run_id, reviewer="alice", decision="override",
                                   override_label="likely_not_exploitable", reason="fp")
    detail = await store.get_run(run_id)
    assert detail["review"]["decision"] == "override"
    assert detail["review"]["override_label"] == "likely_not_exploitable"


async def test_save_is_idempotent():
    await _accept("b3", "t3")
    await store.save_run_output("b3", _output(title="t3"))
    await store.save_run_output("b3", _output(title="t3"))  # re-run, same fingerprint
    rows = await store.list_runs(batch_id="b3")
    assert len(rows) == 1
    assert len((await store.get_run(rows[0]["id"]))["invocations"]) == 1


async def test_output_of_a_run_that_was_never_accepted_is_refused():
    """Regression: saving an unaccepted run created its row, with no population and no ledger,
    so its usage was stored as if it had been accounted."""
    await _accept("accepted-batch", "accepted")
    with pytest.raises(store.MissingDurableRecord):
        await store.save_run_output("accepted-batch", _output(title="not accepted"))
    with pytest.raises(store.MissingDurableRecord):
        await store.save_run_output("no-such-batch", _output(title="accepted"))


async def test_output_without_a_budget_ledger_is_refused():
    await _accept("ledger-removed", "orphan")
    async with db.session() as session:
        await session.delete(await session.get(db.BudgetLedger, "ledger-removed"))
        await session.commit()
    with pytest.raises(store.MissingDurableRecord, match="budget ledger"):
        await store.save_run_output("ledger-removed", _output(title="orphan"))


async def test_unknown_cost_is_not_exposed_as_zero():
    await _accept("unknown-cost", "unknown-cost")
    output = _output(title="unknown-cost")
    output.invocations[0].cost_usd = None
    run_id = await store.save_run_output("unknown-cost", output)
    detail = await store.get_run(run_id)
    assert detail["cost_usd"] is None
    assert detail["telemetry"]["cost_usd"] is None
    assert detail["telemetry"]["cost_coverage"] == 0


async def test_late_output_cannot_overwrite_cancelled_result_data():
    await _accept("late-output", "late-output")
    out = _output(title="late-output")
    run_id = await store.save_run_output("late-output", out)
    before = await store.get_run(run_id)
    async with db.session() as session:
        run = await session.get(db.TriageRun, run_id)
        run.status = "cancelled"
        await session.commit()
    late = _output(title="late-output", label=VerdictLabel.likely_not_exploitable)
    late.manifest = {"late": True}
    late.invocations[0].agent = "late-verdict"
    late.invocations[0].config_hash = "late"
    await store.save_run_output("late-output", late)
    detail = await store.get_run(run_id)
    assert detail["status"] == "cancelled"
    assert detail["phase"] == "cancelled"
    assert detail["verdict"] == before["verdict"]
    assert detail["evidence"] == before["evidence"]
    assert detail["invocations"] == before["invocations"]


async def test_zero_priced_uncertain_attempts_keep_cost_zero_and_tokens_unknown():
    await _accept("free-retries", "free-retry")
    out = _output(title="free-retry")
    out.invocations[0].cost_usd = 0.0
    async with db.session() as session:
        ledger = await session.get(db.BudgetLedger, "free-retries")
        state = dict(ledger.state)
        state["operations"] = {"triage:free-retry:call": {
            "kind": "agent", "fingerprint": out.finding.fingerprint, "status": "uncertain",
            "reserved": {"tokens": 500, "requests": 10, "cost_usd": 0},
            "record": {"pricing_status": "known_zero"}}}
        ledger.state = state
        await session.commit()
    detail = await store.get_run(await store.save_run_output("free-retries", out))
    assert detail["telemetry"]["cost_usd"] == 0
    assert detail["telemetry"]["cost_accounting_complete"] is True
    assert detail["telemetry"]["total_tokens"] is None
    assert detail["telemetry"]["accounting_complete"] is False


def _usage(out: TriageRunOutput, operations: list[dict]) -> dict:
    now = datetime.now(UTC)
    return RunTelemetry.accepted("demo", now).with_usage(out.invocations, operations, now).stored()


def test_uncertain_execution_does_not_erase_exact_zero_provider_usage():
    out = _output(title="resource-separated")
    invocation = out.invocations[0]
    invocation.input_tokens = 0
    invocation.output_tokens = 0
    invocation.cost_usd = 0.0
    fingerprint = out.finding.fingerprint
    state = {"operations": {
        "triage:resource-separated:0:verdict": {
            "kind": "agent", "fingerprint": fingerprint, "status": "settled",
            "record": {"pricing_status": "known_zero"},
        },
        "triage:resource-separated:1:probe": {
            "kind": "execution", "fingerprint": fingerprint, "status": "uncertain",
        },
    }}

    telemetry = _usage(out, store.agent_operations(state, fingerprint))

    assert telemetry["accounting_complete"] is True
    assert telemetry["cost_accounting_complete"] is True
    assert telemetry["total_tokens"] == 0
    assert telemetry["cost_usd"] == 0


@pytest.mark.parametrize(("pricing_status", "expected_cost"), [(None, None), ("known_zero", 0)])
def test_uncertain_agent_usage_keeps_cost_unknown_unless_pricing_is_zero(
    pricing_status, expected_cost,
):
    out = _output(title="uncertain-agent")
    out.invocations[0].cost_usd = 0.0
    operations = [{"kind": "agent", "fingerprint": out.finding.fingerprint, "status": "uncertain",
                   "record": {"pricing_status": pricing_status}}]

    telemetry = _usage(out, operations)

    assert telemetry["accounting_complete"] is False
    assert telemetry["total_tokens"] is None
    assert telemetry["cost_usd"] == expected_cost


def test_calls_without_ledger_operations_are_not_complete_accounting():
    """Regression: ``all([])`` made a run whose calls had no ledger operation at all report
    complete accounting and exact totals. Only matching, settled operations do."""
    out = _output(title="unaccounted")
    telemetry = _usage(out, [])
    assert telemetry["accounting_complete"] is False
    assert telemetry["cost_accounting_complete"] is False
    assert telemetry["total_tokens"] is None and telemetry["cost_usd"] is None
    assert telemetry["known_tokens"] == 120
    settled = {"kind": "agent", "fingerprint": out.finding.fingerprint, "status": "settled"}
    assert _usage(out, [settled, settled])["accounting_complete"] is False
    assert _usage(out, [settled])["accounting_complete"] is True
    no_calls = out.model_copy(update={"invocations": []})
    assert _usage(no_calls, [])["accounting_complete"] is True
    assert _usage(no_calls, [])["total_tokens"] is None


def test_operations_are_attributed_by_their_recorded_fingerprint_not_their_identifier():
    """Regression: attribution used to test whether the fingerprint was a *substring* of the
    operation id, so one finding inherited another's uncertain operation whenever its
    fingerprint occurred inside that id. Only the explicit field attributes an operation."""
    out = _output(title="abc")
    fingerprint = out.finding.fingerprint
    state = {"operations": {
        # Another finding's uncertain operation whose identifier contains this fingerprint.
        f"triage:{fingerprint}def:0:verdict": {"kind": "agent", "fingerprint": fingerprint + "def",
                                               "status": "uncertain", "record": {}},
        # This finding's own operation, under an identifier that does not mention it.
        "prep:batch:0:recon": {"kind": "agent", "fingerprint": fingerprint, "status": "settled",
                               "record": {}},
    }}

    telemetry = _usage(out, store.agent_operations(state, fingerprint))

    assert telemetry["accounting_complete"] is True
    assert telemetry["total_tokens"] == 120


async def test_progress_for_a_run_that_was_never_accepted_is_refused():
    """Regression: progress for an unknown run was silently dropped."""
    await _accept("progress-batch", "known")
    with pytest.raises(store.MissingDurableRecord):
        await lifecycle.record_progress("progress-batch", "unknown-fingerprint", "assessing",
                                        "assessing")


async def test_missing_ledger_and_unpinned_configuration_fail_reservation():
    """Regression: a missing ledger returned None (an unaccounted run) and a ledger without
    pinned agent configurations skipped the worker-configuration check."""
    await db.create_all()
    demand = {"requests": 1, "tokens": 1, "cost_usd": 0}
    with pytest.raises(budgets.MissingLedger):
        await budgets.reserve("no-ledger", "op", demand, "context", "config", fingerprint="f")
    with pytest.raises(budgets.MissingLedger):
        await budgets.settle("no-ledger", "op", None, {})
    with pytest.raises(budgets.MissingLedger):
        await budgets.remaining_time("no-ledger")
    async with db.session() as session:
        session.add(db.BudgetLedger(root_id="unpinned", state=budgets.initial_state(
            {"requests": 10, "tokens": 10, "cost_usd": 1})))
        await session.commit()
    with pytest.raises(ValueError, match="pin"):
        await budgets.reserve("unpinned", "op", demand, "context", "config", fingerprint="f")
    execution = {"requests": 0, "tokens": 0, "cost_usd": 0}
    assert (await budgets.reserve("unpinned", "exec", execution, "probe",
                                  operation_kind="execution", fingerprint="f"))["status"] == "reserved"


async def test_durable_writeback_retry_reuses_existing_ado_comment(monkeypatch):
    """No real ADO call: a completed activity retry reuses the persisted hash record."""
    from infosec_harness.integrations import ado
    from infosec_harness.settings import get_settings
    from infosec_harness.workflows.payloads import WritebackArgs
    from infosec_harness.workflows.persistence_activities import writeback_output_activity

    await _accept("ado-durable", "ado-durable")
    out = _output(title="ado-durable")
    out.finding.ado_work_item_id = 42
    run_id = await store.save_run_output("ado-durable", out)
    calls = []

    async def fake_post(work_item_id, text, comment_id):
        calls.append((work_item_id, comment_id))
        return 9001

    monkeypatch.setattr(get_settings(), "ado_writeback_enabled", True)
    monkeypatch.setattr(ado, "post_or_update_comment", fake_post)
    args = WritebackArgs(run_id=run_id, output=out)
    await writeback_output_activity(args)
    await writeback_output_activity(args)
    assert calls == [(42, None)]
    async with db.session() as session:
        row = (await session.execute(select(db.AdoSync).where(
            db.AdoSync.work_item_id == 42))).scalar_one()
        assert row.run_id == run_id
        assert row.comment_id == 9001
