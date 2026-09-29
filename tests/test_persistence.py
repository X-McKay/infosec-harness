import pytest
from sqlalchemy import select

from infosec_harness.domain.models import (
    AgentOutcome,
    Finding,
    FindingSourceKind,
    PriorityBand,
    TriageResult,
    TriageRunOutput,
    Verdict,
    VerdictLabel,
)
from infosec_harness.persistence import db, store


def _output(fp="fp1", label=VerdictLabel.potentially_exploitable):
    finding = Finding(fingerprint=fp, title="t", repo_url="/r", revision="HEAD",
                      cwe="CWE-89", source_kind=FindingSourceKind.generic_json)
    verdict = Verdict(label=label, confidence=0.8, rationale="r")
    result = TriageResult(fingerprint=fp, verdict=verdict, priority_score=0.5, priority=PriorityBand.p2)
    inv = AgentOutcome(output=None, agent="verdict", model_name="stub", config_hash="abc",
                       input_tokens=100, output_tokens=20, cache_read_tokens=40, cost_usd=0.01,
                       requests=7, repeated_tool_calls={"read_file({'path': 'app.py'})": 3})
    return TriageRunOutput(finding=finding, result=result, prepared_status="ready", invocations=[inv])


async def test_save_and_query_run():
    await db.create_all()
    await store.create_batch("b1", source_kind="generic_json", label="t", count=1)
    run_id = await store.save_run_output("b1", _output())
    rows = await store.list_runs(batch_id="b1")
    assert len(rows) == 1 and rows[0]["verdict"] == "potentially_exploitable"
    detail = await store.get_run(run_id)
    assert detail["cost_usd"] == pytest.approx(0.01)
    assert detail["invocations"][0]["agent"] == "verdict"
    assert detail["cache_read_tokens"] == 40
    # Request accounting survives the round trip, so a request_limit breach stays
    # diagnosable from the stored run rather than needing a live re-run.
    assert detail["invocations"][0]["requests"] == 7
    assert detail["invocations"][0]["repeated_tool_calls"] == {"read_file({'path': 'app.py'})": 3}
    assert detail["evidence"]["manifest"]["schema_version"] == 2
    assert len(detail["evidence"]["manifest"]["harness"]["packaged_source_sha256"]) == 64


async def test_review_roundtrip():
    await db.create_all()
    await store.create_batch("b2", source_kind="generic_json", label="t", count=1)
    run_id = await store.save_run_output("b2", _output(fp="fp2"))
    assert await store.save_review(run_id, reviewer="alice", decision="override",
                                   override_label="likely_not_exploitable", reason="fp")
    detail = await store.get_run(run_id)
    assert detail["review"]["decision"] == "override"
    assert detail["review"]["override_label"] == "likely_not_exploitable"


async def test_save_is_idempotent():
    await db.create_all()
    await store.create_batch("b3", source_kind="generic_json", label="t", count=1)
    await store.save_run_output("b3", _output(fp="fp3"))
    await store.save_run_output("b3", _output(fp="fp3"))  # re-run, same fingerprint
    rows = await store.list_runs(batch_id="b3")
    assert len(rows) == 1


async def test_unknown_cost_is_not_exposed_as_zero():
    await db.create_all()
    await store.create_batch("unknown-cost", source_kind="generic_json", label="unknown", count=1)
    output = _output(fp="unknown-cost")
    output.invocations[0].cost_usd = None
    run_id = await store.save_run_output("unknown-cost", output)
    detail = await store.get_run(run_id)
    assert detail["cost_usd"] is None
    assert detail["telemetry"]["cost_usd"] is None
    assert detail["telemetry"]["cost_coverage"] == 0


async def test_late_output_cannot_overwrite_cancelled_result_data():
    await db.create_all()
    await store.create_batch("late-output", source_kind="generic_json", label="late", count=1)
    out = _output(fp="late-output")
    run_id = await store.save_run_output("late-output", out)
    before = await store.get_run(run_id)
    async with db.session() as session:
        run = await session.get(db.TriageRun, run_id)
        run.status = "cancelled"
        await session.commit()
    late = _output(fp="late-output", label=VerdictLabel.likely_not_exploitable)
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
    from infosec_harness.persistence.budgets import initial_state

    await db.create_all()
    await store.create_batch("free-retries", source_kind="generic_json", label="free", count=1)
    out = _output(fp="free-retry-fingerprint")
    out.invocations[0].cost_usd = 0.0
    state = initial_state({"tokens": 1000, "requests": 100, "cost_usd": 1})
    state["operations"]["triage:free-retry-fingerprint:call"] = {
        "status": "uncertain", "reserved": {"tokens": 500, "requests": 10, "cost_usd": 0},
        "record": {"pricing_status": "known_zero"}}
    async with db.session() as session:
        session.add(db.BudgetLedger(root_id="free-retries", state=state))
        await session.commit()
    detail = await store.get_run(await store.save_run_output("free-retries", out))
    assert detail["telemetry"]["cost_usd"] == 0
    assert detail["telemetry"]["cost_accounting_complete"] is True
    assert detail["telemetry"]["total_tokens"] is None
    assert detail["telemetry"]["accounting_complete"] is False


def test_uncertain_execution_does_not_erase_exact_zero_provider_usage():
    out = _output(fp="resource-separated")
    invocation = out.invocations[0]
    invocation.input_tokens = 0
    invocation.output_tokens = 0
    invocation.cost_usd = 0.0
    operations = {
        "triage:resource-separated:0:verdict": {
            "kind": "agent", "status": "settled", "record": {"pricing_status": "known_zero"},
        },
        "triage:resource-separated:1:probe": {
            "kind": "execution", "status": "uncertain",
        },
    }

    telemetry = store._output_values(out, {}, operations)["telemetry"]

    assert telemetry["accounting_complete"] is True
    assert telemetry["cost_accounting_complete"] is True
    assert telemetry["total_tokens"] == 0
    assert telemetry["cost_usd"] == 0


@pytest.mark.parametrize(("pricing_status", "expected_cost"), [(None, None), ("known_zero", 0)])
def test_uncertain_agent_usage_keeps_cost_unknown_unless_pricing_is_zero(
    pricing_status, expected_cost,
):
    out = _output(fp="uncertain-agent")
    out.invocations[0].cost_usd = 0.0
    operations = {
        "triage:uncertain-agent:0:verdict": {
            "kind": "agent",
            "status": "uncertain",
            "record": {"pricing_status": pricing_status},
        },
    }

    telemetry = store._output_values(out, {}, operations)["telemetry"]

    assert telemetry["accounting_complete"] is False
    assert telemetry["total_tokens"] is None
    assert telemetry["cost_usd"] == expected_cost


def test_legacy_operation_without_kind_remains_an_agent_operation():
    out = _output(fp="legacy-operation")
    operations = {"triage:legacy-operation:0:verdict": {"status": "settled", "record": {}}}

    telemetry = store._output_values(out, {}, operations)["telemetry"]

    assert telemetry["accounting_complete"] is True
    assert telemetry["cost_accounting_complete"] is True
    assert telemetry["total_tokens"] == 120
    assert telemetry["cost_usd"] == pytest.approx(0.01)


async def test_durable_writeback_retry_reuses_existing_ado_comment(monkeypatch):
    """No real ADO call: a completed activity retry reuses the persisted hash record."""
    from infosec_harness.integrations import ado
    from infosec_harness.settings import get_settings
    from infosec_harness.workflows.progress import writeback_output_activity

    await db.create_all()
    await store.create_batch("ado-durable", source_kind="ado", label="ado", count=1)
    out = _output(fp="ado-durable-fingerprint")
    out.finding.ado_work_item_id = 42
    run_id = await store.save_run_output("ado-durable", out)
    calls = []

    async def fake_post(work_item_id, text, comment_id):
        calls.append((work_item_id, comment_id))
        return 9001

    monkeypatch.setattr(get_settings(), "ado_writeback_enabled", True)
    monkeypatch.setattr(ado, "post_or_update_comment", fake_post)
    args = {"run_id": run_id, "output": out.model_dump(mode="json")}
    await writeback_output_activity(args)
    await writeback_output_activity(args)
    assert calls == [(42, None)]
    async with db.session() as session:
        row = (await session.execute(select(db.AdoSync).where(
            db.AdoSync.work_item_id == 42))).scalar_one()
        assert row.run_id == run_id
        assert row.comment_id == 9001
