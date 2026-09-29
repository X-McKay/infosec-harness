import pytest

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
