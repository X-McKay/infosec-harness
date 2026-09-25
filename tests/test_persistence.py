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
                       input_tokens=100, output_tokens=20, cache_read_tokens=40, cost_usd=0.01)
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
