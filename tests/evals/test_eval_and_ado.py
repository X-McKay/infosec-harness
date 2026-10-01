import yaml

from infosec_harness.domain.models import (
    Finding,
    FindingSourceKind,
    PriorityBand,
    TriageResult,
    TriageRunOutput,
    Verdict,
    VerdictLabel,
)
from infosec_harness.evals.run import run_experiment
from infosec_harness.integrations import ado
from infosec_harness.settings import get_settings


async def test_eval_probe_diagnosis_scores():
    exp_id = await run_experiment("probe-diagnosis")
    from infosec_harness.persistence import db
    async with db.session() as s:
        exp = await s.get(db.EvalExperiment, exp_id)
    assert exp.metrics["accuracy"] == 1.0  # stub reads exit code + oracle deterministically
    # Every case in the dataset, including the ones carrying the plan and probe source the
    # graph really sends. The stub decides from the execution record alone, so a new case
    # failing here means the record itself is ambiguous.
    assert exp.metrics["n"] == len(
        yaml.safe_load((get_settings().agents_dir / "probe-diagnosis" / "evals" / "dataset.yaml")
                       .read_text())["cases"])


def test_ado_work_item_mapping():
    field_map = {"repo_url": "Custom.Repository", "file_path": "Custom.FilePath", "cwe": "Custom.CWE"}
    item = {"id": 42, "fields": {"System.Title": "SSRF", "System.Description": "user url fetched",
            "Custom.Repository": "https://git/x", "Custom.FilePath": "svc.py", "Custom.CWE": "CWE-918"}}
    finding = ado.work_item_to_finding(item, field_map)
    assert finding.ado_work_item_id == 42 and finding.repo_url == "https://git/x"
    assert finding.cwe == "CWE-918" and finding.source_kind.value == "ado"


def test_ado_comment_render_is_comment_only():
    finding = Finding(fingerprint="fp", title="t", repo_url="/r", revision="HEAD",
                      source_kind=FindingSourceKind.ado, ado_work_item_id=7)
    verdict = Verdict(label=VerdictLabel.potentially_exploitable, confidence=0.9, rationale="oracle fired")
    out = TriageRunOutput(finding=finding,
                          result=TriageResult(fingerprint="fp", verdict=verdict, priority_score=0.7,
                                              priority=PriorityBand.p1),
                          prepared_status="ready")
    text = ado.render_comment(out, "http://ui")
    assert "potentially exploitable" in text and "http://ui/findings/fp" in text
    assert "recommended before action" in text
