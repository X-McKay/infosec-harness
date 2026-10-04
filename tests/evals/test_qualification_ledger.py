import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
spec = importlib.util.spec_from_file_location(
    "qualification_ledger", ROOT / "scripts/qualification_ledger.py"
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


@pytest.fixture
def evidence(tmp_path):
    p = tmp_path / "reviewed-evidence.json"
    p.write_text('{"status":"passed"}')
    return {"file": str(p), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}


def record(evidence, component="intake", status="passed"):
    v = {
        "component": component,
        "scope": "agent_semantics",
        "measured_status": status,
        "measured_source_commit": "a" * 40,
        "dependencies": {"model": {"settings": "b" * 64}},
        "evidence": {"report": evidence},
    }
    v["id"] = m.digest(v)
    return v


def snapshot(rows):
    return {
        "qualification_candidate_commit": "c" * 40,
        "components": {r["component"]: copy.deepcopy(r["dependencies"]) for r in rows},
    }


def test_only_changed_component_invalidated_and_commit_is_not_dependency(evidence):
    rows = [record(evidence), record(evidence, "context")]
    current = snapshot(rows)
    current["components"]["intake"]["model"]["settings"] = "d" * 64
    result = m.assess({"version": 1, "records": rows}, current)
    assert [r["status"] for r in result["results"]] == ["not_checked", "passed"]
    assert result["system_release"] == result["fresh_full118"] == "not_checked"
    assert (
        result["results"][1]["measured_source_commit"]
        != result["results"][1]["qualification_candidate_commit"]
    )


def test_exact_scope_hash_review_cannot_promote_failed_measurement(evidence):
    row = record(evidence)
    current = snapshot([row])
    current["components"]["intake"]["model"]["settings"] = "d" * 64
    review = {
        "scope": row["scope"],
        "before_sha256": m.digest(row["dependencies"]),
        "after_sha256": m.digest(current["components"]["intake"]),
        "reviewer": "operator",
        "reason": "reviewed scope equivalence",
        "evidence": evidence,
    }
    assert (
        m.assess({"version": 1, "records": [row]}, current, {row["id"]: review})["results"][0][
            "status"
        ]
        == "passed"
    )
    failed = record(evidence, status="failed")
    with pytest.raises(ValueError, match="cannot promote"):
        m.assess({"version": 1, "records": [failed]}, current, {failed["id"]: review})
    review["scope"] = "provider_network"
    with pytest.raises(ValueError, match="identity mismatch"):
        m.assess({"version": 1, "records": [row]}, current, {row["id"]: review})


def test_auto_file_hash_and_artifact_drift(evidence, tmp_path):
    row = record(evidence)
    p = tmp_path / "settings.yaml"
    p.write_text("max_tokens: 16000\n")
    row["dependencies"]["model"]["settings"] = hashlib.sha256(p.read_bytes()).hexdigest()
    row["id"] = m.digest({k: v for k, v in row.items() if k != "id"})
    current = snapshot([row])
    current["components"]["intake"]["model"]["settings"] = {"file": str(p)}
    assert m.assess({"version": 1, "records": [row]}, current)["results"][0]["status"] == "passed"
    p.write_text("max_tokens: 32000\n")
    assert (
        m.assess({"version": 1, "records": [row]}, current)["results"][0]["status"] == "not_checked"
    )
    Path(evidence["file"]).write_text("drift")
    assert (
        m.assess({"version": 1, "records": [row]}, current)["results"][0]["disposition"]
        == "evidence_unavailable"
    )


def test_missing_component_and_unknown_review_fail_closed(evidence):
    row = record(evidence)
    current = snapshot([])
    assert (
        m.assess({"version": 1, "records": [row]}, current)["results"][0]["status"] == "not_checked"
    )
    with pytest.raises(ValueError, match="unknown review"):
        m.assess({"version": 1, "records": [row]}, current, {"unknown": {}})


def test_actual_sixteen_records_preserve_fifteen_historical_measurements():
    value = json.loads((ROOT / "evals/qualification/ledger.json").read_text())
    assert len(value["records"]) == 16
    assert sum(r["measured_source_commit"].startswith("5c32ed1") for r in value["records"]) == 11
    assert sum(r["measured_source_commit"].startswith("10f35e9") for r in value["records"]) == 4
    assert sum(r["measured_source_commit"].startswith("449be68") for r in value["records"]) == 1
    for r in value["records"]:
        assert r["id"] == m.digest({k: v for k, v in r.items() if k != "id"})


def test_actual_reviewed_matrix_preserves_measured_scope_and_all_failures(monkeypatch):
    ledger = json.loads((ROOT / "evals/qualification/ledger.json").read_text())
    current = json.loads((ROOT / "evals/qualification/current-449be68.json").read_text())
    reviews = json.loads((ROOT / "evals/qualification/reviews-449be68.json").read_text())
    refs = [v for row in ledger["records"] for v in row["evidence"].values()]
    if any(not Path(ref["file"]).is_file() for ref in refs):
        pytest.skip("private historical evidence is unavailable in this checkout")
    # These private receipts describe the qualified checkout, not the caller's other Git checkout.
    qualified_root = next(
        parent.parent for parent in Path(refs[0]["file"]).parents if parent.name == ".harness"
    )
    monkeypatch.chdir(qualified_root)
    result = m.assess(ledger, current, reviews)
    selected = [r for r in result["results"] if r["record_id"] in reviews]
    assert len(selected) == 11 and len({r["component"] for r in selected}) == 11
    assert all(
        r["status"] == "passed" and r["disposition"] == "reviewed_equivalence" for r in selected
    )
    assert sum(r["measured_source_commit"].startswith("10f35e9") for r in selected) == 4
    assert sum(r["measured_source_commit"].startswith("5c32ed1") for r in selected) == 7
    fresh = [r for r in result["results"] if r["measured_source_commit"].startswith("449be68")]
    assert len(fresh) == 1 and fresh[0]["component"] == "partial-build"
    assert fresh[0]["status"] == "passed" and fresh[0]["disposition"] == "unchanged"
    assert result["system_release"] == result["fresh_full118"] == "not_checked"


def test_reproducible_group_inventory_hashes_actual_bytes_only(evidence, tmp_path):
    source = tmp_path / "agent.py"
    unrelated = tmp_path / "README.md"
    source.write_text("output_contract = 1\n")
    unrelated.write_text("first docs\n")
    row = record(evidence)
    row["dependencies"] = {
        "agent": {
            "inventory": m.digest({"agent.py": hashlib.sha256(source.read_bytes()).hexdigest()})
        }
    }
    row["id"] = m.digest({k: v for k, v in row.items() if k != "id"})
    current = snapshot([row])
    current["components"]["intake"] = {"agent": {"files": {"agent.py": str(source)}}}
    ledger = {"version": 1, "records": [row]}
    assert m.assess(ledger, current)["results"][0]["status"] == "passed"
    unrelated.write_text("docs-only change\n")
    current["qualification_candidate_commit"] = "f" * 40
    assert m.assess(ledger, current)["results"][0]["status"] == "passed"
    source.write_text("output_contract = 2\n")
    assert m.assess(ledger, current)["results"][0]["status"] == "not_checked"
    source.unlink()
    assert m.assess(ledger, current)["results"][0]["status"] == "not_checked"


def test_agent_file_changes_only_owner_and_shared_file_changes_dependents(evidence, tmp_path):
    intake = tmp_path / "intake.py"
    context = tmp_path / "context.py"
    shared = tmp_path / "shared.py"
    for path in (intake, context, shared):
        path.write_text("generation = 1\n")
    rows = [record(evidence, name) for name in ("intake", "context")]
    for row, path in zip(rows, (intake, context), strict=True):
        values = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest(),
            "shared.py": hashlib.sha256(shared.read_bytes()).hexdigest(),
        }
        row["dependencies"] = {"agent_and_shared": {"inventory": m.digest(values)}}
        row["id"] = m.digest({k: v for k, v in row.items() if k != "id"})
    current = snapshot(rows)
    for row, path in zip(rows, (intake, context), strict=True):
        current["components"][row["component"]] = {
            "agent_and_shared": {"files": {path.name: str(path), "shared.py": str(shared)}}
        }
    ledger = {"version": 1, "records": rows}
    intake.write_text("generation = 2\n")
    assert [r["status"] for r in m.assess(ledger, current)["results"]] == ["not_checked", "passed"]
    shared.write_text("generation = 2\n")
    assert [r["status"] for r in m.assess(ledger, current)["results"]] == [
        "not_checked",
        "not_checked",
    ]
    shared.write_text("generation = 1\n")
    intake.unlink()
    assert [r["status"] for r in m.assess(ledger, current)["results"]] == ["not_checked", "passed"]


def test_evidence_drift_does_not_invalidate_unrelated_record(evidence, tmp_path):
    second = tmp_path / "second-report.json"
    second.write_text("{}")
    rows = [
        record(evidence),
        record(
            {"file": str(second), "sha256": hashlib.sha256(second.read_bytes()).hexdigest()},
            "context",
        ),
    ]
    Path(evidence["file"]).write_text("changed historical report")
    result = m.assess({"version": 1, "records": rows}, snapshot(rows))
    assert [r["status"] for r in result["results"]] == ["not_checked", "passed"]
    assert result["results"][0]["disposition"] == "evidence_unavailable"


def test_stale_review_invalidates_only_changed_or_missing_component(evidence, tmp_path):
    path = tmp_path / "intake.py"
    path.write_text("generation = 1\n")
    rows = [record(evidence), record(evidence, "context")]
    current = snapshot(rows)
    current["components"]["intake"] = {"agent": {"files": {"intake.py": str(path)}}}
    reviewed_after = m.dependencies(current["components"]["intake"], current=True)
    review = {
        "scope": rows[0]["scope"],
        "before_sha256": m.digest(rows[0]["dependencies"]),
        "after_sha256": m.digest(reviewed_after),
        "reviewer": "operator",
        "reason": "exact reviewed candidate",
        "evidence": evidence,
    }
    ledger = {"version": 1, "records": rows}
    reviews = {rows[0]["id"]: review}
    assert [r["status"] for r in m.assess(ledger, current, reviews)["results"]] == [
        "passed",
        "passed",
    ]
    path.write_text("generation = 2\n")
    result = m.assess(ledger, current, reviews)["results"]
    assert [r["status"] for r in result] == ["not_checked", "passed"]
    assert result[0]["disposition"] == "retest_or_review_required"
    path.unlink()
    result = m.assess(ledger, current, reviews)["results"]
    assert [r["status"] for r in result] == ["not_checked", "passed"]
    assert result[0]["disposition"] == "inventory_missing"
    review["before_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="identity mismatch"):
        m.assess(ledger, current, reviews)
