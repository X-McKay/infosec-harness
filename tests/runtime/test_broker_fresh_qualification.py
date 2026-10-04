"""Fresh cohort provenance, conservative uncertainty and unchanged comparison controls."""
import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from broker_real_provider_fixture import (
    CASES,
    RealProviderManifest,
    compare_baseline,
    selected_phases,
    verify_fresh_qualification,
)
from test_broker_real_provider_check import manifest

from infosec_harness.persistence import db
from infosec_harness.persistence import reconciliation as rec


def private_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, default=lambda d: d.isoformat()))
    path.chmod(0o600)
    return {"file": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def fresh_manifest(tmp_path, monkeypatch):
    import broker_real_provider_fixture as fixture

    base = manifest(tmp_path)
    root_dir = tmp_path / "checkout"
    root_dir.mkdir()
    source = root_dir / "source.py"
    source.write_text("# pinned offline source\n")
    monkeypatch.setattr(fixture, "ROOT", root_dir)
    monkeypatch.setattr(fixture, "fresh_git_observation", lambda: (base.source_commit, True, {"source.py"}))
    binding = {"root_id": "root", "operation_id": "op", "run_id": "run"}
    reserved = {"requests": 4, "tokens": 100, "cost_usd": 1}
    operation = {"status": "closed_unknown", "run_id": "run", "broker_binding": binding,
        "broker_owned": True, "broker_revoked": True, "reserved": reserved}
    audit = rec.ClosureRequest(root_id="root", operation_id="op", expected_root_revision=0,
        expected_root_sha256="a" * 64, expected_request_sha256={"request": "b" * 64},
        unknown_request_ids=["request"], source_commit="c" * 40,
        evidence_sha256={"backup": "d" * 64}, reason="loss_accepted")
    now = datetime.now(UTC)
    row = db.InferenceRequestRecord(request_id="request", root_id="root", operation_id="op",
        lease_id="deleted", state="completion_unknown", revision=1, request={"binding": binding},
        allocation={"requests": 1, "tokens": 10, "cost_usd": 0}, result=None,
        overrun=None, fence="no-resend", created_at=now, updated_at=now)
    audit = audit.model_copy(update={"expected_request_sha256": {"request": rec.row_sha256(row)}})
    operation["unknown_reconciliation"] = {"version": 1, "authorization": audit.model_dump(),
        "charged": reserved, "accounting_basis": "full_reserved_envelope_estimate",
        "closed_operation_sha256": rec._operation_hash(operation)}
    root = db.BudgetLedger(root_id="root", revision=1, state={"operations": {"op": operation},
        "limits": reserved, "used": reserved, "broker_revoked_runs": ["run"],
        "deadline_at": (now - timedelta(days=1)).isoformat()})
    evidence = {
        "source_pin": private_json(tmp_path / "source.json", {"source_base_commit": base.source_commit,
            "host_git_clean": True, "tracked_files_sha256": {"source.py": hashlib.sha256(source.read_bytes()).hexdigest()}}),
        "closure_manifest": private_json(tmp_path / "closure.json", {"source_commit": "c" * 40,
            "operations": [audit.model_dump()]}),
        "closure_rows": private_json(tmp_path / "rows.json", {
            "roots": [{c.name: getattr(root, c.name) for c in root.__table__.columns}],
            "requests": [{c.name: getattr(row, c.name) for c in row.__table__.columns}]}),
        "baseline_snapshot": private_json(tmp_path / "snapshot.json", {
            "roots": {"root": rec.row_sha256(root)}, "requests": {"request": rec.row_sha256(row)}}),
        "closure_result": private_json(tmp_path / "result.json", {"status": "passed", "source_commit": "c" * 40,
            "all_request_rows_unchanged": True, "all_unrelated_roots_unchanged": True,
            "full_reserved_envelopes_charged_once": True, "provider_calls": 0, "lease_mutations": 0,
            "request_row_mutations": 0, "unresolved_requests": 0, "request_rows": 1, "budget_roots": 1,
            "conservatively_closed_requests": 1, "permanent_unknown_outcomes": 1, "exact_affected_roots": 1}),
    }
    files = []
    for name in ("direct.yaml", "models.yaml", "broker.yaml", "native.yaml"):
        p = tmp_path / name
        p.write_text("# frozen candidate\n")
        files.append(p)
    value = base.model_dump(mode="json")
    value.update(case_digests=dict.fromkeys(CASES, "e" * 64), direct_models_config=str(files[0]), broker_models_config=str(files[1]), broker_config=str(files[2]),
        fresh={"generation": "fresh-native-v1", "evidence": evidence, "native_config_file": str(files[3]),
            "candidate_files": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
            "case_budget_sha256": dict.fromkeys(CASES, "a" * 64),
            "case_contract_sha256": dict.fromkeys(CASES, "b" * 64), "graph_trials": 3})
    return RealProviderManifest.model_validate(value)


def repin(config, name, change):
    value = config.model_dump(mode="json")
    ref = value["fresh"]["evidence"][name]
    content = json.loads(Path(ref["file"]).read_text())
    change(content)
    value["fresh"]["evidence"][name] = private_json(Path(ref["file"]), content)
    return RealProviderManifest.model_validate(value)


def test_fresh_scope_all33_and_closed_unknown_proof_never_opens_database(tmp_path, monkeypatch):
    config = fresh_manifest(tmp_path, monkeypatch)
    monkeypatch.setattr(db, "session", lambda: pytest.fail("File-only preflight opened database"))
    verify_fresh_qualification(config)
    assert selected_phases(config, "all") == ("direct", "local", "temporal")
    assert config.maximum_pilot_agent_trials == 33 and config.fresh.graph_trials == 3


@pytest.mark.parametrize("name,change", [
    ("closure_result", lambda v: v.update(unresolved_requests=1)),
    ("closure_result", lambda v: v.update(full_reserved_envelopes_charged_once=False)),
    ("closure_rows", lambda v: v["requests"][0].update(result={"invented": True})),
    ("closure_rows", lambda v: v["roots"][0]["state"]["operations"]["op"].pop("unknown_reconciliation")),
    ("baseline_snapshot", lambda v: v["requests"].update(request="0" * 64)),
    ("closure_manifest", lambda v: v["operations"][0].update(evidence_sha256={"different": "e" * 64})),
])
def test_rehashed_but_semantically_invalid_evidence_rejects(tmp_path, monkeypatch, name, change):
    config = fresh_manifest(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        verify_fresh_qualification(repin(config, name, change))


def test_fresh_candidate_drift_and_historical_serialization_unchanged(tmp_path, monkeypatch):
    assert "fresh" not in manifest(tmp_path).model_dump(mode="json")
    config = fresh_manifest(tmp_path, monkeypatch)
    Path(config.broker_models_config).write_text("# changed\n")
    with pytest.raises(ValueError, match="candidate changed"):
        verify_fresh_qualification(config)


def test_current_direct_native_strict_controls_match_and_full_budget_drift_rejects(tmp_path, monkeypatch):
    from infosec_harness.inference.protocol import digest

    model = {"capability_profile": {"strict_closed_output_tools": True}, "effective_settings": {"max_tokens": 16000}}
    config = {"model": model, "budget": {"requested": {"max_requests": 4}, "effective": {"max_requests": 4}}}
    case_digest = "a" * 64
    path = tmp_path / "direct.json"
    private_json(path, {"phase": "direct", "status": "passed", "cases": [
        {"agent": agent, "case": case, "case_digest": case_digest, "config": config}
        for agent, case in CASES.items()]})
    monkeypatch.setenv("HARNESS_REAL_PROVIDER_BASELINE", str(path))
    assert compare_baseline("intake", config, case_digest, reviewed_strict_closed_output_tools=True,
                            fresh_controls=True)["status"] == "passed"
    changed = deepcopy(config)
    changed["budget"]["effective"]["max_requests"] = 5
    with pytest.raises(ValueError, match="full case budgets"):
        compare_baseline("intake", changed, case_digest, reviewed_strict_closed_output_tools=True, fresh_controls=True)
    assert digest(config["budget"]) != digest(changed["budget"])
    with pytest.raises(ValueError):
        compare_baseline("intake", config, case_digest, reviewed_strict_closed_output_tools=True)


def test_exact_three_fresh_graph_registries_no_claim_reuse_and_sha_required(tmp_path, monkeypatch):
    import broker_real_graph_fixture as graph
    import broker_real_provider_fixture as provider

    config = fresh_manifest(tmp_path, monkeypatch)
    monkeypatch.setattr(graph, "ROOT", provider.ROOT)
    monkeypatch.setattr(provider, "verify_review5_configuration", lambda _: {})
    parent = provider.ROOT / ".harness/openshell-spike/live-qualification"
    parent.mkdir(parents=True)
    pilot = parent / "pilot.json"
    private_json(pilot, config.model_dump(mode="json"))
    manifests = []
    for index in (1, 2, 3):
        path = parent / f"graph{index}.json"
        frozen = graph.freeze(pilot, path, "native", trial_index=index)
        assert frozen["maximum_trials"] == 1 and frozen["fresh_cohort"]["maximum_trials"] == 3
        assert frozen["duration_seconds"] == 7200
        with pytest.raises(ValueError, match="exact frozen manifest"):
            graph.preflight(path)
        graph.preflight(path, graph.sha(path))
        manifests.append(path)
    assert len({json.loads(path.read_text())["directory"] for path in manifests}) == 3
    with pytest.raises(ValueError):
        graph.freeze(pilot, parent / "fourth.json", "native", trial_index=4)
    with pytest.raises(ValueError, match="already has"):
        graph.freeze(pilot, parent / "reused.json", "native", trial_index=1)
    assert not (parent / "graph-native-manifest.frozen").exists()


def test_historical_pilot_cannot_request_new_graph_scope(tmp_path):
    import broker_real_graph_fixture as graph

    pilot = tmp_path / "old.json"
    private_json(pilot, manifest(tmp_path).model_dump(mode="json"))
    with pytest.raises(ValueError):
        graph.freeze(pilot, tmp_path / "graph.json", "native", trial_index=1)


@pytest.mark.parametrize("head,clean,tracked", [
    ("d" * 40, True, {"source.py"}),
    (None, False, {"source.py"}),
    (None, True, {"source.py", "omitted.py"}),
    (None, True, set()),
])
def test_fresh_source_requires_actual_complete_clean_head(tmp_path, monkeypatch, head, clean, tracked):
    import broker_real_provider_fixture as fixture

    config = fresh_manifest(tmp_path, monkeypatch)
    monkeypatch.setattr(fixture, "fresh_git_observation",
        lambda: (head or config.source_commit, clean, tracked))
    with pytest.raises(ValueError, match="exact current HEAD"):
        verify_fresh_qualification(config)


def test_fresh_git_observation_is_bounded_readonly(tmp_path, monkeypatch):
    from types import SimpleNamespace

    import broker_real_provider_fixture as fixture

    calls = []
    outputs = iter(["a" * 40 + "\n", "", "source.py\0other.py\0"])
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(stdout=next(outputs))
    monkeypatch.setattr(fixture, "ROOT", tmp_path)
    monkeypatch.setattr(fixture.subprocess, "run", run)
    assert fixture.fresh_git_observation() == ("a" * 40, True, {"source.py", "other.py"})
    assert [c[0] for c in calls] == [
        ["git", "rev-parse", "HEAD"],
        ["git", "status", "--porcelain", "--untracked-files=no"],
        ["git", "ls-files", "-z"],
    ]
    assert all(k == {"cwd": tmp_path, "check": True, "capture_output": True,
        "text": True, "timeout": 10} for _, k in calls)
