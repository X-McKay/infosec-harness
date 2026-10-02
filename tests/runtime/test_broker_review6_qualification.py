"""The next generation retains all outcomes and admits only reviewed differences."""
import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest
from broker_real_provider_fixture import (
    CASES,
    NativeRerunAmendment,
    compare_manifest_baseline,
    selected_phases,
    verify_native_rerun,
    verify_review5_configuration,
)
from pydantic import ValidationError
from test_broker_native_review5 import candidate_files, review5, v5_manifest, write_candidates

SEAL = "667beac3be8c8569df0c981a4ad24f35ccdf7ea77148f120a89346a7bb935981"
NONTHINKING = {"intake", "probe-diagnosis", "verdict"}
SERIAL = {"env-planner", "build-repair", "partial-build"}


def review6(tmp_path):
    old = review5(tmp_path)
    saved = old.retained_completed_request_ids + [hashlib.sha256(f"v6-old-{i}".encode()).hexdigest() for i in range(660)]
    reports = dict(old.prior_reports)
    for i in range(3):
        path = tmp_path / f"full-retained-{i}.json"
        path.write_text(json.dumps({"ledger": {"requests": [
            {"request_id": rid, "state": "completed"} for rid in saved[162:][i::3]]}}))
        reports[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    proof = Path(old.ledger_proof_file)
    proof.write_text(json.dumps({"status": "passed", "unknown_request_ids": old.retained_unknown_request_ids,
        "completed_request_ids": saved, "unknown_holds_retained": True, "baseline_seal_sha256": SEAL,
        "all837_records_and_budget_states_unchanged": True}))
    cause = Path(old.cause_resolution_file)
    cause.write_text(json.dumps({"status": "passed", "reviewed": True,
        "boundary": "native-serial-tools-and-targeted-output-guidance", "evidence_sha256": "a" * 64}))
    return NativeRerunAmendment.model_validate({**old.model_dump(), "review_version": 6,
        "retained_completed_count": 822, "retained_completed_request_ids": saved, "prior_reports": reports,
        "ledger_proof_sha256": hashlib.sha256(proof.read_bytes()).hexdigest(),
        "cause_resolution_sha256": hashlib.sha256(cause.read_bytes()).hexdigest(),
        "reason": "reviewed serial tool calls and targeted output guidance; retain all outcomes; no unknown resend"})


def v6_manifest(tmp_path):
    old = v5_manifest(tmp_path)
    return type(old).model_validate({**old.model_dump(), "rerun": review6(tmp_path).model_dump()})


def test_exact_sealed_union_and_finite_fresh_phases(tmp_path):
    cfg = v6_manifest(tmp_path)
    verify_native_rerun(cfg.rerun)
    assert len(cfg.rerun.retained_unknown_request_ids) == 15
    assert len(cfg.rerun.retained_completed_request_ids) == 822
    assert (cfg.rerun.additional_trials, cfg.rerun.additional_graph_trials) == (22, 1)
    assert selected_phases(cfg, "all") == ("local", "temporal")
    with pytest.raises(ValueError, match="only fresh native"):
        selected_phases(cfg, "direct")


@pytest.mark.parametrize("change", [{"retained_completed_count": 821}, {"additional_trials": 23},
    {"additional_graph_trials": 2}, {"strict_closed_output_tools": False}, {"intake_enable_thinking": True},
    {"retained_local_report_file": "old-local"}, {"baseline_report_sha256": "b" * 64}])
def test_scope_cannot_expand_or_erase_history(tmp_path, change):
    old = review6(tmp_path)
    with pytest.raises(ValidationError):
        type(old).model_validate({**old.model_dump(), **change})


@pytest.mark.parametrize("change", ["seal", "budget", "hold", "lost_id", "extra_key"])
def test_rehashed_proof_cannot_downgrade_preservation(tmp_path, change):
    old = review6(tmp_path)
    path = Path(old.ledger_proof_file)
    proof = json.loads(path.read_text())
    if change == "seal":
        proof["baseline_seal_sha256"] = "b" * 64
    elif change == "budget":
        proof["all837_records_and_budget_states_unchanged"] = False
    elif change == "hold":
        proof["unknown_holds_retained"] = False
    elif change == "lost_id":
        proof["completed_request_ids"].pop()
    else:
        proof["ignore_failure"] = True
    path.write_text(json.dumps(proof))
    changed = old.model_copy(update={"ledger_proof_sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    with pytest.raises(ValueError):
        verify_native_rerun(changed)


def comparison(tmp_path, monkeypatch, agent):
    from broker_real_provider_fixture import COMPARISON_MODEL_FIELDS
    previous = {"model": dict.fromkeys(COMPARISON_MODEL_FIELDS, "fixed"),
        "budget": {"requested": {"max_requests": 4}, "effective": {"max_input_tokens": 20000}}}
    previous["model"].update(backend_name="gateway", resolved_model="gateway:Qwen",
        capability_profile={"tool_calling": True}, requested_settings={"max_tokens": 16},
        effective_settings={"max_tokens": 16}, pricing_table="sdk:pinned;models:old;backend:gateway;custom:zero")
    baseline = tmp_path / "direct.json"
    baseline.write_text(json.dumps({"phase": "direct", "status": "passed", "cases": [
        {"agent": a, "case": c, "case_digest": "a" * 64, "config": previous} for a, c in CASES.items()]}))
    monkeypatch.setenv("HARNESS_REAL_PROVIDER_BASELINE", str(baseline))
    candidate = deepcopy(previous)
    m = candidate["model"]
    m["capability_profile"]["strict_closed_output_tools"] = True
    if agent in NONTHINKING:
        m.update(backend_name="gateway-intake", resolved_model="gateway-intake:Qwen",
            pricing_table="sdk:pinned;models:new;backend:gateway-intake;custom:zero")
        m["capability_profile"]["enable_thinking"] = False
    if agent in SERIAL:
        for key in ("requested_settings", "effective_settings"):
            m[key]["parallel_tool_calls"] = False
    m["broker_contract"] = {"strict_closed_output_tools": True, "backend": m["backend_name"], "model": "Qwen",
        "model_settings": deepcopy(m["effective_settings"])}
    if agent in NONTHINKING:
        m["broker_contract"]["enable_thinking"] = False
    return candidate


@pytest.mark.parametrize("agent", list(CASES))
def test_only_declared_per_agent_changes_compare_without_mutation(tmp_path, monkeypatch, agent):
    cfg = v6_manifest(tmp_path)
    candidate = comparison(tmp_path, monkeypatch, agent)
    before = deepcopy(candidate)
    result = compare_manifest_baseline(cfg, agent, candidate, "a" * 64)
    assert result["declared_output_shaping_difference"]["review_version"] == 6
    assert result["declared_review6_difference"]["parallel_tool_calls"] is (False if agent in SERIAL else None)
    assert candidate == before


@pytest.mark.parametrize("change", ["capability", "budget", "price", "max_tokens", "serial_true",
    "unrelated_serial", "unrelated_thinking", "contract_settings"])
def test_every_unrelated_config_difference_is_rejected(tmp_path, monkeypatch, change):
    agent = "env-planner" if change == "serial_true" else "recon"
    cfg = v6_manifest(tmp_path)
    candidate = comparison(tmp_path, monkeypatch, agent)
    model = candidate["model"]
    if change == "capability":
        model["capability_profile"]["tool_calling"] = False
    elif change == "budget":
        candidate["budget"]["effective"]["max_input_tokens"] += 1
    elif change == "price":
        model["pricing_table"] += "changed"
    elif change == "unrelated_thinking":
        model["capability_profile"]["enable_thinking"] = False
    elif change == "contract_settings":
        model["broker_contract"]["model_settings"]["max_tokens"] += 1
    else:
        for key in ("requested_settings", "effective_settings"):
            if change == "max_tokens":
                model[key]["max_tokens"] += 1
            else:
                model[key]["parallel_tool_calls"] = change == "serial_true"
        model["broker_contract"]["model_settings"] = deepcopy(model["effective_settings"])
    with pytest.raises(ValueError):
        compare_manifest_baseline(cfg, agent, candidate, "a" * 64)


def test_pure_configuration_resolution_checks_exact_three_routes(tmp_path, monkeypatch):
    import openai
    cfg = v6_manifest(tmp_path)
    models, catalog = candidate_files(cfg)
    for agent in NONTHINKING:
        models["agents"][agent] = {"backend": "gateway-intake"}
        catalog["profiles"][agent] = {**catalog["profiles"]["intake"]}
        catalog["agent_profiles"][agent] = agent
    write_candidates(cfg, models, catalog)
    monkeypatch.setattr(openai, "AsyncOpenAI", lambda *a, **kw: pytest.fail("Preflight constructed a client"))
    resolved = verify_review5_configuration(cfg)
    assert {a for a, v in resolved.items() if v["enable_thinking"] is False} == NONTHINKING
    models["agents"]["recon"] = {"backend": "gateway-intake"}
    write_candidates(cfg, models, catalog)
    with pytest.raises(ValueError):
        verify_review5_configuration(cfg)


@pytest.mark.parametrize("change", ["clone", "model", "profile_thinking", "profile_backend", "strict"])
def test_preflight_rejects_other_provider_or_profile_changes(tmp_path, change):
    cfg = v6_manifest(tmp_path)
    models, catalog = candidate_files(cfg)
    for agent in NONTHINKING:
        models["agents"][agent] = {"backend": "gateway-intake"}
        catalog["profiles"][agent] = {**catalog["profiles"]["intake"]}
        catalog["agent_profiles"][agent] = agent
    if change == "clone":
        models["backends"]["gateway-intake"]["min_max_tokens"] += 1
    elif change == "model":
        models["model_catalog"]["sonnet"]["gateway-intake"] = "other-model"
    elif change == "profile_thinking":
        catalog["profiles"]["verdict"]["enable_thinking"] = None
    elif change == "profile_backend":
        catalog["profiles"]["verdict"]["backend_name"] = "gateway"
    else:
        catalog["profiles"]["verdict"]["strict_closed_output_tools"] = False
    write_candidates(cfg, models, catalog)
    with pytest.raises(ValueError):
        verify_review5_configuration(cfg)


def test_v6_phase_expectation_cannot_come_from_ambient_environment(tmp_path, monkeypatch):
    from broker_real_provider_fixture import phase_environment
    cfg = v6_manifest(tmp_path)
    monkeypatch.setenv("HARNESS_REAL_PROVIDER_STRICT_CLOSED_OUTPUT_TOOLS", "false")
    assert phase_environment(cfg, "local")["HARNESS_REAL_PROVIDER_STRICT_CLOSED_OUTPUT_TOOLS"] == "true"
    assert "HARNESS_REAL_PROVIDER_STRICT_CLOSED_OUTPUT_TOOLS" not in phase_environment(cfg, "direct")
