"""Review7 additive controls; synthetic test seals never authorize operator trials."""
import hashlib
import json
from copy import deepcopy
from pathlib import Path

import broker_real_provider_fixture as fixture
import pytest
from pydantic import ValidationError
from test_broker_native_review5 import candidate_files, write_candidates
from test_broker_review6_qualification import comparison, review6, v6_manifest

REASON = "reviewed JVM class guidance and build non-thinking; retain all outcomes; no unknown resend"
NONTHINKING = {"intake", "probe-diagnosis", "verdict", "build-repair"}


def review7(tmp_path, monkeypatch):
    old = review6(tmp_path)
    monkeypatch.setattr(fixture, "REVIEW7_RETAINED_COMPLETED_COUNT", 823)
    monkeypatch.setattr(fixture, "REVIEW7_TERMINAL_SEAL_SHA256", "c" * 64)
    new = hashlib.sha256(b"synthetic-focused-terminal-only").hexdigest()
    saved = old.retained_completed_request_ids + [new]
    retained = tmp_path / "focused-new-row.json"
    retained.write_text(json.dumps({"ledger": {"requests": [{"request_id": new, "state": "completed"}]}}))
    reports = {**old.prior_reports, str(retained): hashlib.sha256(retained.read_bytes()).hexdigest()}
    proof = Path(old.ledger_proof_file)
    proof.write_text(json.dumps({"status": "passed", "unknown_request_ids": old.retained_unknown_request_ids,
        "completed_request_ids": saved, "unknown_holds_retained": True,
        "baseline_seal_sha256": "c" * 64, "all_records_and_all_budget_states_unchanged": True}))
    cause = Path(old.cause_resolution_file)
    cause.write_text(json.dumps({"status": "passed", "reviewed": True,
        "boundary": "native-jvm-class-guidance-and-build-nonthinking", "evidence_sha256": "a" * 64}))
    return fixture.NativeRerunAmendment.model_validate({**old.model_dump(), "review_version": 7,
        "retained_completed_count": 823, "retained_completed_request_ids": saved,
        "prior_reports": reports, "ledger_proof_sha256": hashlib.sha256(proof.read_bytes()).hexdigest(),
        "cause_resolution_sha256": hashlib.sha256(cause.read_bytes()).hexdigest(), "reason": REASON})


def test_review7_cannot_validate_unresolved_terminal_count_or_seal(tmp_path):
    old = review6(tmp_path)
    with pytest.raises(ValidationError, match="frozen focused terminal"):
        fixture.NativeRerunAmendment.model_validate({**old.model_dump(), "review_version": 7, "reason": REASON})


def test_review7_keeps_exact_union_and_finite_scope(tmp_path, monkeypatch):
    value = review7(tmp_path, monkeypatch)
    fixture.verify_native_rerun(value)
    assert len(value.retained_completed_request_ids) == 823
    assert len(value.retained_unknown_request_ids) == 15
    assert (value.additional_trials, value.additional_graph_trials) == (22, 1)
    for changed in ({"additional_trials": 23}, {"additional_graph_trials": 2},
                    {"retained_completed_count": 822}, {"strict_closed_output_tools": False}):
        with pytest.raises(ValidationError):
            type(value).model_validate({**value.model_dump(), **changed})


@pytest.mark.parametrize("change", ["seal", "budgets", "hold", "missing_new_row", "extra"])
def test_review7_rehashed_proof_cannot_erase_full_retention(tmp_path, monkeypatch, change):
    value = review7(tmp_path, monkeypatch)
    path = Path(value.ledger_proof_file)
    proof = json.loads(path.read_text())
    if change == "seal":
        proof["baseline_seal_sha256"] = "d" * 64
    elif change == "budgets":
        proof["all_records_and_all_budget_states_unchanged"] = False
    elif change == "hold":
        proof["unknown_holds_retained"] = False
    elif change == "missing_new_row":
        proof["completed_request_ids"].pop()
    else:
        proof["ignored_failure"] = True
    path.write_text(json.dumps(proof))
    with pytest.raises(ValueError):
        fixture.verify_native_rerun(value.model_copy(update={"ledger_proof_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}))


@pytest.mark.parametrize("agent", list(fixture.CASES))
def test_review7_only_adds_build_thinking_control(tmp_path, monkeypatch, agent):
    candidate = comparison(tmp_path, monkeypatch, agent)
    if agent == "build-repair":
        model = candidate["model"]
        model.update(backend_name="gateway-intake", resolved_model="gateway-intake:Qwen",
            pricing_table="sdk:pinned;models:new;backend:gateway-intake;custom:zero")
        model["capability_profile"]["enable_thinking"] = False
        model["broker_contract"].update(backend="gateway-intake", enable_thinking=False)
    before = deepcopy(candidate)
    result = fixture.compare_review6_baseline(agent, candidate, "a" * 64, review_version=7)
    assert result["declared_output_shaping_difference"]["review_version"] == 7
    assert candidate == before
    if agent == "build-repair":
        with pytest.raises(ValueError):
            fixture.compare_review6_baseline(agent, candidate, "a" * 64)


def test_review7_exact_four_routes_without_client_construction(tmp_path, monkeypatch):
    import openai
    cfg = v6_manifest(tmp_path)
    cfg = cfg.model_copy(update={"rerun": review7(tmp_path, monkeypatch)})
    models, catalog = candidate_files(cfg)
    for agent in NONTHINKING:
        models["agents"][agent] = {"backend": "gateway-intake"}
        catalog["profiles"][agent] = {**catalog["profiles"]["intake"]}
        catalog["agent_profiles"][agent] = agent
    write_candidates(cfg, models, catalog)
    monkeypatch.setattr(openai, "AsyncOpenAI", lambda *a, **kw: pytest.fail("Provider client constructed"))
    resolved = fixture.verify_review5_configuration(cfg)
    assert {agent for agent, value in resolved.items() if value["enable_thinking"] is False} == NONTHINKING
    models["agents"]["env-planner"] = {"backend": "gateway-intake"}
    write_candidates(cfg, models, catalog)
    with pytest.raises(ValueError):
        fixture.verify_review5_configuration(cfg)


@pytest.mark.parametrize("change", ["budget", "capability", "price", "serial", "thinking", "contract_settings"])
def test_review7_rejects_every_undeclared_difference(tmp_path, monkeypatch, change):
    candidate = comparison(tmp_path, monkeypatch, "env-planner")
    model = candidate["model"]
    if change == "budget":
        candidate["budget"]["effective"]["max_input_tokens"] += 1
    elif change == "capability":
        model["capability_profile"]["tool_calling"] = False
    elif change == "price":
        model["pricing_table"] += "changed"
    elif change == "serial":
        for key in ("requested_settings", "effective_settings"):
            model[key]["parallel_tool_calls"] = True
        model["broker_contract"]["model_settings"] = deepcopy(model["effective_settings"])
    elif change == "thinking":
        model["capability_profile"]["enable_thinking"] = False
        model["broker_contract"]["enable_thinking"] = False
    else:
        model["broker_contract"]["model_settings"]["max_tokens"] += 1
    with pytest.raises(ValueError):
        fixture.compare_review6_baseline("env-planner", candidate, "a" * 64, review_version=7)
