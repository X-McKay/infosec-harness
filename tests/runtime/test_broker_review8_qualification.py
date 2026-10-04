"""Synthetic review8 evidence exercises verification; it authorizes no live trial."""

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import broker_real_provider_fixture as fixture
import pytest
from pydantic import ValidationError
from test_broker_native_review5 import candidate_files, write_candidates
from test_broker_review6_qualification import comparison, v6_manifest
from test_broker_review7_qualification import review7

REASON = "reviewed parent-prepared workload seccomp; retain all outcomes; no unknown resend"


def review8(tmp_path, monkeypatch):
    previous = review7(tmp_path, monkeypatch)
    request_id = hashlib.sha256(b"synthetic-review8-new-completed-row").hexdigest()
    saved = previous.retained_completed_request_ids + [request_id]
    retained = tmp_path / "review8-new-row.json"
    retained.write_text(
        json.dumps({"ledger": {"requests": [{"request_id": request_id, "state": "completed"}]}})
    )
    reports = {
        **previous.prior_reports,
        str(retained): hashlib.sha256(retained.read_bytes()).hexdigest(),
    }
    seal = tmp_path / "whole-state-seal.json"
    states = {rid: "completed" for rid in saved}
    states.update({rid: "completion_unknown" for rid in previous.retained_unknown_request_ids})
    # A complete baseline may include known saved rows absent from the native report union.
    states[hashlib.sha256(b"all-record-not-native-report").hexdigest()] = "completed"
    seal.write_text(
        json.dumps(
            {
                "status": "passed",
                "active_lease_count": 0,
                "native_sandbox_count": 0,
                "states": states,
                "requests": {rid: "a" * 64 for rid in states},
                "ledgers": {"root": "b" * 64},
            }
        )
    )
    seal_sha = hashlib.sha256(seal.read_bytes()).hexdigest()
    proof = Path(previous.ledger_proof_file)
    proof.write_text(
        json.dumps(
            {
                "status": "passed",
                "unknown_request_ids": previous.retained_unknown_request_ids,
                "completed_request_ids": saved,
                "unknown_holds_retained": True,
                "baseline_seal_sha256": seal_sha,
                "all_records_and_all_budget_states_unchanged": True,
            }
        )
    )
    cause = Path(previous.cause_resolution_file)
    cause.write_text(
        json.dumps(
            {
                "status": "passed",
                "reviewed": True,
                "boundary": "native-parent-prepared-workload-seccomp",
                "evidence_sha256": "a" * 64,
            }
        )
    )
    return fixture.NativeRerunAmendment.model_validate(
        {
            **previous.model_dump(),
            "review_version": 8,
            "retained_terminal_seal_sha256": seal_sha,
            "retained_terminal_seal_file": str(seal),
            "reason": REASON,
            "retained_completed_count": 824,
            "retained_completed_request_ids": saved,
            "prior_reports": reports,
            "ledger_proof_sha256": hashlib.sha256(proof.read_bytes()).hexdigest(),
            "cause_resolution_sha256": hashlib.sha256(cause.read_bytes()).hexdigest(),
        }
    )


def test_review8_accepts_exact_current_union_without_replacing_historical_anchor(
    tmp_path, monkeypatch
):
    value = review8(tmp_path, monkeypatch)
    fixture.verify_native_rerun(value)
    assert (value.additional_trials, value.additional_graph_trials) == (22, 1)
    assert value.retained_completed_count == 824
    assert fixture.REVIEW7_RETAINED_COMPLETED_COUNT == 823  # synthetic historical fixture anchor


@pytest.mark.parametrize(
    "change",
    [
        {"retained_terminal_seal_sha256": None},
        {"retained_terminal_seal_sha256": "bad"},
        {"retained_completed_count": 825},
        {"additional_trials": 23},
        {"additional_graph_trials": 2},
        {"strict_closed_output_tools": False},
        {"intake_enable_thinking": None},
    ],
)
def test_review8_rejects_unresolved_or_expanded_scope(tmp_path, monkeypatch, change):
    value = review8(tmp_path, monkeypatch)
    with pytest.raises(ValidationError):
        type(value).model_validate({**value.model_dump(), **change})


@pytest.mark.parametrize("change", ["seal", "budgets", "holds", "request", "extra"])
def test_review8_rehashed_retention_proof_cannot_erase_state(tmp_path, monkeypatch, change):
    value = review8(tmp_path, monkeypatch)
    path = Path(value.ledger_proof_file)
    proof = json.loads(path.read_text())
    if change == "seal":
        proof["baseline_seal_sha256"] = "d" * 64
    elif change == "budgets":
        proof["all_records_and_all_budget_states_unchanged"] = False
    elif change == "holds":
        proof["unknown_holds_retained"] = False
    elif change == "request":
        proof["completed_request_ids"].pop()
    else:
        proof["ignored"] = True
    path.write_text(json.dumps(proof))
    changed = value.model_copy(
        update={"ledger_proof_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    )
    with pytest.raises(ValueError):
        fixture.verify_native_rerun(changed)


def test_review8_does_not_allow_new_field_in_historical_review(tmp_path, monkeypatch):
    previous = review7(tmp_path, monkeypatch)
    with pytest.raises(ValidationError):
        type(previous).model_validate(
            {**previous.model_dump(), "retained_terminal_seal_sha256": "c" * 64}
        )


@pytest.mark.parametrize("agent", list(fixture.CASES))
def test_review8_preserves_all_current_controls_without_mutating_input(
    tmp_path, monkeypatch, agent
):
    candidate = comparison(tmp_path, monkeypatch, agent)
    if agent == "build-repair":
        model = candidate["model"]
        model.update(
            backend_name="gateway-build-repair",
            resolved_model="gateway-build-repair:Qwen",
            pricing_table="sdk:pinned;models:new;backend:gateway-build-repair;custom:zero",
        )
        model["capability_profile"]["thinking_token_budget"] = 4000
        model["broker_contract"].update(backend="gateway-build-repair", thinking_token_budget=4000)
    if agent == "intake":
        approved_intake_budget(candidate)
    before = deepcopy(candidate)
    result = fixture.compare_review6_baseline(agent, candidate, "a" * 64, review_version=8)
    assert candidate == before
    assert result["declared_review8_difference"]["thinking_token_budget"] == (
        4000 if agent == "build-repair" else None
    )


@pytest.mark.parametrize(
    "change", ["cap", "thinking", "backend", "output", "budget", "price", "serial"]
)
def test_review8_rejects_undeclared_build_repair_changes(tmp_path, monkeypatch, change):
    candidate = comparison(tmp_path, monkeypatch, "build-repair")
    model = candidate["model"]
    model.update(
        backend_name="gateway-build-repair",
        resolved_model="gateway-build-repair:Qwen",
        pricing_table="sdk:pinned;models:new;backend:gateway-build-repair;custom:zero",
    )
    model["capability_profile"]["thinking_token_budget"] = 4000
    model["broker_contract"].update(backend="gateway-build-repair", thinking_token_budget=4000)
    if change == "cap":
        model["capability_profile"]["thinking_token_budget"] = 4001
        model["broker_contract"]["thinking_token_budget"] = 4001
    elif change == "thinking":
        model["capability_profile"]["enable_thinking"] = False
        model["broker_contract"]["enable_thinking"] = False
    elif change == "backend":
        model["backend_name"] = "gateway-intake"
        model["broker_contract"]["backend"] = "gateway-intake"
    elif change == "budget":
        candidate["budget"]["effective"]["max_input_tokens"] += 1
    elif change == "price":
        model["pricing_table"] += "changed"
    else:
        for key in ("requested_settings", "effective_settings"):
            model[key]["max_tokens" if change == "output" else "parallel_tool_calls"] = (
                999 if change == "output" else True
            )
        model["broker_contract"]["model_settings"] = deepcopy(model["effective_settings"])
    with pytest.raises(ValueError):
        fixture.compare_review6_baseline("build-repair", candidate, "a" * 64, review_version=8)


def review8_configuration(tmp_path, monkeypatch):
    cfg = v6_manifest(tmp_path).model_copy(update={"rerun": review8(tmp_path, monkeypatch)})
    models, catalog = candidate_files(cfg)
    for agent in {"intake", "probe-diagnosis", "verdict"}:
        models["agents"][agent] = {"backend": "gateway-intake"}
        catalog["profiles"][agent] = {**catalog["profiles"]["intake"]}
        catalog["agent_profiles"][agent] = agent
    models["backends"]["gateway-build-repair"] = {
        **models["backends"]["gateway"],
        "thinking_token_budget": 4000,
    }
    models["agents"]["build-repair"] = {"backend": "gateway-build-repair"}
    for mapping in models["model_catalog"].values():
        mapping["gateway-build-repair"] = cfg.model
    catalog["profiles"]["build-repair"] = {
        **catalog["profiles"][catalog["agent_profiles"]["build-repair"]],
        "backend_name": "gateway-build-repair",
        "thinking_token_budget": 4000,
    }
    catalog["agent_profiles"]["build-repair"] = "build-repair"
    return cfg, models, catalog


@pytest.mark.parametrize(
    "change", [None, "cap", "profile_cap", "thinking", "model", "clone", "route"]
)
def test_review8_resolves_current_three_plus_build_routes_without_clients(
    tmp_path, monkeypatch, change
):
    import openai

    cfg, models, catalog = review8_configuration(tmp_path, monkeypatch)
    if change == "cap":
        models["backends"]["gateway-build-repair"]["thinking_token_budget"] = 4001
    elif change == "profile_cap":
        catalog["profiles"]["build-repair"]["thinking_token_budget"] = 3999
    elif change == "thinking":
        models["backends"]["gateway-build-repair"]["enable_thinking"] = False
    elif change == "model":
        next(iter(models["model_catalog"].values()))["gateway-build-repair"] = "Other"
    elif change == "clone":
        models["backends"]["gateway-build-repair"]["min_max_tokens"] += 1
    elif change == "route":
        models["agents"]["build-repair"] = {"backend": "gateway-intake"}
    write_candidates(cfg, models, catalog)
    monkeypatch.setattr(
        openai, "AsyncOpenAI", lambda *a, **kw: pytest.fail("Provider client constructed")
    )
    if change:
        with pytest.raises(ValueError):
            fixture.verify_review5_configuration(cfg)
    else:
        resolved = fixture.verify_review5_configuration(cfg)
        assert len(resolved) == 11
        assert {a for a, v in resolved.items() if v["enable_thinking"] is False} == {
            "intake",
            "probe-diagnosis",
            "verdict",
        }
        assert resolved["build-repair"]["backend"] == "gateway-build-repair"
        assert resolved["build-repair"]["enable_thinking"] is None
        assert resolved["build-repair"]["thinking_token_budget"] == 4000


def approved_intake_budget(candidate):
    path = Path(__import__("os").environ["HARNESS_REAL_PROVIDER_BASELINE"])
    document = json.loads(path.read_text())
    budget = {
        "requested": {
            "max_requests": 4,
            "max_output_tokens": 64000,
            "max_input_tokens": 80000,
            "max_input_tokens_per_request": 20000,
            "max_tool_calls": 16,
            "max_cost_usd": 0.25,
        },
        "provider_output_floor": 16000,
        "formula_version": "fixed",
    }
    budget["scaled"] = deepcopy(budget["requested"])
    budget["effective"] = deepcopy(budget["requested"])
    for row in document["cases"]:
        if row["agent"] == "intake":
            row["config"]["budget"] = budget
    path.write_text(json.dumps(document))
    candidate["budget"] = deepcopy(budget)
    for section in ("requested", "scaled", "effective"):
        candidate["budget"][section].update(
            max_input_tokens=128000, max_input_tokens_per_request=32000
        )


@pytest.mark.parametrize(
    "section,key,value",
    [
        (section, key, value)
        for section in ("requested", "scaled", "effective")
        for key, value in (
            ("max_input_tokens", 128001),
            ("max_input_tokens_per_request", 32001),
            ("max_requests", 5),
            ("max_output_tokens", 64001),
            ("max_tool_calls", 17),
            ("max_cost_usd", 0.26),
        )
    ]
    + [(None, "provider_output_floor", 16001), (None, "formula_version", "changed")],
)
def test_review8_rejects_any_undeclared_intake_budget_change(
    tmp_path, monkeypatch, section, key, value
):
    candidate = comparison(tmp_path, monkeypatch, "intake")
    approved_intake_budget(candidate)
    target = candidate["budget"][section] if section else candidate["budget"]
    target[key] = value
    with pytest.raises(ValueError):
        fixture.compare_review6_baseline("intake", candidate, "a" * 64, review_version=8)


def test_review8_budget_change_is_declared_and_historical_review_rejects_it(tmp_path, monkeypatch):
    candidate = comparison(tmp_path, monkeypatch, "intake")
    approved_intake_budget(candidate)
    result = fixture.compare_review6_baseline("intake", candidate, "a" * 64, review_version=8)
    assert result["declared_intake_input_budget_difference"]["native"] == {
        "max_input_tokens": 128000,
        "max_input_tokens_per_request": 32000,
    }
    with pytest.raises(ValueError, match="Authored agent safety budget"):
        fixture.compare_review6_baseline("intake", candidate, "a" * 64, review_version=7)


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "wrong_state",
        "extra_unknown",
        "bad_request_hash",
        "bad_budget_hash",
        "lost_budget",
        "active",
        "native",
        "state_request_mismatch",
        "symlink",
    ],
)
def test_review8_rejects_union_not_in_full_seal(tmp_path, monkeypatch, change):
    value = review8(tmp_path, monkeypatch)
    path = Path(value.retained_terminal_seal_file)
    seal = json.loads(path.read_text())
    rid = value.retained_completed_request_ids[0]
    if change == "missing":
        del seal["states"][rid]
        del seal["requests"][rid]
    elif change == "wrong_state":
        seal["states"][rid] = "completion_unknown"
    elif change == "extra_unknown":
        seal["states"][hashlib.sha256(b"all-record-not-native-report").hexdigest()] = (
            "completion_unknown"
        )
    elif change == "bad_request_hash":
        seal["requests"][rid] = "invalid"
    elif change == "bad_budget_hash":
        seal["ledgers"]["root"] = "invalid"
    elif change == "lost_budget":
        seal["ledgers"] = {}
    elif change == "active":
        seal["active_lease_count"] = 1
    elif change == "native":
        seal["native_sandbox_count"] = 1
    elif change == "state_request_mismatch":
        del seal["requests"][rid]
    elif change == "symlink":
        target = path.with_name("target.json")
        path.rename(target)
        path.symlink_to(target)
    if change != "symlink":
        path.write_text(json.dumps(seal))
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    proof_path = Path(value.ledger_proof_file)
    proof = json.loads(proof_path.read_text())
    proof["baseline_seal_sha256"] = sha
    proof_path.write_text(json.dumps(proof))
    changed = value.model_copy(
        update={
            "retained_terminal_seal_sha256": sha,
            "ledger_proof_sha256": hashlib.sha256(proof_path.read_bytes()).hexdigest(),
        }
    )
    with pytest.raises(ValueError):
        fixture.verify_native_rerun(changed)
