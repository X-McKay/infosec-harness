"""Review5 permits exactly one intake reasoning change and finite fresh trials."""

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest
import yaml
from broker_real_provider_fixture import (
    CASES,
    NativeRerunAmendment,
    compare_manifest_baseline,
    selected_phases,
    verify_native_rerun,
    verify_review5_configuration,
)
from pydantic import ValidationError
from test_broker_profiles import _config
from test_broker_real_provider_check import (
    manifest,
    native_rerun,
    reviewed_output_rerun,
    reviewed_temporal_only_rerun,
    reviewed_transport_rerun,
)
from test_broker_thinking_control import thinking_baseline


def review5(tmp_path):
    old = reviewed_output_rerun(tmp_path)
    completed = old.retained_completed_request_ids + [
        hashlib.sha256(f"v5-saved-{i}".encode()).hexdigest() for i in range(82)
    ]
    reports = dict(old.prior_reports)
    for i in range(6):
        p = tmp_path / f"review5-retained-{i}.json"
        p.write_text(
            json.dumps(
                {
                    "ledger": {
                        "requests": [
                            {"request_id": rid, "state": "completed"}
                            for rid in completed[80:][i::6]
                        ]
                    }
                }
            )
        )
        reports[str(p)] = hashlib.sha256(p.read_bytes()).hexdigest()
    proof = Path(old.ledger_proof_file)
    proof.write_text(
        json.dumps(
            {
                "status": "passed",
                "unknown_request_ids": old.retained_unknown_request_ids,
                "completed_request_ids": completed,
                "unknown_holds_retained": True,
            }
        )
    )
    cause = Path(old.cause_resolution_file)
    cause.write_text(
        json.dumps(
            {
                "status": "passed",
                "reviewed": True,
                "boundary": "native-intake-nonthinking-and-reference-repair",
                "evidence_sha256": "a" * 64,
            }
        )
    )
    return NativeRerunAmendment.model_validate(
        {
            **old.model_dump(),
            "review_version": 5,
            "intake_enable_thinking": False,
            "retained_completed_count": 162,
            "retained_completed_request_ids": completed,
            "prior_reports": reports,
            "ledger_proof_sha256": hashlib.sha256(proof.read_bytes()).hexdigest(),
            "cause_resolution_sha256": hashlib.sha256(cause.read_bytes()).hexdigest(),
            "reason": "reviewed intake non-thinking and bounded reference repair; retain all outcomes; no unknown resend",
        }
    )


def v5_manifest(tmp_path):
    value = manifest(tmp_path).model_dump()
    rerun = review5(tmp_path)
    value.update(
        rerun=rerun.model_dump(),
        maximum_pilot_agent_trials=22,
        phases=["native-local", "native-temporal"],
        broker_models_config=str(tmp_path / "broker.yaml"),
        broker_config=str(tmp_path / "catalog.yaml"),
    )
    return type(manifest(tmp_path)).model_validate(value)


def test_review5_exact_scope_and_retained_union(tmp_path):
    value = review5(tmp_path)
    verify_native_rerun(value)
    assert (
        len(value.prior_reports),
        len(value.retained_unknown_request_ids),
        len(value.retained_completed_request_ids),
    ) == (18, 15, 162)
    assert (value.additional_trials, value.additional_graph_trials) == (22, 1)
    assert value.model_dump()["intake_enable_thinking"] is False
    config = v5_manifest(tmp_path)
    assert selected_phases(config, "all") == ("local", "temporal")
    with pytest.raises(ValueError, match="only fresh native"):
        selected_phases(config, "direct")


@pytest.mark.parametrize(
    "change",
    [
        {"intake_enable_thinking": None},
        {"intake_enable_thinking": True},
        {"intake_enable_thinking": 0},
        {"strict_closed_output_tools": False},
        {"retained_unknown_count": 14},
        {"retained_completed_count": 161},
        {"additional_trials": 11},
        {"additional_trials": 23},
        {"additional_graph_trials": 2},
        {"retained_local_report_file": "reuse-old-local"},
        {"baseline_report_sha256": "b" * 64},
        {"reason": "accept despite missing scores"},
    ],
)
def test_review5_rejects_any_undeclared_scope_or_retention_change(tmp_path, change):
    value = review5(tmp_path)
    with pytest.raises(ValidationError):
        NativeRerunAmendment.model_validate({**value.model_dump(), **change})


@pytest.mark.parametrize(
    "factory",
    [native_rerun, reviewed_transport_rerun, reviewed_output_rerun, reviewed_temporal_only_rerun],
)
def test_historical_reviews_omit_and_reject_reasoning_declaration(tmp_path, factory):
    value = factory(tmp_path)
    before = value.model_dump_json()
    assert "intake_enable_thinking" not in value.model_dump()
    assert (
        type(value)
        .model_validate({**value.model_dump(), "intake_enable_thinking": None})
        .model_dump_json()
        == before
    )
    with pytest.raises(ValidationError):
        type(value).model_validate({**value.model_dump(), "intake_enable_thinking": False})


def test_review5_reports_exact_intake_difference_without_mutation(tmp_path, monkeypatch):
    candidate = thinking_baseline(tmp_path, monkeypatch)
    before = deepcopy(candidate)
    result = compare_manifest_baseline(v5_manifest(tmp_path), "intake", candidate, "a" * 64)
    assert result["declared_output_shaping_difference"]["review_version"] == 5
    assert result["declared_reasoning_difference"]["review_version"] == 5
    assert result["declared_reasoning_difference"]["enable_thinking"] == {
        "baseline": None,
        "candidate": False,
    }
    assert candidate == before


@pytest.mark.parametrize("where", ["capability_profile", "broker_contract"])
def test_review5_rejects_thinking_changes_for_other_agents(tmp_path, monkeypatch, where):
    candidate = thinking_baseline(tmp_path, monkeypatch)
    candidate["model"].update(
        backend_name="gateway",
        resolved_model="gateway:Qwen3.6-35B-A3B-NVFP4",
        pricing_table="sdk:1:abc;models:new;backend:gateway;custom:zero",
    )
    candidate["model"]["capability_profile"].pop("enable_thinking")
    candidate["model"]["broker_contract"].pop("enable_thinking")
    candidate["model"][where]["enable_thinking"] = False
    with pytest.raises(ValueError, match="only for intake"):
        compare_manifest_baseline(v5_manifest(tmp_path), "recon", candidate, "a" * 64)


def candidate_files(config):
    base = {
        "kind": "openai_compatible",
        "transport": "brokered",
        "base_url": config.endpoint,
        "min_max_tokens": 16000,
        "strict_closed_output_tools": True,
    }
    models = {
        "backends": {"gateway": base, "gateway-intake": {**base, "enable_thinking": False}},
        "default_backend": "gateway",
        "agents": {"intake": {"backend": "gateway-intake"}},
        "model_catalog": {"sonnet": {"gateway": config.model, "gateway-intake": config.model}},
    }
    catalog = _config()
    for limits in (catalog["root_limits"], *catalog["agent_limits"].values()):
        limits["max_output_tokens"] = 64000
    profile = catalog["profiles"]["inference-only"]
    profile.update(endpoint=config.endpoint, min_max_tokens=16000, strict_closed_output_tools=True)
    catalog["profiles"]["intake"] = {
        **profile,
        "backend_name": "gateway-intake",
        "enable_thinking": False,
    }
    catalog["agent_profiles"]["intake"] = "intake"
    return models, catalog


def write_candidates(config, models, catalog):
    Path(config.broker_models_config).write_text(yaml.safe_dump(models))
    Path(config.broker_config).write_text(yaml.safe_dump(catalog))


def test_review5_side_effect_free_preflight_resolves_all_actual_agent_contracts(
    tmp_path, monkeypatch
):
    import openai

    config = v5_manifest(tmp_path)
    models, catalog = candidate_files(config)
    write_candidates(config, models, catalog)
    monkeypatch.setattr(
        openai,
        "AsyncOpenAI",
        lambda *a, **k: pytest.fail("Preflight must not construct provider clients"),
    )
    monkeypatch.setenv("HARNESS_MODEL_BACKEND", "untrusted-ambient-backend")
    contracts = verify_review5_configuration(config)
    assert set(contracts) == set(CASES)
    assert contracts["intake"]["backend"] == "gateway-intake"
    assert contracts["intake"]["enable_thinking"] is False
    assert all(
        v["backend"] == "gateway" and v["enable_thinking"] is None
        for k, v in contracts.items()
        if k != "intake"
    )


@pytest.mark.parametrize(
    "change",
    [
        "route",
        "default",
        "clone",
        "model",
        "intake_enabled",
        "other_thinking",
        "profile_backend",
        "profile_thinking",
        "profile_floor",
    ],
)
def test_review5_preflight_rejects_undeclared_routing_or_contract_change(tmp_path, change):
    config = v5_manifest(tmp_path)
    models, catalog = candidate_files(config)
    if change == "route":
        models["agents"]["recon"] = {"backend": "gateway-intake"}
    elif change == "default":
        models["default_backend"] = "gateway-intake"
    elif change == "clone":
        models["backends"]["gateway-intake"]["min_max_tokens"] = 17000
    elif change == "model":
        models["model_catalog"]["sonnet"]["gateway-intake"] = "other-model"
    elif change == "intake_enabled":
        models["backends"]["gateway-intake"]["enable_thinking"] = True
    elif change == "other_thinking":
        models["backends"]["gateway"]["enable_thinking"] = False
    elif change == "profile_backend":
        catalog["profiles"]["intake"]["backend_name"] = "gateway"
    elif change == "profile_thinking":
        catalog["profiles"]["inference-only"]["enable_thinking"] = False
    else:
        catalog["profiles"]["intake"]["min_max_tokens"] = 17000
    write_candidates(config, models, catalog)
    with pytest.raises(ValueError):
        verify_review5_configuration(config)


def test_review5_graph_freeze_resolves_contracts_before_creating_trial(tmp_path, monkeypatch):
    import broker_real_graph_fixture as graph

    config = v5_manifest(tmp_path)
    parent = tmp_path / ".harness/openshell-spike/live-qualification"
    parent.mkdir(parents=True)
    pilot = parent / "pilot.json"
    pilot.write_text(config.model_dump_json())
    monkeypatch.setattr(graph, "ROOT", tmp_path)
    calls = []

    def reject_contracts(_config):
        calls.append(1)
        raise ValueError("reviewed contract mismatch")

    import broker_real_provider_fixture as provider

    monkeypatch.setattr(provider, "verify_review5_configuration", reject_contracts)
    with pytest.raises(ValueError, match="reviewed contract mismatch"):
        graph.freeze(
            pilot, parent / "graph.json", "native", baseline_report=tmp_path / "baseline.json"
        )
    assert calls == [1]
    assert not (parent / "graph.json").exists() and not list(parent.glob("graph-native-*"))
