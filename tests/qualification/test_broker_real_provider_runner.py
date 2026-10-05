"""Offline regressions for the real-provider qualification validators, runner and pilot."""
from __future__ import annotations

import asyncio
import json
import os
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from broker_qualification_support import (
    ENDPOINT,
    MODEL,
    broker_catalog,
    manifest,
    manifest_values,
    models_config,
    reap,
    sleeping_child,
)
from pydantic import ValidationError

from infosec_harness.qualification.broker import pilot, runner, validators
from infosec_harness.qualification.broker.runner import (
    check_resolved_model,
    output_class,
    phase_environment,
    prepare_case,
    score_output,
    workflow_input,
)
from infosec_harness.qualification.broker.validators import (
    CASES,
    COMPARISON_MODEL_FIELDS,
    ROOT,
    WORKFLOW_NAME,
    RealProviderManifest,
    claim_phase,
    compare_baseline,
    selected_phases,
    sha256_file,
    verify_baseline_report,
    verify_configuration,
    verify_source,
)

# --- Manifest scope -------------------------------------------------------------------------


@pytest.mark.parametrize("field", ["endpoint", "model"])
def test_manifest_has_no_default_provider_endpoint_or_model(tmp_path, field):
    values = manifest_values(tmp_path)
    values.pop(field)
    with pytest.raises(ValidationError, match=rf"{field}\n\s+Field required"):
        RealProviderManifest.model_validate(values)


def _drop_verdict(values):
    values["cases"] = {k: v for k, v in CASES.items() if k != "verdict"}


def _change_case(values):
    values["cases"] = {**CASES, "verdict": "another-case"}


def _drop_dataset(values):
    values["datasets"].pop("verdict")


def _partial_digests(values):
    values["case_digests"] = {"intake": "a" * 64}


def _no_phases(values):
    values.update(phases=[], maximum_pilot_agent_trials=0)


def _reordered_phases(values):
    values.update(phases=["native-local", "direct"], maximum_pilot_agent_trials=22)


def _duplicate_phase(values):
    values.update(phases=["direct", "direct"], maximum_pilot_agent_trials=22)


def _unknown_phase(values):
    values.update(phases=["graph"], maximum_pilot_agent_trials=11)


def _extra_trials(values):
    values["maximum_pilot_agent_trials"] = 34


def _paid_input(values):
    values["pricing"]["input_per_mtok"] = 1.0


def _paid_output(values):
    values["pricing"]["output_per_mtok"] = 1.0


@pytest.mark.parametrize("change,message", [
    (_drop_verdict, "exactly one frozen case per registered agent"),
    (_change_case, "exactly one frozen case per registered agent"),
    (_drop_dataset, "Frozen datasets must cover every case"),
    (_partial_digests, "Case digests must cover every frozen case"),
    (_no_phases, "at least one phase"),
    (_reordered_phases, "ordered, duplicate-free subset"),
    (_duplicate_phase, "ordered, duplicate-free subset"),
    (_unknown_phase, "ordered, duplicate-free subset"),
    (_extra_trials, "one trial per case per phase"),
    (_paid_input, "input price must be zero"),
    (_paid_output, "output price must be zero"),
])
def test_manifest_scope_rules_report_their_own_clause(tmp_path, change, message):
    values = manifest_values(tmp_path)
    change(values)
    with pytest.raises(ValidationError, match=message):
        RealProviderManifest.model_validate(values)


@pytest.mark.parametrize("field,value", [("max_concurrency", 2), ("root_duration_seconds", 7201),
                                         ("root_duration_seconds", 0), ("version", 2)])
def test_manifest_cannot_add_concurrency_or_extend_duration(tmp_path, field, value):
    with pytest.raises(ValidationError, match=field):
        RealProviderManifest.model_validate(manifest_values(tmp_path, **{field: value}))


def test_phase_selection_is_limited_to_declared_phases(tmp_path):
    config = manifest(tmp_path, phases=["direct", "native-local"], maximum_pilot_agent_trials=22)
    assert selected_phases(config, "validate") == ()
    assert selected_phases(config, "all") == ("direct", "native-local")
    assert selected_phases(config, "local") == ("native-local",)
    with pytest.raises(ValueError, match="Phase native-temporal is not declared by the manifest"):
        selected_phases(config, "temporal")
    with pytest.raises(ValueError, match="Unknown qualification phase"):
        selected_phases(config, "graph")


# --- Frozen cases and scoring ---------------------------------------------------------------


@pytest.mark.parametrize("agent", tuple(CASES))
def test_frozen_case_inputs_keep_ground_truth_and_credentials_host_only(tmp_path, agent):
    inputs, _predict, expected, case_digest = prepare_case(agent, manifest(tmp_path))
    public = workflow_input(inputs)
    assert set(public) == {"agent", "prompt", "deps"}
    assert set(inputs) == {"agent", "prompt", "deps"}
    assert len(case_digest) == 64 and expected
    assert "expected" not in public and "predict" not in public
    assert "offline-test-key-never-in-workflow" not in json.dumps(public)
    assert "broker_binding" not in public["deps"] and "broker_contract" not in public["deps"]


@pytest.mark.parametrize("field,value,message", [
    ("sha256", "0" * 64, "provenance changed: content differs"),
    ("case", "another-case", "provenance changed: case differs"),
    ("path", "/elsewhere/dataset.yaml", "provenance changed: path differs"),
    ("version", "999", "Frozen dataset version changed"),
])
def test_changed_dataset_provenance_fails_before_any_execution(tmp_path, field, value, message):
    config = manifest(tmp_path)
    datasets = dict(config.datasets)
    datasets["context"] = datasets["context"].model_copy(update={field: value})
    with pytest.raises(ValueError, match=message):
        prepare_case("context", config.model_copy(update={"datasets": datasets}))


def test_changed_frozen_case_digest_fails(tmp_path):
    config = manifest(tmp_path, case_digests=dict.fromkeys(CASES, "a" * 64))
    with pytest.raises(ValueError, match="Frozen case content changed"):
        prepare_case("context", config)


def test_semantic_failure_keeps_original_expected_and_typed_output(tmp_path):
    from infosec_harness.domain.models import RepoProfile
    _inputs, predict, expected, _digest = prepare_case("recon", manifest(tmp_path))
    output = RepoProfile(summary="a Python repository", primary_language="python",
                         test_framework="unknown", test_layout="tests")
    result = score_output("recon", output, predict, expected)
    assert result["semantic_score"] == "failed"
    assert result["expected"] == "python/pytest"
    assert result["predicted"] == "python/unknown"
    assert result["typed_output"]["test_framework"] == "unknown"


@pytest.mark.parametrize("agent", tuple(CASES))
def test_output_matcher_covers_all_current_agent_contracts(agent):
    from infosec_harness.domain.models import (
        EnvironmentSpec,
        ExtractedFinding,
        ProbeDiagnosis,
        ProbePlan,
        ProbeSource,
        RepoProfile,
    )
    from infosec_harness.runtime.outputs import (
        ContextOutput,
        InconclusiveOutput,
        PartialEnvironmentOutput,
        PlannedEnvironmentOutput,
    )
    expected = {
        "intake": ExtractedFinding, "recon": RepoProfile,
        "env-planner": PlannedEnvironmentOutput, "build-repair": EnvironmentSpec,
        "partial-build": PartialEnvironmentOutput, "context": ContextOutput,
        "probe-planner": ProbePlan, "probe-author": ProbeSource,
        "probe-diagnosis": ProbeDiagnosis, "probe-repair": ProbeSource,
        "verdict": InconclusiveOutput,
    }
    assert set(expected) == set(CASES)
    assert output_class(agent) is expected[agent]


def test_env_planner_accepts_current_required_install_output():
    from infosec_harness.evals.adapters import _ecosystem_label
    from infosec_harness.runtime.outputs import PlannedEnvironmentOutput

    output = PlannedEnvironmentOutput(base_image="python:3.12-slim", install_commands=[],
                                      test_command="python -m pytest {test_file}")
    result = score_output("env-planner", output, _ecosystem_label, "python/pytest")
    assert result["output_type"] == "PlannedEnvironmentOutput"
    assert result["semantic_score"] == "passed"
    assert result["typed_output"]["install_commands"] == []


def test_env_planner_rejects_domain_type_despite_equal_fields():
    from infosec_harness.domain.models import EnvironmentSpec
    from infosec_harness.evals.adapters import _ecosystem_label

    output = EnvironmentSpec(base_image="python:3.12-slim", install_commands=[],
                             test_command="python -m pytest {test_file}")
    with pytest.raises(ValueError, match="Registered output type differs"):
        score_output("env-planner", output, _ecosystem_label, "python/pytest")


def test_temporal_env_planner_reconstruction_preserves_required_install_contract():
    from infosec_harness.runtime.outputs import PlannedEnvironmentOutput

    serialized = {"base_image": "python:3.12-slim", "install_commands": [],
                  "test_command": "python -m pytest {test_file}"}
    output = output_class("env-planner").model_validate(serialized)
    assert type(output) is PlannedEnvironmentOutput
    assert "install_commands" in output.model_fields_set
    incomplete = dict(serialized)
    del incomplete["install_commands"]
    with pytest.raises(ValidationError) as error:
        output_class("env-planner").model_validate(incomplete)
    assert [(entry["loc"], entry["type"]) for entry in error.value.errors()] == [
        (("install_commands",), "missing")]


# --- Phase environment ----------------------------------------------------------------------


def test_worker_environment_removes_provider_keys_and_native_admin(tmp_path, monkeypatch):
    config = manifest(tmp_path)
    for key in ("HARNESS_OPENAI_API_KEY", "OPENAI_API_KEY", "HARNESS_BROKER_NATIVE_CONFIG",
                "HARNESS_MODEL_BACKEND", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.setenv(key, "must-not-reach-worker")
    values = phase_environment(config, "local")
    assert "must-not-reach-worker" not in values.values()
    assert values["HARNESS_BROKER_WORKER_KEY"] == "offline-test-key-never-in-workflow"
    assert values["HARNESS_BROKER_CONFIG"] == config.broker_config
    assert values["HARNESS_MODELS_CONFIG"] == config.broker_models_config
    assert values["HARNESS_SANDBOX_RUNTIME"] == "runsc"
    assert values["HARNESS_ALLOW_INSECURE_RUNTIME"] == "false"
    assert values["PATH"].split(os.pathsep)[0] == str(ROOT / ".harness/bin")
    assert values["PYTHONPATH"] == str(ROOT / "src")


def test_direct_baseline_never_receives_broker_authority(tmp_path, monkeypatch):
    config = manifest(tmp_path)
    monkeypatch.setenv(config.worker_hmac_env, "inherited-broker-authority")
    monkeypatch.setenv("HARNESS_BROKER_CONFIG", "inherited-catalog")
    values = phase_environment(config, "direct")
    assert config.worker_hmac_env not in values
    assert "HARNESS_BROKER_CONFIG" not in values
    assert values["HARNESS_MODELS_CONFIG"] == config.direct_models_config
    assert values["HARNESS_DATABASE_URL"] == "sqlite+aiosqlite:///:memory:"


def test_native_phase_requires_owner_only_worker_key(tmp_path):
    config = manifest(tmp_path)
    Path(config.worker_hmac_file).chmod(0o644)
    with pytest.raises(ValueError, match="Worker HMAC reference must be owner-only"):
        phase_environment(config, "local")


# --- Source and configuration preflight -----------------------------------------------------


@pytest.mark.parametrize("head,clean,message", [
    ("d" * 40, True, "source commit differs from the checkout HEAD"),
    ("0" * 40, False, "uncommitted tracked changes"),
])
def test_source_requires_exact_clean_head(tmp_path, monkeypatch, head, clean, message):
    monkeypatch.setattr(validators, "git_observation", lambda: (head, clean))
    with pytest.raises(ValueError, match=message):
        verify_source(manifest(tmp_path))


def test_source_accepts_exact_clean_head_and_git_observation_is_readonly(tmp_path, monkeypatch):
    monkeypatch.setattr(validators, "git_observation", lambda: ("0" * 40, True))
    verify_source(manifest(tmp_path))
    monkeypatch.undo()
    calls = []
    outputs = iter(["a" * 40 + "\n", ""])

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(stdout=next(outputs))

    monkeypatch.setattr(validators, "ROOT", tmp_path)
    monkeypatch.setattr(validators.subprocess, "run", run)
    assert validators.git_observation() == ("a" * 40, True)
    assert [call[0] for call in calls] == [["git", "rev-parse", "HEAD"],
                                           ["git", "status", "--porcelain", "--untracked-files=no"]]
    assert all(kwargs == {"cwd": tmp_path, "check": True, "capture_output": True, "text": True, "timeout": 10}
               for _, kwargs in calls)


def test_configuration_resolves_every_route_without_clients_or_ambient_backend(tmp_path, monkeypatch):
    import openai

    monkeypatch.setattr(openai, "AsyncOpenAI", lambda *a, **k: pytest.fail("Preflight constructed a client"))
    monkeypatch.setenv("HARNESS_MODEL_BACKEND", "untrusted-ambient-backend")
    routes = verify_configuration(manifest(tmp_path))
    assert routes == dict.fromkeys(CASES, {"backend": "gateway", "profile": "inference-only"})


def _write(path, value):
    Path(path).write_text(yaml.safe_dump(value))


def _direct_brokered(config):
    _write(config.direct_models_config, models_config("brokered"))


def _native_direct(config):
    _write(config.broker_models_config, models_config("direct"))


def _direct_endpoint(config):
    _write(config.direct_models_config, models_config("direct", endpoint="https://other.test/v1"))


def _native_model(config):
    _write(config.broker_models_config, models_config("brokered", model="other-model"))


def _native_missing_backend(config):
    value = models_config("brokered")
    value["default_backend"] = "missing"
    _write(config.broker_models_config, value)


def _renamed_native_backend(config):
    value = models_config("brokered")
    value["backends"]["renamed"] = value["backends"].pop("gateway")
    value.update(default_backend="renamed",
                 model_catalog={tier: {"renamed": MODEL} for tier in ("sonnet", "opus", "haiku")})
    _write(config.broker_models_config, value)


def _disabled_catalog(config):
    _write(config.broker_config, {**broker_catalog(), "enabled": False})


def _profile_backend(config):
    value = broker_catalog()
    value["profiles"]["inference-only"]["backend_name"] = "other"
    _write(config.broker_config, value)


def _profile_endpoint(config):
    _write(config.broker_config, broker_catalog(endpoint="https://other.test/v1"))


def _symlinked_catalog(config):
    target = Path(config.broker_config).with_name("real-catalog.yaml")
    Path(config.broker_config).rename(target)
    Path(config.broker_config).symlink_to(target)


@pytest.mark.parametrize("change,message", [
    (_direct_brokered, "direct backend 'gateway' must use direct transport"),
    (_native_direct, "native backend 'gateway' must use brokered transport"),
    (_direct_endpoint, "direct backend 'gateway' endpoint differs from the manifest endpoint"),
    (_native_model, "native backend 'gateway' resolves intake to a model other than the manifest model"),
    (_native_missing_backend, "native configuration has no backend 'missing' for intake"),
    (_renamed_native_backend, "Direct and native routes for intake must use the same backend name"),
    (_disabled_catalog, "Broker catalog must be enabled"),
    (_profile_backend, "Broker profile 'inference-only' does not admit backend 'gateway' for intake"),
    (_profile_endpoint, "Broker profile 'inference-only' endpoint differs from the manifest endpoint"),
    (_symlinked_catalog, "must be a regular file"),
])
def test_configuration_rules_report_their_own_clause(tmp_path, change, message):
    config = manifest(tmp_path)
    change(config)
    with pytest.raises(ValueError, match=message):
        verify_configuration(config)


def _resolved(**changes):
    values = {"endpoint": ENDPOINT, "resolved_model": "gateway:" + MODEL, "broker_contract": object()}
    values.update(changes)
    return SimpleNamespace(**values)


@pytest.mark.parametrize("phase,model,message", [
    ("local", _resolved(endpoint="https://other.test/v1"), "endpoint differs from the manifest endpoint"),
    ("local", _resolved(resolved_model="gateway:other"), "Resolved model differs from the manifest model"),
    ("direct", _resolved(), "Direct phase resolved a brokered model transport"),
    ("local", _resolved(broker_contract=None), "Native phase resolved a direct model transport"),
])
def test_resolved_runtime_route_must_match_manifest_and_phase(tmp_path, phase, model, message):
    with pytest.raises(ValueError, match=message):
        check_resolved_model(manifest(tmp_path), phase, model)
    check_resolved_model(manifest(tmp_path), "local", _resolved())
    check_resolved_model(manifest(tmp_path), "direct", _resolved(broker_contract=None))


# --- Direct baseline comparison -------------------------------------------------------------


def comparable():
    model = dict.fromkeys(COMPARISON_MODEL_FIELDS, "frozen")
    model.update(capability_profile={"tool_calling": True},
                 pricing_table="genai-prices:1:abc;models:direct;backend:gateway;custom:zero")
    return {"model": model, "budget": {"requested": {"max_requests": 16}, "effective": {"max_requests": 16}}}


def write_baseline(tmp_path, monkeypatch, *, config=None, **report):
    rows = [{"agent": agent, "case": case, "case_digest": "a" * 64, "config": config or comparable()}
            for agent, case in CASES.items()]
    value = {"phase": "direct", "status": "passed", "cases": rows, **report}
    path = tmp_path / "direct.json"
    path.write_text(json.dumps(value))
    monkeypatch.setenv("HARNESS_REAL_PROVIDER_BASELINE", str(path))
    return path


def test_native_comparison_permits_only_transport_fields(tmp_path, monkeypatch):
    write_baseline(tmp_path, monkeypatch)
    candidate = comparable()
    candidate["model"].update(durable=True, broker_contract={"backend": "gateway"},
                              credential_reference="openshell:resolve:env:PROVIDER")
    result = compare_baseline("intake", candidate, "a" * 64)
    assert result["status"] == "passed" and result["authored_budget"] == "matched"
    assert result["pricing_catalog_provenance"] is None
    assert result["intentional_transport_fields"]["durable"] is True


def test_native_comparison_retains_catalog_provenance(tmp_path, monkeypatch):
    write_baseline(tmp_path, monkeypatch)
    candidate = comparable()
    candidate["model"]["pricing_table"] = "genai-prices:1:abc;models:native;backend:gateway;custom:zero"
    result = compare_baseline("intake", candidate, "a" * 64)
    assert result["pricing_catalog_provenance"]["direct"] == comparable()["model"]["pricing_table"]
    assert result["pricing_catalog_provenance"]["native"] == candidate["model"]["pricing_table"]


def _set(path, value):
    def change(config):
        target = config
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
    return change


@pytest.mark.parametrize("change,message", [
    (_set(("model", "effective_settings"), "different"), "Baseline model field effective_settings differs"),
    (_set(("model", "endpoint"), "https://other.test/v1"), "Baseline model field endpoint differs"),
    (_set(("model", "resolved_model"), "gateway:other"), "Baseline model field resolved_model differs"),
    (_set(("model", "capability_profile"), {"tool_calling": True, "strict_closed_output_tools": True}),
     "Baseline capability profile differs"),
    (_set(("budget", "requested", "max_requests"), 17), "Authored agent safety budget differs"),
    (_set(("budget", "effective", "max_requests"), 17), "Authored agent safety budget differs"),
    (_set(("model", "pricing_table"), "genai-prices:1:abc;models:native;backend:gateway;custom:paid"),
     "Baseline pricing differs"),
    (_set(("model", "pricing_table"), "genai-prices:2:abc;models:native;backend:gateway;custom:zero"),
     "Baseline pricing differs"),
    (_set(("model", "pricing_table"), "genai-prices:1:abc;models:native;backend:other;custom:zero"),
     "Baseline pricing differs"),
])
def test_native_comparison_rejects_each_undeclared_difference(tmp_path, monkeypatch, change, message):
    write_baseline(tmp_path, monkeypatch)
    candidate = deepcopy(comparable())
    change(candidate)
    with pytest.raises(ValueError, match=message):
        compare_baseline("intake", candidate, "a" * 64)


@pytest.mark.parametrize("report,digest,message", [
    ({"phase": "local"}, "a" * 64, "not a direct phase report"),
    ({"status": "failed"}, "a" * 64, "Baseline direct phase did not pass"),
    ({}, "b" * 64, "Baseline case content for intake differs"),
])
def test_native_comparison_requires_a_passed_matching_direct_baseline(tmp_path, monkeypatch, report, digest, message):
    write_baseline(tmp_path, monkeypatch, **report)
    with pytest.raises(ValueError, match=message):
        compare_baseline("intake", comparable(), digest)


def test_native_comparison_requires_a_baseline_covering_every_case(tmp_path, monkeypatch):
    path = write_baseline(tmp_path, monkeypatch)
    value = json.loads(path.read_text())
    value["cases"].pop()
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="cover every frozen case exactly once"):
        compare_baseline("intake", comparable(), "a" * 64)
    monkeypatch.delenv("HARNESS_REAL_PROVIDER_BASELINE")
    with pytest.raises(ValueError, match="requires a completed direct baseline"):
        compare_baseline("intake", comparable(), "a" * 64)


def test_temporal_case_config_keeps_full_source_size_budget_comparison(tmp_path, monkeypatch):
    from infosec_harness.runtime.budgets import BASELINE_SOURCE_FILES
    from infosec_harness.runtime.durable import CONFIGS

    inputs, _, _, case_digest = prepare_case("recon", manifest(tmp_path))
    scoped = runner.temporal_case_config("recon", inputs)
    assert scoped == CONFIGS["recon"].for_source_files(inputs["deps"].source_files)
    assert scoped.budget.source_files == inputs["deps"].source_files
    rows = [{"agent": agent, "case": case, "case_digest": case_digest, "config": scoped.model_dump(mode="json")}
            for agent, case in CASES.items()]
    path = tmp_path / "scoped-budget-baseline.json"
    path.write_text(json.dumps({"phase": "direct", "status": "passed", "cases": rows}))
    monkeypatch.setenv("HARNESS_REAL_PROVIDER_BASELINE", str(path))
    assert compare_baseline("recon", scoped.model_dump(mode="json"), case_digest)["authored_budget"] == "matched"
    changed = CONFIGS["recon"].for_source_files(BASELINE_SOURCE_FILES * 4)
    assert changed.budget.effective != scoped.budget.effective
    with pytest.raises(ValueError, match="Authored agent safety budget"):
        compare_baseline("recon", changed.model_dump(mode="json"), case_digest)


# --- Phase claims ---------------------------------------------------------------------------


def test_phase_claim_is_single_use_and_keeps_other_phase_available(tmp_path):
    claim_phase(tmp_path, "a" * 64, "native-local")
    with pytest.raises(FileExistsError):
        claim_phase(tmp_path, "a" * 64, "native-local")
    claim_phase(tmp_path, "a" * 64, "native-temporal")
    with pytest.raises(ValueError, match="Unknown qualification phase"):
        claim_phase(tmp_path, "a" * 64, "graph")


def test_phase_claim_has_one_concurrent_winner(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    barrier = Barrier(4)

    def attempt():
        barrier.wait()
        try:
            claim_phase(tmp_path, "c" * 64, "native-local")
        except FileExistsError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(lambda _: attempt(), range(4))).count(True) == 1


# --- Local and Temporal phases --------------------------------------------------------------


async def test_local_failure_retains_closed_output_observations_without_response_text(monkeypatch):
    from pydantic_ai import _agent_graph
    from pydantic_ai.exceptions import UnexpectedModelBehavior
    from pydantic_ai.messages import ModelRequest, ModelResponse, RetryPromptPart, ToolCallPart

    from infosec_harness.graph import ops
    from infosec_harness.runtime import registry
    from infosec_harness.runtime.deps import AgentDeps

    deps = AgentDeps(repo_path="/snapshot", report_text="SECRET_FINDING")
    selected = {"effective_spec": {"metadata": {"intake_output": {"protocol": "intake-atomic-claims/v2"}}}}
    config = SimpleNamespace(model=_resolved(broker_contract=None), model_dump=lambda **_kwargs: selected)
    closed = []

    class FakeOps:
        def __init__(self, **_kwargs):
            pass

        async def run_agent(self, *_args):
            # Inject a mock SDK trace into the actual outer capture context; no agent/model runs.
            _agent_graph.get_captured_run_messages().messages.extend([
                ModelResponse(parts=[ToolCallPart("final_result", {"file_path": "SECRET_MODEL"})]),
                ModelRequest(parts=[RetryPromptPart([{"type": "missing", "loc": ("file_path", "source"),
                    "msg": "SECRET_RETRY", "input": "SECRET_INPUT"}], tool_name="final_result")]),
            ])
            raise UnexpectedModelBehavior("SECRET_EXCEPTION", body="SECRET_BODY")

        async def close(self):
            closed.append(True)

    monkeypatch.setattr(ops, "LocalOps", FakeOps)
    monkeypatch.setattr(registry, "load_spec", lambda *_args: None)
    monkeypatch.setattr(registry, "resolve_agent_config", lambda *_args, **_kwargs: config)
    monkeypatch.setattr(runner, "prepare_case", lambda *_args: ({"prompt": [], "deps": deps}, None, "frozen", "a" * 64))
    row = await runner.run_local_case(SimpleNamespace(cases={"intake": "synthetic"}, endpoint=ENDPOINT, model=MODEL),
                                      "direct", "intake")
    assert row["execution"] == "failed" and row["cleanup"] == "passed"
    assert row["failure_type"] == "UnexpectedModelBehavior"
    assert row["failure_diagnostic"]["error_type"] == "unknown"
    assert row["output_retry_summary"]["output_schema_retry_parts"] == 1
    assert row["intake_field_summary"]["proposals_observed"] == 1
    assert row["intake_field_summary"]["rejection_category_counts"]["schema_invalid"] == 1
    assert "SECRET" not in json.dumps(row)
    assert closed == [True]


async def test_local_case_refuses_a_foreign_route_before_running_the_agent(monkeypatch):
    from infosec_harness.graph import ops
    from infosec_harness.runtime import registry
    from infosec_harness.runtime.deps import AgentDeps

    config = SimpleNamespace(model=_resolved(endpoint="https://other.test/v1", broker_contract=None),
                             model_dump=lambda **_kwargs: {})

    class FakeOps:
        def __init__(self, **_kwargs):
            pass

        async def run_agent(self, *_args):
            pytest.fail("A foreign route reached the agent")

        async def close(self):
            return None

    monkeypatch.setattr(ops, "LocalOps", FakeOps)
    monkeypatch.setattr(registry, "load_spec", lambda *_args: None)
    monkeypatch.setattr(registry, "resolve_agent_config", lambda *_args, **_kwargs: config)
    monkeypatch.setattr(runner, "prepare_case", lambda *_args: (
        {"prompt": [], "deps": AgentDeps(repo_path="/snapshot")}, None, "frozen", "a" * 64))
    row = await runner.run_local_case(SimpleNamespace(cases={"context": "synthetic"}, endpoint=ENDPOINT, model=MODEL),
                                      "direct", "context")
    assert row["execution"] == "failed" and row["failure_type"] == "ValueError"


def native_configs(monkeypatch, configuration):
    """Patch the accepted durable configs so they resolve to the manifest's brokered route."""
    # Bind the workflow's module-level config references before the patch, never to it.
    import infosec_harness.qualification.broker.workflow  # noqa: F401
    from infosec_harness.inference.catalog.profiles import BrokerConfig
    from infosec_harness.inference.models import BackendConfig
    from infosec_harness.runtime import durable

    contract = BrokerConfig.model_validate(broker_catalog()).resolve_contract(
        "context", "gateway", MODEL, {"max_tokens": 1024},
        backend=BackendConfig(kind="openai_compatible", transport="brokered", base_url=ENDPOINT))
    configs = {name: value.model_copy(update={"model": value.model.model_copy(update={
        "endpoint": ENDPOINT, "resolved_model": "gateway:" + MODEL, "broker_contract": contract})})
        for name, value in durable.CONFIGS.items()}
    monkeypatch.setattr(durable, "CONFIGS", configs)
    rows = []
    for name, value in configs.items():
        inputs, _predict, _expected, digest = prepare_case(name, configuration)
        rows.append({"agent": name, "case": CASES[name], "case_digest": digest,
                     "config": value.for_source_files(inputs["deps"].source_files).model_dump(mode="json")})
    baseline = Path(configuration.report_directory) / "baseline.json"
    baseline.write_text(json.dumps({"phase": "direct", "status": "passed", "cases": rows}))
    monkeypatch.setenv("HARNESS_REAL_PROVIDER_BASELINE", str(baseline))
    monkeypatch.setenv("HARNESS_REAL_PROVIDER_MANIFEST", "offline-manifest")


async def test_temporal_connect_failure_reaps_its_owned_worker(tmp_path, monkeypatch):
    from temporalio.client import Client

    configuration = manifest(tmp_path)
    native_configs(monkeypatch, configuration)
    children = []

    def start_owned_child(*_args, **kwargs):
        assert not kwargs.get("start_new_session", False)
        child = sleeping_child(stdout=kwargs["stdout"], stderr=kwargs["stderr"])
        children.append(child)
        assert os.getpgid(child.pid) == os.getpgrp()
        return child

    async def disconnected(*_args, **_kwargs):
        raise ConnectionError("offline startup failure")

    monkeypatch.setattr(runner.subprocess, "Popen", start_owned_child)
    monkeypatch.setattr(Client, "connect", disconnected)
    report_path = tmp_path / "temporal.json"
    try:
        result = await runner.run_temporal(configuration, report_path)
        assert result["status"] == "failed" and result["failure_type"] == "ConnectionError"
        assert result["worker_cleanup"] == "passed"
        assert result["cases"] == []
        assert len(children) == 1 and children[0].poll() is not None
        assert json.loads(report_path.read_text())["execution_status"] == "failed"
    finally:
        reap(children)


@pytest.mark.parametrize("before_handle_return", [False, True])
async def test_cancelled_temporal_trial_terminates_current_workflow_and_reaps_worker(
        tmp_path, monkeypatch, before_handle_return):
    from temporalio.client import Client
    from temporalio.worker import Replayer

    configuration = manifest(tmp_path)
    native_configs(monkeypatch, configuration)
    children = []

    def start_owned_child(*_args, **_kwargs):
        child = sleeping_child(start_new_session=True)
        children.append(child)
        return child

    monkeypatch.setattr(runner.subprocess, "Popen", start_owned_child)
    started = asyncio.Event()
    terminated = []

    class Handle:
        id = "batch:owned-cancelled-fixture"
        first_execution_run_id = "owned-run-id"

        async def result(self):
            started.set()
            await asyncio.Future()

        async def terminate(self, _reason):
            terminated.append(self.id)

        async def fetch_history(self):
            return SimpleNamespace(to_json=lambda: "{}", events=[])

    submissions = {}

    async def start(*_args, **kwargs):
        submissions.update(kwargs)
        if before_handle_return:
            started.set()
            await asyncio.Future()
        return Handle()

    async def describe():
        return SimpleNamespace(id=submissions["id"], task_queue=submissions["task_queue"],
                               workflow_type=WORKFLOW_NAME, run_id=Handle.first_execution_run_id)

    def get_handle(workflow_id, **kwargs):
        assert workflow_id == submissions["id"]
        if not kwargs:
            return SimpleNamespace(describe=describe)
        assert kwargs == {"run_id": Handle.first_execution_run_id,
                          "first_execution_run_id": Handle.first_execution_run_id}
        return Handle()

    async def connect(*_args, **_kwargs):
        return SimpleNamespace(start_workflow=start, get_workflow_handle=get_handle)

    async def seed(*_args, **_kwargs):
        return None

    async def snapshot(root):
        return {"root_id": root, "root_state": {"operations": {}}, "requests": [], "request_states": {}}

    async def replay(*_args, **_kwargs):
        return None

    monkeypatch.setattr(Client, "connect", connect)
    monkeypatch.setattr(runner, "seed_root", seed)
    monkeypatch.setattr(runner, "ledger_snapshot", snapshot)
    monkeypatch.setattr(Replayer, "replay_workflow", replay)
    path = tmp_path / "temporal.json"
    try:
        task = asyncio.create_task(runner.run_temporal(configuration, path))
        await asyncio.wait_for(started.wait(), 10)
        task.cancel()
        result = await asyncio.wait_for(task, 10)
        assert terminated == [Handle.id]
        assert result["status"] == result["execution_status"] == "failed"
        assert result["interrupted"] is True and result["worker_cleanup"] == "passed"
        assert len(result["cases"]) == 1 and result["cases"][0]["failure_type"] == "CancelledError"
        assert len(children) == 1 and children[0].poll() is not None
        if before_handle_return:
            assert result["cases"][0]["submission_recovery"] == "passed"
        assert json.loads(path.read_bytes())["status"] == "failed"
    finally:
        reap(children)


@pytest.mark.parametrize("field,value,message", [
    ("id", "foreign", "workflow id"), ("task_queue", "foreign", "task queue"),
    ("workflow_type", "ForeignWorkflow", "workflow type"), ("run_id", "", "missing run id"),
])
async def test_submission_recovery_rejects_foreign_scope_before_creating_mutation_handle(field, value, message):
    values = {"id": "batch:owned", "task_queue": "owned-queue", "workflow_type": WORKFLOW_NAME, "run_id": "owned-run"}
    values[field] = value

    async def describe():
        return SimpleNamespace(**values)

    def get_handle(workflow_id, **kwargs):
        assert workflow_id == "batch:owned" and not kwargs
        return SimpleNamespace(describe=describe)

    with pytest.raises(ValueError, match=f"ownership differs: {message}"):
        await runner.recover_owned_submission(SimpleNamespace(get_workflow_handle=get_handle), "batch:owned", "owned-queue")


@pytest.mark.parametrize("class_name_alias", [False, True])
async def test_submission_recovery_uses_actual_registered_workflow_name(class_name_alias):
    from temporalio import workflow

    from infosec_harness.qualification.broker.workflow import RealProviderWorkflow

    assert workflow._Definition.must_from_class(RealProviderWorkflow).name == WORKFLOW_NAME
    calls = []
    description = SimpleNamespace(id="batch:owned", task_queue="own-queue", run_id="own-run",
        workflow_type=RealProviderWorkflow.__name__ if class_name_alias else WORKFLOW_NAME)

    async def describe():
        return description

    recovered = object()

    def get_handle(workflow_id, **kwargs):
        calls.append((workflow_id, kwargs))
        return recovered if kwargs else SimpleNamespace(describe=describe)

    client = SimpleNamespace(get_workflow_handle=get_handle)
    if class_name_alias:
        with pytest.raises(ValueError, match="ownership differs: workflow type"):
            await runner.recover_owned_submission(client, "batch:owned", "own-queue")
        assert len(calls) == 1
    else:
        assert await runner.recover_owned_submission(client, "batch:owned", "own-queue") is recovered
        assert calls[-1] == ("batch:owned", {"run_id": "own-run", "first_execution_run_id": "own-run"})


async def test_qualification_workflow_runs_the_current_production_intake_config(monkeypatch):
    from infosec_harness.qualification.broker.workflow import RealProviderWorkflow
    from infosec_harness.runtime.durable import CONFIGS
    from infosec_harness.workflows.accounting import RootAccounting

    class AccountingObserved(Exception):
        pass

    observed = []

    async def observe_reserve(self, config, **kwargs):
        observed.append((self.root_id, config.agent_name, kwargs["configuration_digest"]))
        raise AccountingObserved

    monkeypatch.setattr(RootAccounting, "reserve", observe_reserve)
    with pytest.raises(AccountingObserved):
        await RealProviderWorkflow().run({"agent": "intake", "prompt": ["synthetic input"],
                                          "deps": {"repo_path": "/snapshot"}, "root_id": "broker-real-test"})
    assert observed == [("broker-real-test", "intake", CONFIGS["intake"].digest)]


@pytest.mark.parametrize("part", [{"kind": "image"}, {"kind": "cache-point", "ttl": "1d"}, 7])
async def test_qualification_workflow_rejects_unexpected_prompt_content(part):
    from infosec_harness.qualification.broker.workflow import RealProviderWorkflow

    with pytest.raises(ValueError, match="Unexpected public prompt content"):
        await RealProviderWorkflow().run({"agent": "intake", "prompt": [part], "deps": {"repo_path": "/snapshot"},
                                          "root_id": "broker-real-test"})


@pytest.mark.parametrize("root_id", [None, "batch-foreign", 7])
async def test_qualification_workflow_requires_its_owned_root(root_id):
    from infosec_harness.qualification.broker.workflow import RealProviderWorkflow

    with pytest.raises(ValueError, match="requires its owned qualification root"):
        await RealProviderWorkflow().run({"agent": "intake", "prompt": ["synthetic input"],
                                          "deps": {"repo_path": "/snapshot"}, "root_id": root_id})


# --- Pilot orchestration --------------------------------------------------------------------


def frozen_manifest(tmp_path, monkeypatch, **overrides):
    monkeypatch.setattr(pilot, "ROOT", tmp_path)
    monkeypatch.setattr(pilot, "verify_source", lambda _manifest: None)
    path = tmp_path / "manifest.json"
    path.write_text(manifest(tmp_path, **overrides).model_dump_json())
    return path, sha256_file(path)


def run_pilot(capsys, *argv):
    try:
        code = pilot.main(list(argv))
    except SystemExit as error:
        code = error.code
    return code, capsys.readouterr()


def test_pilot_validate_checks_everything_without_provider_calls(tmp_path, monkeypatch, capsys):
    path, digest = frozen_manifest(tmp_path, monkeypatch)
    code, output = run_pilot(capsys, "--manifest", str(path), "--manifest-sha256", digest)
    assert code == 0
    report = json.loads(output.out)
    assert report["provider_calls"] == 0 and set(report["case_digests"]) == set(CASES)
    assert not list(tmp_path.glob("pilot-*")) and not (tmp_path / "execution-claims").exists()


@pytest.mark.parametrize("argv,message", [
    (["--manifest-sha256", "f" * 64], "Manifest differs from the explicitly frozen digest"),
    (["--phase", "direct"], "requires the explicit frozen-manifest handoff and --allow-inference"),
    (["--phase", "local", "--allow-inference"], "Native phases require --baseline-report"),
    (["--phase", "all", "--allow-inference", "--baseline-report", "direct.json"],
     "A run with a direct phase uses its own baseline"),
])
def test_pilot_refuses_unauthorized_execution(tmp_path, monkeypatch, capsys, argv, message):
    path, digest = frozen_manifest(tmp_path, monkeypatch)
    arguments = ["--manifest", str(path), *argv]
    if "--manifest-sha256" not in argv:
        arguments += ["--manifest-sha256", digest]
    code, output = run_pilot(capsys, *arguments)
    assert code == 2 and message in output.err
    assert not list(tmp_path.glob("pilot-*"))


def test_pilot_refuses_reports_outside_the_checkout(tmp_path, monkeypatch, capsys):
    path, digest = frozen_manifest(tmp_path, monkeypatch)
    monkeypatch.setattr(pilot, "ROOT", tmp_path / "elsewhere")
    code, output = run_pilot(capsys, "--manifest", str(path), "--manifest-sha256", digest)
    assert code == 2 and "Report directory must be inside the checkout" in output.err


def test_pilot_refuses_a_baseline_from_another_manifest(tmp_path, monkeypatch, capsys):
    path, digest = frozen_manifest(tmp_path, monkeypatch)
    other = tmp_path / "pilot-other"
    other.mkdir()
    (other / "manifest.json").write_text("{}")
    (other / "direct.json").write_text(json.dumps({"phase": "direct", "status": "passed", "cases": []}))
    code, output = run_pilot(capsys, "--manifest", str(path), "--manifest-sha256", digest, "--phase", "local",
                             "--allow-inference", "--baseline-report", str(other / "direct.json"))
    assert code == 2 and "Baseline report was not produced by this frozen manifest" in output.err


@pytest.mark.parametrize("change,message", [
    ({"status": "failed"}, "Baseline direct phase did not pass"),
    ({"phase": "local"}, "not a direct phase report"),
    ({"digest": "b" * 64}, "Baseline case content for intake differs"),
    ({"case": "another-case"}, "Baseline case for intake differs from the manifest"),
    ({"drop": True}, "cover every frozen case exactly once"),
])
def test_baseline_report_must_be_a_passed_direct_run_of_the_same_cases(tmp_path, change, message):
    config = manifest(tmp_path)
    (tmp_path / "manifest.json").write_text(config.model_dump_json())
    rows = [{"agent": agent, "case": case, "case_digest": "a" * 64} for agent, case in CASES.items()]
    if "case" in change:
        rows[0]["case"] = change["case"]
    if "digest" in change:
        rows[0]["case_digest"] = change["digest"]
    if change.get("drop"):
        rows.pop()
    report = {"phase": change.get("phase", "direct"), "status": change.get("status", "passed"), "cases": rows}
    (tmp_path / "direct.json").write_text(json.dumps(report))
    with pytest.raises(ValueError, match=message):
        verify_baseline_report(config, sha256_file(tmp_path / "manifest.json"), tmp_path / "direct.json",
                               dict.fromkeys(CASES, "a" * 64))


def test_outer_interrupt_checkpoints_failed_report_and_reaps_owned_phase(tmp_path, monkeypatch, capsys):
    path, digest = frozen_manifest(tmp_path, monkeypatch, phases=["direct"], maximum_pilot_agent_trials=11)
    monkeypatch.setattr(pilot, "phase_environment", lambda *_: {})
    children = []

    class InterruptOnce:
        def __init__(self, child):
            self.child, self.pid, self.interrupted = child, child.pid, False

        def wait(self, timeout):
            if not self.interrupted:
                self.interrupted = True
                raise KeyboardInterrupt
            return self.child.wait(timeout=timeout)

        def poll(self):
            return self.child.poll()

        def terminate(self):
            return self.child.terminate()

        def kill(self):
            return self.child.kill()

    def start(*_args, **_kwargs):
        child = sleeping_child(start_new_session=True)
        children.append(child)
        return InterruptOnce(child)

    monkeypatch.setattr(pilot.subprocess, "Popen", start)
    try:
        code, _output = run_pilot(capsys, "--manifest", str(path), "--manifest-sha256", digest,
                                  "--phase", "direct", "--allow-inference")
        assert code == 1
        report = json.loads(next(tmp_path.glob("pilot-*/report.json")).read_bytes())
        assert report["status"] == "failed"
        assert report["phases"] == [{"phase": "direct", "status": "failed",
                                     "failure_type": "QualificationInterrupted", "child_reaped": True}]
        assert len(children) == 1 and children[0].poll() is not None
        assert (tmp_path / "execution-claims" / f"{digest}-direct.started").exists()
    finally:
        reap(children)
