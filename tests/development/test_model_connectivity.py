"""Single-request checks use real PydanticAI validation without live infrastructure."""

import asyncio
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from pydantic_ai.messages import ModelResponse, ToolCallPart
from pydantic_ai.models.function import FunctionModel

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "model_connectivity", ROOT / "scripts/model_connectivity.py"
)
check = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check
SPEC.loader.exec_module(check)


@pytest.fixture
def profile(tmp_path, monkeypatch):
    path = tmp_path / "models.yaml"
    config = {
        "default_backend": "local",
        "model_catalog": {"sonnet": {"local": "actual-model"}},
        "backends": {
            "local": {
                "kind": "openai_compatible",
                "transport": "direct",
                "base_url": "https://model.invalid/v1",
                "max_retries_under_temporal": 0,
                "min_max_tokens": 16000,
                "enable_thinking": False,
                "strict_closed_output_tools": True,
                "prices": {"actual-model": {"input_per_mtok": 0, "output_per_mtok": 0}},
            }
        },
    }
    path.write_text(yaml.safe_dump(config))
    settings = SimpleNamespace(
        model_mode="live", git_commit_sha="a" * 40, models_config=path, broker_config=None
    )
    monkeypatch.setattr(check, "get_settings", lambda: settings)
    monkeypatch.setattr(check.models, "get_settings", lambda: settings)
    monkeypatch.setattr(check, "load_spec", lambda name: SimpleNamespace(model="sonnet"))
    # Real configuration loading/resolution; replace only the actual provider construction.
    check.models.load_models_config.cache_clear()
    calls = []

    def respond(messages, info):
        calls.append(info)
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, {"ready": True})])

    monkeypatch.setattr(
        check.models, "resolve", lambda name, tier, **kwargs: FunctionModel(respond)
    )
    yield settings, config, calls
    check.models.load_models_config.cache_clear()


def run(**kwargs):
    return asyncio.run(check.check_model(**kwargs))


def test_actual_structured_request_and_exact_profile_receipt(profile):
    settings, _, calls = profile
    result = run()
    assert result["status"] == "passed"
    assert result["requests"] == 1
    assert result["model"] == "local:actual-model"
    assert len(calls) == 1
    assert calls[0].model_settings["max_tokens"] == 16000
    assert calls[0].model_settings["timeout"] == 90
    assert calls[0].output_tools[0].parameters_json_schema["additionalProperties"] is False
    receipt = result["receipt"]
    assert set(receipt) == {
        "version",
        "checked_at",
        "source_commit",
        "model_config_sha256",
        "broker_config_sha256",
        "mode",
        "transport",
        "status",
    }
    assert receipt["source_commit"] == settings.git_commit_sha
    assert receipt["model_config_sha256"] == check.profile_identity()["model_config_sha256"]
    assert receipt["broker_config_sha256"] is None
    assert "model.invalid" not in json.dumps(result)


@pytest.mark.parametrize(
    "condition", ["stub", "brokered", "retry", "bad_source", "mixed", "missing", "cached"]
)
def test_refused_profiles_make_no_request(profile, condition):
    settings, config, calls = profile
    if condition == "stub":
        settings.model_mode = "stub"
    elif condition == "bad_source":
        settings.git_commit_sha = "missing"
    elif condition == "mixed":
        settings.broker_config = settings.models_config.parent / "broker.yaml"
        settings.broker_config.write_text("{}")
    elif condition == "missing":
        settings.models_config.unlink()
    else:
        if condition == "cached":
            check.models.load_models_config()
        config["backends"]["local"]["transport"] = (
            "brokered" if condition == "brokered" else "direct"
        )
        config["backends"]["local"]["max_retries_under_temporal"] = 1
        settings.models_config.write_text(yaml.safe_dump(config))
    result = run()
    assert result["status"] == "not_checked"
    assert "receipt" not in result
    assert result["requests"] == 0
    assert calls == []


@pytest.mark.parametrize("args", [{"ready": False}, {"ready": True, "extra": "private"}])
def test_invalid_output_fails_without_format_retry(profile, monkeypatch, args):
    calls = []

    def respond(messages, info):
        calls.append(info)
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, args)])

    monkeypatch.setattr(check.models, "resolve", lambda *a, **kw: FunctionModel(respond))
    result = run()
    assert result["status"] == "failed"
    assert result["requests"] is None
    assert len(calls) == 1
    assert "receipt" not in result
    assert "private" not in json.dumps(result)


def test_profile_drift_after_inference_cannot_record_pass(profile, monkeypatch):
    settings, _, _ = profile

    def respond(messages, info):
        settings.git_commit_sha = "b" * 40
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, {"ready": True})])

    monkeypatch.setattr(check.models, "resolve", lambda *a, **kw: FunctionModel(respond))
    result = run()
    assert result["status"] == "failed"
    assert result["requests"] == 1
    assert "receipt" not in result


def test_provider_error_is_closed_and_not_retried(profile, monkeypatch):
    calls = []

    def respond(messages, info):
        calls.append(info)
        raise RuntimeError("private credential and endpoint")

    monkeypatch.setattr(check.models, "resolve", lambda *a, **kw: FunctionModel(respond))
    result = run()
    assert result["status"] == "failed"
    assert result["requests"] is None
    assert len(calls) == 1
    assert "private" not in json.dumps(result)
    assert "receipt" not in result


def test_outer_timeout_cancels_the_only_request(profile, monkeypatch):
    calls = []

    async def respond(messages, info):
        calls.append(info)
        await asyncio.sleep(10)
        raise AssertionError("must be cancelled")

    monkeypatch.setattr(check.models, "resolve", lambda *a, **kw: FunctionModel(respond))
    result = run(timeout=1)
    assert result["status"] == "failed"
    assert "deadline" in result["detail"]
    assert len(calls) == 1
    assert result["elapsed_s"] < 3
    assert "receipt" not in result


@pytest.mark.parametrize("timeout", [0, 301, float("nan"), float("inf"), True, "90"])
def test_invalid_timeout_never_calls_model(profile, timeout):
    result = run(timeout=timeout)
    assert result["status"] == "failed"
    assert profile[2] == []


def test_cli_requires_explicit_inference_authorization(monkeypatch):
    monkeypatch.setattr(check, "check_model", lambda **kw: pytest.fail("inference must not run"))
    with pytest.raises(SystemExit) as exc:
        check.main([])
    assert exc.value.code == 2


def test_configuration_bytes_drift_after_request_fails(profile, monkeypatch):
    settings, config, _ = profile

    def respond(messages, info):
        config["backends"]["local"]["base_url"] = "https://changed.invalid/v1"
        settings.models_config.write_text(yaml.safe_dump(config))
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, {"ready": True})])

    monkeypatch.setattr(check.models, "resolve", lambda *a, **kw: FunctionModel(respond))
    result = run()
    assert result["status"] == "failed"
    assert result["requests"] == 1
    assert "receipt" not in result
    assert "changed.invalid" not in json.dumps(result)


def test_provider_without_enforced_transport_retry_bound_is_not_checked(profile):
    settings, config, calls = profile
    backend = config["backends"]["local"]
    backend["kind"] = "bedrock"
    backend.pop("enable_thinking")
    backend.pop("strict_closed_output_tools")
    settings.models_config.write_text(yaml.safe_dump(config))
    result = run()
    assert result["status"] == "not_checked"
    assert "transport bound" in result["detail"]
    assert result["requests"] == 0
    assert "receipt" not in result
    assert calls == []
