"""Offline Bedrock resolver coverage for the current atomic intake generation."""

from __future__ import annotations

from typing import Any


def test_atomic_intake_uses_bedrock_converse_with_existing_retry_and_region_contract(monkeypatch):
    from infosec_harness.agents import models
    from infosec_harness.agents.intake_claims import AtomicFinding
    from infosec_harness.agents.intake_contracts import retained_intake_spec
    from infosec_harness.agents.registry import build_agent, load_spec, resolve_agent_config
    from infosec_harness.settings import get_settings

    captured: dict[str, Any] = {}

    class Provider:
        def __init__(self, **kwargs: Any) -> None:
            captured["provider"] = kwargs

    class ConverseModel:
        def __init__(self, model_id: str, *, provider: Any) -> None:
            captured["model_id"] = model_id
            captured["model_provider"] = provider

    import pydantic_ai.models.bedrock
    import pydantic_ai.providers.bedrock

    monkeypatch.setattr(pydantic_ai.providers.bedrock, "BedrockProvider", Provider)
    monkeypatch.setattr(pydantic_ai.models.bedrock, "BedrockConverseModel", ConverseModel)
    monkeypatch.setenv("HARNESS_MODEL_MODE", "live")
    monkeypatch.setenv("HARNESS_MODEL_BACKEND", "bedrock")
    monkeypatch.setenv("AWS_PROFILE", "synthetic-bedrock-profile")
    get_settings.cache_clear()
    models.load_models_config.cache_clear()
    models._build_live.cache_clear()
    try:
        model = models.resolve_intake_atomic("intake", "sonnet", durable=True)
        backend = models.load_models_config().backends["bedrock"]
        expected_model_id = models.load_models_config().model_id("sonnet", "bedrock")
        current_config = resolve_agent_config("intake", load_spec("intake"), durable=True)
        retained_config = resolve_agent_config(
            "intake", retained_intake_spec(), durable=True
        )
        agent = build_agent("intake", durable=True)
    finally:
        models._build_live.cache_clear()
        models.load_models_config.cache_clear()
        get_settings.cache_clear()

    assert isinstance(model, ConverseModel)
    assert captured["provider"] == {
        "region_name": backend.region,
        "profile_name": "synthetic-bedrock-profile",
    }
    assert captured["model_id"] == expected_model_id
    assert captured["model_provider"].__class__ is Provider
    assert current_config.model.backend_name == retained_config.model.backend_name == "bedrock"
    assert current_config.model.transport_retries == retained_config.model.transport_retries
    assert current_config.model.durable is retained_config.model.durable is True
    assert current_config.model.effective_settings.get("temperature") == 0.0
    assert retained_config.model.effective_settings.get("temperature") is None
    assert agent.output_type is AtomicFinding
    assert len(agent._output_validators) >= 1


def test_bedrock_factory_mock_restores_provider_settings_for_later_tests(monkeypatch):
    from infosec_harness.agents import models
    from infosec_harness.settings import get_settings

    get_settings.cache_clear()
    before = get_settings().model_mode
    with monkeypatch.context() as isolated:
        test_atomic_intake_uses_bedrock_converse_with_existing_retry_and_region_contract(isolated)
    assert get_settings().model_mode == before
    models.load_models_config.cache_clear()
    get_settings.cache_clear()
