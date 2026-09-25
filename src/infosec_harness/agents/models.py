"""Model factory (§6.1, D9/D15/D16).

``agent.yaml`` names a *tier* (``model: sonnet``). The ``ResolveModelId`` capability calls
:func:`resolve` on the worker, which maps the tier through ``config/models.yaml`` to a
Bedrock (SSO/IRSA) or OpenAI-spec (API key) model. Credentials are read on the worker and
never enter workflow history. In ``stub`` mode a deterministic in-process model is used.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field
from pydantic_ai.models import Model

from infosec_harness.settings import get_settings


class Prices(BaseModel):
    input_per_mtok: float
    output_per_mtok: float
    cache_read_per_mtok: float | None = None
    cache_write_per_mtok: float | None = None


class BackendConfig(BaseModel):
    kind: Literal["bedrock", "openai_compatible"]
    region: str | None = None
    aws_profile: str | None = None
    base_url: str | None = None
    api_key_env: str | None = None
    prices: dict[str, Prices] = Field(default_factory=dict)


class ModelsConfig(BaseModel):
    backends: dict[str, BackendConfig]
    default_backend: str
    model_catalog: dict[str, dict[str, str]]
    default_model: str = "sonnet"
    agents: dict[str, dict[str, str]] = Field(default_factory=dict)

    def backend_for(self, agent_name: str | None) -> str:
        if agent_name and (b := self.agents.get(agent_name, {}).get("backend")):
            return b
        return os.environ.get("HARNESS_MODEL_BACKEND") or self.default_backend

    def model_id(self, tier: str, backend: str) -> str:
        if tier not in self.model_catalog:
            # Not a tier: treat as a concrete model id for this backend.
            return tier
        try:
            return self.model_catalog[tier][backend]
        except KeyError as e:
            raise KeyError(f"Tier {tier!r} has no model for backend {backend!r}") from e


@lru_cache
def load_models_config(path: Path | None = None) -> ModelsConfig:
    path = path or get_settings().models_config
    return ModelsConfig.model_validate(yaml.safe_load(Path(path).read_text()))


@lru_cache(maxsize=64)
def _build_live(backend_name: str, model_id: str) -> Model:
    cfg = load_models_config()
    backend = cfg.backends[backend_name]
    if backend.kind == "bedrock":
        from pydantic_ai.models.bedrock import BedrockConverseModel
        from pydantic_ai.providers.bedrock import BedrockProvider

        # In k8s the profile is unset and the default chain picks up IRSA / Pod Identity.
        profile = os.environ.get("AWS_PROFILE") or backend.aws_profile
        provider = BedrockProvider(region_name=backend.region, profile_name=profile or None)
        return BedrockConverseModel(model_id, provider=provider)
    from pydantic_ai.models.openai import OpenAIChatModel
    from pydantic_ai.providers.openai import OpenAIProvider

    # Some gateways (e.g. an internal LLM proxy) require no key. Fall back to a placeholder
    # so the OpenAI client still constructs; if the endpoint enforces auth it returns 401.
    api_key = os.environ.get(backend.api_key_env or "", "") or "no-key"
    return OpenAIChatModel(model_id, provider=OpenAIProvider(base_url=backend.base_url, api_key=api_key))


def resolve(agent_name: str, tier: str) -> Model:
    """Resolve an agent's model tier to a concrete model on the worker."""
    if get_settings().model_mode == "stub":
        from infosec_harness.agents.stubs import stub_model

        return stub_model(agent_name, tier)
    cfg = load_models_config()
    backend = cfg.backend_for(agent_name)
    return _build_live(backend, cfg.model_id(tier, backend))


def resolved_model_name(agent_name: str, tier: str) -> str:
    """The concrete model id an agent's tier resolves to (recorded in the config hash)."""
    if get_settings().model_mode == "stub":
        return f"stub:{agent_name}:{tier}"
    cfg = load_models_config()
    backend = cfg.backend_for(agent_name)
    return f"{backend}:{cfg.model_id(tier, backend)}"


def custom_prices(model_name: str) -> Prices | None:
    """Configured fallback prices for models genai-prices doesn't know (e.g. gateways)."""
    cfg = load_models_config()
    for backend in cfg.backends.values():
        if model_name in backend.prices:
            return backend.prices[model_name]
    return None


def estimate_cost(model_name: str, usage: Any) -> tuple[float | None, bool]:
    """Return (usd, estimated?) for a RunUsage using genai-prices, then configured prices."""
    try:
        from genai_prices import Usage, calc_price

        provider = None
        name = model_name
        if name.startswith("anthropic."):
            name, provider = name.removeprefix("anthropic."), "anthropic"
        for prefix in ("us.", "eu.", "global.", "apac."):
            if name.startswith(prefix + "anthropic."):
                name, provider = name.removeprefix(prefix + "anthropic."), "anthropic"
        price = calc_price(
            Usage(
                input_tokens=usage.input_tokens,
                output_tokens=usage.output_tokens,
                cache_read_tokens=usage.cache_read_tokens or None,
                cache_write_tokens=usage.cache_write_tokens or None,
            ),
            model_ref=name,
            provider_id=provider,
        )
        return float(price.total_price), False
    except Exception:
        pass
    if (p := custom_prices(model_name)) is not None:
        uncached = usage.input_tokens - (usage.cache_read_tokens or 0) - (usage.cache_write_tokens or 0)
        cost = (
            max(uncached, 0) * p.input_per_mtok
            + (usage.cache_read_tokens or 0) * (p.cache_read_per_mtok or p.input_per_mtok * 0.1)
            + (usage.cache_write_tokens or 0) * (p.cache_write_per_mtok or p.input_per_mtok * 1.25)
            + usage.output_tokens * p.output_per_mtok
        ) / 1_000_000
        return cost, True
    return None, True
