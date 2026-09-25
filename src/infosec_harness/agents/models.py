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
from pydantic_ai.models.openai import OpenAIChatModel as OpenAIChatModelBase

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
    # A self-hosted endpoint can drop requests under load (502 upstream_unreachable). The
    # OpenAI client's default of 2 retries is not enough to ride that out, and without
    # Temporal (e.g. `harness eval corpus`) one 502 kills a whole batch.
    max_retries: int = 6
    # Many self-hosted OpenAI-spec servers (vLLM/TGI with a single-system chat template)
    # reject a request carrying more than one system message. pydantic-ai emits one per
    # instruction block, and the Skills capability adds its own, so every skill-bearing
    # agent would 400. Merging the leading run of system messages into one is semantically
    # neutral and keeps the cache prefix stable. See :class:`_SingleSystemOpenAIChatModel`.
    merge_system_messages: bool = True
    # Reasoning models served over the chat-completions API spend their thinking inside
    # `max_tokens`, unlike Bedrock/Anthropic where thinking has its own budget. The agent
    # specs are budgeted for the latter, so a small per-agent `max_tokens` (e.g. 3000) is
    # exhausted by reasoning and the run dies with "token limit exceeded before any
    # response was generated". This raises the floor for one backend without touching the
    # specs — set it to 0 to disable.
    min_max_tokens: int = 0


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


def _merge_leading_system_messages(messages: list[Any]) -> list[Any]:
    """Collapse the leading run of system messages into a single one.

    Order is preserved and the blocks are joined with a blank line, so the resulting prefix
    is byte-stable across runs — prompt caching still sees the same stable head.
    """
    lead = 0
    while lead < len(messages) and messages[lead].get("role") == "system":
        lead += 1
    if lead < 2:
        return messages
    merged = "\n\n".join(str(m.get("content") or "") for m in messages[:lead])
    return [{"role": "system", "content": merged}, *messages[lead:]]


def _apply_max_tokens_floor(settings: Any, floor: int) -> Any:
    """Raise ``max_tokens`` to ``floor``, never lower it. A zero floor is a no-op."""
    if not floor or settings is None:
        return settings
    if settings.get("max_tokens", 0) >= floor:
        return settings
    return {**settings, "max_tokens": floor}


class _CompatOpenAIChatModel(OpenAIChatModelBase):  # type: ignore[misc,valid-type]
    """An OpenAI-spec model that works around two common self-hosted-endpoint quirks.

    1. *One system message.* Endpoints whose chat template allows a single leading system
       message (common for self-hosted vLLM builds) answer 400 "System message must be at
       the beginning." to the multi-block layout pydantic-ai produces for instructions +
       deferred capabilities.
    2. *Thinking inside ``max_tokens``.* Reasoning models on this API spend their thinking
       against the same budget as the answer, so the specs' Anthropic-shaped budgets can be
       exhausted before a single output token is produced.

    Both are properties of the endpoint, not of an agent, so they are configured per
    backend and applied here rather than by editing the agent specs.
    """

    def __init__(self, *args: Any, merge_system: bool = True, min_max_tokens: int = 0,
                 **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._merge_system = merge_system
        self._min_max_tokens = min_max_tokens

    def prepare_request(self, model_settings: Any, model_request_parameters: Any) -> Any:
        settings, params = super().prepare_request(model_settings, model_request_parameters)
        return _apply_max_tokens_floor(settings, self._min_max_tokens), params

    async def _map_messages(self, *args: Any, **kwargs: Any) -> list[Any]:
        mapped = await super()._map_messages(*args, **kwargs)
        return _merge_leading_system_messages(mapped) if self._merge_system else mapped


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
    from pydantic_ai.providers.openai import OpenAIProvider

    # Some gateways (e.g. an internal LLM proxy) require no key. Fall back to a placeholder
    # so the OpenAI client still constructs; if the endpoint enforces auth it returns 401.
    api_key = os.environ.get(backend.api_key_env or "", "") or "no-key"
    from openai import AsyncOpenAI

    client = AsyncOpenAI(base_url=backend.base_url, api_key=api_key,
                         max_retries=backend.max_retries)
    return _CompatOpenAIChatModel(
        model_id,
        provider=OpenAIProvider(openai_client=client),
        merge_system=backend.merge_system_messages,
        min_max_tokens=backend.min_max_tokens,
    )


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
