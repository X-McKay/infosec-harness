"""Model factory (§6.1, D9/D15/D16).

``agent.yaml`` names a *tier* (``model: sonnet``). The ``ResolveModelId`` capability calls
:func:`resolve` on the worker, which maps the tier through ``config/models.yaml`` to a
Bedrock (SSO/IRSA) or OpenAI-spec (API key) model. Credentials are read on the worker and
never enter workflow history. In ``stub`` mode a deterministic in-process model is used.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
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
    # Under Temporal the activity layer owns transient infrastructure retries, so provider
    # transport retries are minimized rather than stacked on top of them (agent-playbook
    # §6). See registry.ACTIVITY_RETRY for the combined bound this participates in.
    max_retries_under_temporal: int = 1
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


class CapabilityProfile(BaseModel):
    """Provider behavior which changes how an otherwise identical agent is invoked."""

    model_config = {"frozen": True}

    # AgentSpec's typed Pydantic outputs are emitted through the model-facing output tool on
    # both supported backends. Recording "native" here would claim a JSON-schema response
    # format that these agents do not request.
    structured_output: Literal["native", "tool"] = "tool"
    tool_calling: bool = True
    message_layout: Literal["native", "single_system"] = "native"
    reasoning_accounting: Literal["separate", "inside_output", "unknown"] = "unknown"
    usage_reporting: Literal["observed", "unavailable"] = "observed"
    prompt_caching: Literal["observed", "provider_managed", "unsupported"] = "provider_managed"


class ResolvedModelConfig(BaseModel):
    """Secret-free, immutable identity of the model configuration actually used.

    This is deliberately more explicit than ``"backend:model"``. Backend adaptations and
    retry ownership change observable behavior, and requested settings can differ from the
    values sent on the wire (notably the gateway's output-token floor).
    """

    model_config = {"frozen": True}

    mode: Literal["stub", "live"]
    backend_name: str
    backend_kind: Literal["stub", "bedrock", "openai_compatible"]
    requested_model: str
    resolved_model: str
    requested_settings: dict[str, Any] = Field(default_factory=dict)
    effective_settings: dict[str, Any] = Field(default_factory=dict)
    capability_profile: CapabilityProfile
    provider_output_floor: int = 0
    transport_retries: int = 0
    durable: bool = False
    region: str | None = None
    endpoint: str | None = None
    credential_reference: str | None = None
    pricing_table: str
    pricing_status: Literal["known_zero", "catalog", "custom", "unknown"]

    @property
    def digest(self) -> str:
        payload = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()[:16]


class ModelsConfig(BaseModel):
    backends: dict[str, BackendConfig]
    default_backend: str
    model_catalog: dict[str, dict[str, str]]
    default_model: str = "sonnet"
    # Versioned logical policy -> tier. Specs name a policy in metadata.model_policy so
    # routing is a config decision rather than an edit across every spec.
    model_policies: dict[str, str] = Field(default_factory=dict)
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


def max_tokens_floor(agent_name: str | None = None) -> int:
    """The per-call output floor required by the backend that will serve ``agent_name``.

    The floor has to be applied in *two* places, and applying it only in the model is a bug
    that shows up as an error message naming a cap that was never sent:

    * the outgoing payload, so the endpoint actually gets the larger cap
      (:meth:`_CompatOpenAIChatModel.prepare_request`), and
    * the agent's own ``model_settings``, because pydantic-ai records
      ``model_settings['max_tokens']`` into ``GraphAgentState.last_max_tokens`` *before* it
      calls ``Model.prepare_request`` (``_agent_graph.py``), and that recorded number is what
      "Model token limit (N) exceeded before any response was generated" reports. With the
      floor applied only to the payload, a run that burned the real 16000-token cap was
      reported as having exceeded 6000.

    ``Model.settings`` cannot carry the floor either: pydantic-ai merges it as the *base*
    under the agent's settings, so a small per-agent ``max_tokens`` overrides it. See
    ``registry._apply_backend_token_floor`` for the agent-side half.
    """
    cfg = load_models_config()
    return cfg.backends[cfg.backend_for(agent_name)].min_max_tokens


def resolve_config(
    agent_name: str,
    tier: str,
    *,
    model_settings: dict[str, Any] | None = None,
    durable: bool = False,
) -> ResolvedModelConfig:
    """Resolve the secret-free effective model contract without constructing a client."""
    requested = dict(model_settings or {})
    if get_settings().model_mode == "stub":
        return ResolvedModelConfig(
            mode="stub",
            backend_name="stub",
            backend_kind="stub",
            requested_model=tier,
            resolved_model=f"stub:{agent_name}:{tier}",
            requested_settings=requested,
            effective_settings=requested,
            capability_profile=CapabilityProfile(prompt_caching="unsupported"),
            durable=durable,
            pricing_table="stub-known-zero",
            pricing_status="known_zero",
        )

    cfg = load_models_config()
    backend_name = cfg.backend_for(agent_name)
    backend = cfg.backends[backend_name]
    model_id = cfg.model_id(tier, backend_name)
    resolved_model = f"{backend_name}:{model_id}"
    source = pricing_source(resolved_model)
    effective = _apply_max_tokens_floor(requested, backend.min_max_tokens) or {}
    retries = backend.max_retries_under_temporal if durable else backend.max_retries
    if backend.kind == "openai_compatible":
        capabilities = CapabilityProfile(
            message_layout=("single_system" if backend.merge_system_messages else "native"),
            reasoning_accounting="inside_output",
        )
        credential_reference = backend.api_key_env
    else:
        capabilities = CapabilityProfile(reasoning_accounting="separate")
        credential_reference = "aws-default-chain"
    return ResolvedModelConfig(
        mode="live",
        backend_name=backend_name,
        backend_kind=backend.kind,
        requested_model=tier,
        resolved_model=resolved_model,
        requested_settings=requested,
        effective_settings=effective,
        capability_profile=capabilities,
        provider_output_floor=backend.min_max_tokens,
        transport_retries=retries,
        durable=durable,
        region=backend.region,
        endpoint=backend.base_url,
        credential_reference=credential_reference,
        pricing_table=pricing_table_identity(backend_name),
        pricing_status={
            "custom-zero": "known_zero",
            "genai-prices": "catalog",
            "custom": "custom",
        }.get(source, "unknown"),
    )


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
def _build_live(backend_name: str, model_id: str, durable: bool = False) -> Model:
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

    retries = backend.max_retries_under_temporal if durable else backend.max_retries
    client = AsyncOpenAI(base_url=backend.base_url, api_key=api_key, max_retries=retries)
    return _CompatOpenAIChatModel(
        model_id,
        provider=OpenAIProvider(openai_client=client),
        merge_system=backend.merge_system_messages,
        min_max_tokens=backend.min_max_tokens,
    )


def resolve(agent_name: str, tier: str, *, durable: bool = False) -> Model:
    """Resolve an agent's model tier to a concrete model on the worker.

    ``durable`` says the agent runs inside a Temporal workflow, where the activity layer
    owns transient retries and provider transport retries are minimized instead of
    multiplying with them.
    """
    if get_settings().model_mode == "stub":
        from infosec_harness.agents.stubs import stub_model

        return stub_model(agent_name, tier)
    cfg = load_models_config()
    backend = cfg.backend_for(agent_name)
    return _build_live(backend, cfg.model_id(tier, backend), durable)


def resolved_model_name(agent_name: str, tier: str) -> str:
    """The concrete model id an agent's tier resolves to (recorded in the config hash)."""
    if get_settings().model_mode == "stub":
        return f"stub:{agent_name}:{tier}"
    cfg = load_models_config()
    backend = cfg.backend_for(agent_name)
    return f"{backend}:{cfg.model_id(tier, backend)}"


def _backend_and_bare_model(model_name: str) -> tuple[str, str]:
    """Return the selected backend and its model id without guessing across backends."""
    cfg = load_models_config()
    prefix, sep, rest = model_name.partition(":")
    if sep and prefix in cfg.backends:
        return prefix, rest
    return cfg.backend_for(None), model_name


def strip_backend_prefix(model_name: str) -> str:
    """Drop a leading ``<backend>:`` from a recorded model name.

    :func:`resolved_model_name` records ``"gateway:Qwen3.6-35B-A3B-NVFP4"`` so a run is
    attributable to the backend that served it, but every price table — genai-prices and the
    configured fallbacks alike — is keyed on the bare model id. Looking a prefixed name up
    silently found nothing, so *all* configured prices were dead and cost came back None for
    any model genai-prices does not know, which is precisely the case they exist to cover.

    Only a known backend name is stripped, so a model id that legitimately contains a colon
    (``qwen3.5:9b``) is left alone.
    """
    return _backend_and_bare_model(model_name)[1]


def _content_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()[:16]


def pricing_table_identity(backend_name: str) -> str:
    """Version the exact price inputs used for one backend without exposing credentials."""
    cfg = load_models_config()
    if backend_name not in cfg.backends:
        raise KeyError(f"unknown backend {backend_name!r}")
    config_path = Path(get_settings().models_config)
    config_digest = _content_digest(config_path.read_bytes())
    backend_prices = cfg.backends[backend_name].prices
    custom_digest = _content_digest(json.dumps(
        {name: price.model_dump(mode="json") for name, price in sorted(backend_prices.items())},
        sort_keys=True,
        separators=(",", ":"),
    ).encode())
    try:
        import genai_prices

        version = importlib.metadata.version("genai-prices")
        data_path = Path(genai_prices.__file__).with_name("data.py")
        data_digest = _content_digest(data_path.read_bytes())
    except Exception:
        version, data_digest = "unavailable", "unavailable"
    return (
        f"genai-prices:{version}:{data_digest};models:{config_digest};"
        f"backend:{backend_name};custom:{custom_digest}"
    )


def custom_prices(model_name: str) -> Prices | None:
    """Configured fallback prices for models genai-prices doesn't know (e.g. gateways)."""
    cfg = load_models_config()
    backend_name, bare = _backend_and_bare_model(model_name)
    backend = cfg.backends[backend_name]
    for candidate in (bare, model_name):
        if candidate in backend.prices:
            return backend.prices[candidate]
    return None


def pricing_source(model_name: str) -> Literal[
    "stub", "genai-prices", "custom", "custom-zero", "unknown"
]:
    """Identify whether a dollar ceiling can be enforced before a provider call starts."""
    if model_name.startswith("stub:"):
        return "stub"
    # Backend-scoped configured prices are deployment truth (including an explicit zero for
    # self-hosted models), so they override a public catalog entry for the same bare model id.
    if (price := custom_prices(model_name)) is not None:
        return "custom-zero" if price.input_per_mtok == price.output_per_mtok == 0 else "custom"
    try:
        from genai_prices import Usage, calc_price

        name = strip_backend_prefix(model_name)
        provider = None
        if name.startswith("anthropic."):
            name, provider = name.removeprefix("anthropic."), "anthropic"
        for prefix in ("us.", "eu.", "global.", "apac."):
            if name.startswith(prefix + "anthropic."):
                name, provider = name.removeprefix(prefix + "anthropic."), "anthropic"
        calc_price(Usage(input_tokens=1, output_tokens=1), model_ref=name, provider_id=provider)
        return "genai-prices"
    except Exception:
        return "unknown"


def estimate_cost(model_name: str, usage: Any) -> tuple[float | None, bool]:
    """Return (usd, estimated?) using the selected backend's rates, then genai-prices."""
    if model_name.startswith("stub:"):
        return 0.0, False
    if (p := custom_prices(model_name)) is not None:
        uncached = usage.input_tokens - (usage.cache_read_tokens or 0) - (usage.cache_write_tokens or 0)
        cost = (
            max(uncached, 0) * p.input_per_mtok
            + (usage.cache_read_tokens or 0) * (p.cache_read_per_mtok or p.input_per_mtok * 0.1)
            + (usage.cache_write_tokens or 0) * (p.cache_write_per_mtok or p.input_per_mtok * 1.25)
            + usage.output_tokens * p.output_per_mtok
        ) / 1_000_000
        return cost, True
    try:
        from genai_prices import Usage, calc_price

        provider = None
        name = strip_backend_prefix(model_name)
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
    return None, True
