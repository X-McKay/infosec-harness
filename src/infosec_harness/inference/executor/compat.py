"""Provider shaping shared by direct workers and isolated inference executors."""
from __future__ import annotations

from dataclasses import replace
from typing import Any

from pydantic_ai.models.openai import OpenAIChatModel as OpenAIChatModelBase
from pydantic_ai.profiles import ModelProfile
from pydantic_ai.providers.openai import OpenAIProvider

from infosec_harness.agents.intake_schema import intake_openai_profile
from infosec_harness.inference.wire.codec import check_schemas
from infosec_harness.inference.wire.protocol import BrokerError, validate_thinking_token_budget


def merge_leading_system_messages(messages: list[Any]) -> list[Any]:
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


def apply_max_tokens_floor(settings: Any, floor: int) -> Any:
    """Raise ``max_tokens`` to ``floor``, never lower it. A zero floor is a no-op."""
    if not floor or settings is None:
        return settings
    if settings.get("max_tokens", 0) >= floor:
        return settings
    return {**settings, "max_tokens": floor}


class CompatOpenAIChatModel(OpenAIChatModelBase):  # type: ignore[misc,valid-type]
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
                 strict_closed_output_tools: bool = False, enable_thinking: bool | None = None,
                 thinking_token_budget: int | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._merge_system = merge_system
        self._min_max_tokens = min_max_tokens
        self._strict_closed_output_tools = strict_closed_output_tools
        if enable_thinking is not None and type(enable_thinking) is not bool:
            raise ValueError("Thinking control must be a strict boolean or omitted")
        # The budget is validated against the effective output cap on every request.
        self._enable_thinking = enable_thinking
        self._thinking_token_budget = thinking_token_budget

    def prepare_request(self, model_settings: Any, model_request_parameters: Any) -> Any:
        if self._strict_closed_output_tools:
            model_request_parameters = strict_closed_outputs(model_request_parameters, self.profile)
        settings, params = super().prepare_request(model_settings, model_request_parameters)
        settings = apply_max_tokens_floor(settings, self._min_max_tokens)
        if self._enable_thinking is not None or self._thinking_token_budget is not None:
            if settings and any(key in settings for key in ("extra_body", "extra_headers")):
                raise BrokerError("policy", "Thinking control cannot be combined with request overrides")
            try:
                validate_thinking_token_budget(
                    self._thinking_token_budget, self._enable_thinking,
                    (settings or {}).get("max_tokens"), require_output_cap=True)
            except ValueError:
                raise BrokerError("policy", "Invalid thinking token budget") from None
            # Typed operator controls are the only admitted provider body extensions.
            body: dict[str, Any] = {}
            if self._enable_thinking is not None:
                body["chat_template_kwargs"] = {"enable_thinking": self._enable_thinking}
            if self._thinking_token_budget is not None:
                body["thinking_token_budget"] = self._thinking_token_budget
            settings = {**(settings or {}), "extra_body": body}
        return settings, params

    async def _map_messages(self, *args: Any, **kwargs: Any) -> list[Any]:
        mapped = await super()._map_messages(*args, **kwargs)
        return merge_leading_system_messages(mapped) if self._merge_system else mapped


def contract_profile(model: str, *, atomic_intake: bool) -> ModelProfile:
    """The static OpenAI profile of a contract model; atomic intake inlines its output schema."""
    profile = OpenAIProvider.model_profile(model) or {}
    return intake_openai_profile(profile) if atomic_intake else profile


def model_for_contract(contract: Any, provider: Any) -> CompatOpenAIChatModel:
    """The one construction of a contract's provider model.

    Admission sizing (:func:`rendering.input_wire`) and executor dispatch both call this, so the request
    that is measured is the request that is sent.
    """
    extra: dict[str, Any] = {}
    if contract.atomic_intake:
        extra["profile"] = contract_profile(contract.model, atomic_intake=True)
    return CompatOpenAIChatModel(
        contract.model,
        provider=provider,
        merge_system=contract.merge_system_messages,
        min_max_tokens=contract.min_max_tokens,
        strict_closed_output_tools=contract.strict_closed_output_tools,
        enable_thinking=contract.enable_thinking,
        thinking_token_budget=contract.thinking_token_budget,
        **extra,
    )


def _closed_output_schema(schema: Any) -> bool:
    """Conservatively qualify closed JSON objects; dictionaries keep their keys."""
    found_object = False
    pending = [schema]
    while pending:
        node = pending.pop()
        if isinstance(node, list):
            pending.extend(node)
        elif isinstance(node, dict):
            if any(key in node for key in ("$dynamicRef", "$recursiveRef", "patternProperties", "unevaluatedProperties")):
                return False
            kind = node.get("type")
            if (kind == "object" or isinstance(kind, list) and "object" in kind
                    or "properties" in node or "additionalProperties" in node):
                found_object = True
                if node.get("additionalProperties") is not False:
                    return False
            pending.extend(node.values())
    return found_object


def strict_closed_outputs(params: Any, profile: Any) -> Any:
    """Copy output definitions only; authored parameters and local guards stay intact."""
    if params.output_mode not in {"auto", "tool"}:
        return params
    check_schemas(tool.parameters_json_schema for tool in params.output_tools if tool.strict is None)
    tools = []
    for tool in params.output_tools:
        if tool.strict is not None:
            tools.append(tool)
            continue
        if _closed_output_schema(tool.parameters_json_schema):
            if not profile.get("openai_supports_strict_tool_definition", True):
                raise BrokerError("policy", "Model profile does not support strict output tools")
            tools.append(replace(tool, strict=True))
        else:
            tools.append(tool)
    return replace(params, output_tools=tools)
