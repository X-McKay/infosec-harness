"""Provider shaping shared by direct workers and isolated inference executors."""
from __future__ import annotations

from dataclasses import replace
from typing import Any

from pydantic_ai.models.openai import OpenAIChatModel as OpenAIChatModelBase


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
                 strict_closed_output_tools: bool = False, enable_thinking: bool | None = None,
                 thinking_token_budget: int | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._merge_system = merge_system
        self._min_max_tokens = min_max_tokens
        self._strict_closed_output_tools = strict_closed_output_tools
        if enable_thinking is not None and type(enable_thinking) is not bool:
            raise ValueError("Thinking control must be a strict boolean or omitted")
        from .protocol import validate_thinking_token_budget

        validate_thinking_token_budget(thinking_token_budget, enable_thinking)
        self._enable_thinking = enable_thinking
        self._thinking_token_budget = thinking_token_budget

    def prepare_request(self, model_settings: Any, model_request_parameters: Any) -> Any:
        if self._strict_closed_output_tools:
            model_request_parameters = _strict_closed_outputs(model_request_parameters, self.profile)
        settings, params = super().prepare_request(model_settings, model_request_parameters)
        settings = _apply_max_tokens_floor(settings, self._min_max_tokens)
        if self._enable_thinking is not None or self._thinking_token_budget is not None:
            from .protocol import BrokerError, validate_thinking_token_budget

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
        return _merge_leading_system_messages(mapped) if self._merge_system else mapped




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


def _strict_closed_outputs(params: Any, profile: Any) -> Any:
    """Copy output definitions only; authored parameters and local guards stay intact."""
    from .protocol import BrokerError

    if params.output_mode not in {"auto", "tool"}:
        return params
    tools, size, nodes = [], 0, 0
    for tool in params.output_tools:
        if tool.strict is not None:
            tools.append(tool)
            continue
        expanded_size, expanded_nodes = _check_schema_expansion(tool.parameters_json_schema)
        size += expanded_size
        nodes += expanded_nodes
        if size > 1_048_576 or nodes > 65_536:
            raise BrokerError("policy", "Aggregate output schemas exceed rendering bound")
        if _closed_output_schema(tool.parameters_json_schema):
            if not profile.get("openai_supports_strict_tool_definition", True):
                raise BrokerError("policy", "Model profile does not support strict output tools")
            tools.append(replace(tool, strict=True))
        else:
            tools.append(tool)
    return replace(params, output_tools=tools)



def _check_schema_expansion(schema: Any) -> tuple[int, int]:
    """Bound acyclic local-ref expansion before SDK inlining/deepcopy.

    The SDK protects cycles but repeated acyclic references can expand exponentially.
    These are rendering resource bounds, independent of token/context admission.
    """
    from .protocol import BrokerError, _ascii_normalized_size

    definitions = schema.get("$defs", {}) if isinstance(schema, dict) else {}
    cache: dict[str, tuple[int, int, int]] = {}

    def visit(value: Any, depth: int, stack: tuple[str, ...]) -> tuple[int, int, int]:
        if depth > 64:
            raise BrokerError("policy", "Admission schema exceeds rendering depth")
        size, nodes, height = 0, 1, 1
        if isinstance(value, dict):
            for key, child in value.items():
                child_size, child_nodes, child_height = visit(child, depth + 1, stack)
                size += _ascii_normalized_size(key) + child_size + 4
                nodes += child_nodes
                height = max(height, child_height + 1)
            if "$ref" in value:
                reference = value["$ref"]
                if not isinstance(reference, str) or not reference.startswith("#/$defs/"):
                    raise BrokerError("policy", "Admission schema has an unsupported reference")
                name = reference[8:]
                if name in stack or name not in definitions:
                    raise BrokerError("policy", "Admission schema reference cannot be bounded")
                if name not in cache:
                    cache[name] = visit(definitions[name], depth + 1, (*stack, name))
                extra_size, extra_nodes, extra_height = cache[name]
                size += extra_size
                nodes += extra_nodes
                height = max(height, extra_height + 1)
        elif isinstance(value, list):
            for child in value:
                child_size, child_nodes, child_height = visit(child, depth + 1, stack)
                size += child_size + 2
                nodes += child_nodes
                height = max(height, child_height + 1)
        else:
            size = _ascii_normalized_size(value)
        if depth + height > 64:
            raise BrokerError("policy", "Admission schema exceeds expanded rendering depth")
        if size > 262_144 or nodes > 16_384:
            raise BrokerError("policy", "Admission schema exceeds rendering expansion bound")
        return size, nodes, height

    size, nodes, _ = visit(schema, 0, ())
    return size, nodes


async def input_wire(payload: Any, contract: Any) -> dict[str, Any]:
    """Pure SDK shaping, in the same order as request/_completions_create.

    The restricted codec excludes every content item that can fetch a remote resource.
    A rejecting transport additionally prevents any accidental provider request. This
    deliberately does not invoke request() or its global allow-model-requests check.
    """
    import httpx2
    from openai import AsyncOpenAI
    from pydantic_ai.providers.openai import OpenAIProvider

    from .codec import decode_payload
    from .protocol import MAX_BODY_BYTES, BrokerError, _ascii_normalized_size

    def deny_request(request: Any) -> Any:
        raise BrokerError("policy", "Admission rendering cannot send a provider request")

    messages, settings, params = decode_payload(payload)
    schemas = [schema for definition in (*params.function_tools, *params.output_tools)
               for schema in (definition.parameters_json_schema, definition.return_schema)
               if schema is not None]
    if params.output_object is not None:
        schemas.append(params.output_object.json_schema)
    total_size, total_nodes = 0, 0
    for schema in schemas:
        size, nodes = _check_schema_expansion(schema)
        total_size += size
        total_nodes += nodes
        if total_size > 1_048_576 or total_nodes > 65_536:
            raise BrokerError("policy", "Aggregate admission schemas exceed rendering bound")
    async with (
        httpx2.AsyncClient(transport=httpx2.MockTransport(deny_request), trust_env=False) as transport,
        AsyncOpenAI(base_url=contract.endpoint, api_key="admission-no-network",
                    max_retries=0, http_client=transport) as client,
    ):
        provider = OpenAIProvider(openai_client=client)
        extra: dict[str, Any] = {}
        if contract.atomic_intake:
            from infosec_harness.agents.intake_schema import intake_openai_profile

            extra["profile"] = intake_openai_profile(provider.model_profile(contract.model))
        model = _CompatOpenAIChatModel(
            contract.model, provider=provider, merge_system=contract.merge_system_messages,
            min_max_tokens=contract.min_max_tokens,
            strict_closed_output_tools=contract.strict_closed_output_tools,
            enable_thinking=contract.enable_thinking,
            thinking_token_budget=contract.thinking_token_budget, **extra,
        )
        try:
            settings, params = model.prepare_request(settings, params)
            settings = settings or {}
            tools, _ = model._get_tool_choice(settings, params)
            mapped = await model._map_messages(messages, params, model_settings=settings)
            response_format = None
            if params.output_mode == "native":
                if params.output_object is None:
                    raise BrokerError("policy", "Native output schema is missing")
                response_format = model._map_json_schema(params.output_object)
            elif params.output_mode == "prompted":
                raise BrokerError("policy", "Prompted output is not qualified for admission")
        except BrokerError:
            raise
        except Exception as exc:
            raise BrokerError("policy", "Unsupported admission rendering") from exc
    wire = {"messages": mapped, "tools": tools, "response_format": response_format}
    if contract.enable_thinking is not None or contract.thinking_token_budget is not None:
        wire["extra_body"] = settings["extra_body"]
    if _ascii_normalized_size(wire) > MAX_BODY_BYTES:
        raise BrokerError("policy", "Transformed admission input exceeds rendering bound")
    return wire
