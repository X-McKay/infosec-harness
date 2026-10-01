"""Provider shaping shared by direct workers and isolated inference executors."""
from __future__ import annotations

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


