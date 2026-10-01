"""Replay-only retained model: preserve protocol identity, never execute provider I/O."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from types import TracebackType
from typing import Any, NoReturn, Self, cast

from pydantic_ai import RunContext
from pydantic_ai.messages import ModelMessage, ModelResponse
from pydantic_ai.models import ModelRequestContext, ModelRequestParameters, StreamedResponse
from pydantic_ai.models.wrapper import WrapperModel
from pydantic_ai.settings import ModelSettings
from pydantic_ai.usage import RequestUsage
from temporalio import activity
from temporalio.exceptions import ApplicationError


class RetainedModelUnavailable(RuntimeError):
    """An old generation reached a provider operation absent a completed activity result."""


class ReplayOnlyModel(WrapperModel):
    """Install inside durability, on every retained-generation model resolution.

    Completed Temporal activity results replay without calling this model. Executed pending or
    retry-frontier activities fail closed. Identity, profile, settings and pure preparation are
    inherited unchanged; the underlying model is never entered or called.
    """

    @staticmethod
    def _deny() -> NoReturn:
        message = "Retained intake generation is replay-only; start a new workflow"
        if activity.in_activity():
            raise ApplicationError(message, type="RetainedModelUnavailable", non_retryable=True)
        raise RetainedModelUnavailable(message)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        return None

    async def request(
        self,
        messages: list[ModelMessage],
        model_settings: ModelSettings | None,
        model_request_parameters: ModelRequestParameters,
    ) -> ModelResponse:
        self._deny()

    @asynccontextmanager
    async def request_stream(
        self,
        messages: list[ModelMessage],
        model_settings: ModelSettings | None,
        model_request_parameters: ModelRequestParameters,
        run_context: RunContext[Any] | None = None,
    ) -> AsyncIterator[StreamedResponse]:
        self._deny()
        yield cast(
            StreamedResponse, None
        )  # Unreachable: retain the public async-context-manager API.

    async def count_tokens(
        self,
        messages: list[ModelMessage],
        model_settings: ModelSettings | None,
        model_request_parameters: ModelRequestParameters,
    ) -> RequestUsage:
        self._deny()

    async def compact_messages(
        self, request_context: ModelRequestContext, *, instructions: str | None = None
    ) -> ModelResponse:
        self._deny()

    async def cancel_suspended_response(self, response: ModelResponse) -> None:
        self._deny()
