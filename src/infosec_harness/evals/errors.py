"""Closed failure diagnostics that never retain exception messages or provider bodies."""

from __future__ import annotations

import asyncio
from typing import TypedDict

import httpx
import openai
from pydantic_ai.exceptions import ModelAPIError, ModelHTTPError


class FailureDiagnostic(TypedDict):
    error_type: str
    error: str
    http_status_code: int | None
    provider_body_retained: bool


def failure_diagnostic(exc: BaseException) -> FailureDiagnostic:
    """Preserve recognized exception types and bounded HTTP status, not external text."""
    known_types = (
        ModelHTTPError, ModelAPIError, openai.APITimeoutError, openai.APIConnectionError,
        openai.APIStatusError, httpx.TimeoutException, httpx.TransportError,
        TimeoutError, asyncio.CancelledError, KeyboardInterrupt, SystemExit, ValueError,
    )
    error_type = next((kind.__name__ for kind in known_types if isinstance(exc, kind)), "unknown")
    status = None
    if isinstance(exc, ModelHTTPError | openai.APIStatusError):
        candidate = exc.status_code
        if type(candidate) is int and 400 <= candidate <= 599:
            status = candidate
    return {
        "error_type": error_type,
        "error": "exception details omitted",
        "http_status_code": status,
        "provider_body_retained": False,
    }
