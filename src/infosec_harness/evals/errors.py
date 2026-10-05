"""Closed failure diagnostics that never retain exception messages or provider bodies."""

from __future__ import annotations

import asyncio
from typing import NotRequired, TypedDict

import httpx
import openai
from pydantic_ai.exceptions import ModelAPIError, ModelHTTPError

from infosec_harness.inference.protocol import ERROR_CODES, BrokerError


class FailureDiagnostic(TypedDict):
    error_type: str
    error: str
    http_status_code: int | None
    provider_body_retained: bool
    broker_error_code: NotRequired[str]


def failure_diagnostic(exc: BaseException) -> FailureDiagnostic:
    """Preserve recognized exception types and bounded HTTP status, not external text."""
    known_types = (
        BrokerError,
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
    result: FailureDiagnostic = {
        "error_type": error_type,
        "error": "exception details omitted",
        "http_status_code": status,
        "provider_body_retained": False,
    }
    if isinstance(exc, BrokerError):
        code = exc.code
        # Neither arbitrary exception text nor forged/unrecognized disposition names
        # become evidence. Historical non-broker diagnostics retain their exact shape.
        result["broker_error_code"] = (
            code if type(code) is str and code in ERROR_CODES else "unknown")
    return result
