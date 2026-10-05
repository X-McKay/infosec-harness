"""Fixed failure categories only: never exception messages, URLs, headers or bodies.

Every boundary records a failure through :func:`record_failure`, which logs one fixed marker and
returns the closed two-field diagnostic an error response may relay. Only exception types are
inspected; the vocabulary itself is part of the wire contract in ``protocol``.
"""

from __future__ import annotations

import asyncio
import logging
import ssl

import httpcore
import httpx
import httpx2
from openai import APIConnectionError, APIResponseValidationError, APIStatusError
from pydantic import ValidationError
from pydantic_ai.exceptions import ModelHTTPError, UnexpectedModelBehavior

from infosec_harness.inference.wire.protocol import (
    BrokerError,
    DiagnosticBoundary,
    sanitize_diagnostic,
)

__all__ = ["budget_guard", "exception_chain", "failure_category", "record_failure",
           "report_remote_diagnostic", "sanitize_diagnostic"]

_LOG = logging.getLogger(__name__)
# Channel boundaries see only exchange failures; anything unrecognized there is the network.
_CHANNEL_BOUNDARIES = frozenset({"worker_controller", "json_channel", "server", "controller"})
_TRANSPORT_CATEGORIES: tuple[tuple[type[BaseException] | tuple[type[BaseException], ...], str], ...] = (
    (asyncio.CancelledError, "cancelled"),
    (ssl.SSLError, "tls"),
    ((httpx.ReadTimeout, httpx2.ReadTimeout, httpcore.ReadTimeout), "read_timeout"),
    ((httpx.ConnectTimeout, httpx2.ConnectTimeout, httpcore.ConnectTimeout), "connect_timeout"),
    ((httpx.RemoteProtocolError, httpx2.RemoteProtocolError, httpcore.RemoteProtocolError),
     "remote_protocol"),
    (TimeoutError, "wall_timeout"),
)
_NETWORK = (APIConnectionError, httpx.TransportError, httpx2.TransportError, ConnectionError)
_PROVIDER_STATUS = (APIStatusError, ModelHTTPError)
_PROVIDER_SCHEMA = (APIResponseValidationError, ValidationError, UnexpectedModelBehavior)


def report_remote_diagnostic(value: object) -> dict[str, str] | None:
    diagnostic = sanitize_diagnostic(value)
    if diagnostic is not None:
        _LOG.warning("IH_REMOTE_INFERENCE_FAILURE boundary=%s category=%s",
                     diagnostic["boundary"], diagnostic["category"])
    return diagnostic


def exception_chain(error: BaseException, *, limit: int = 8) -> list[BaseException]:
    """The bounded, cycle-safe cause/context chain; only types are ever inspected."""
    causes: list[BaseException] = []
    current: BaseException | None = error
    while current is not None and len(causes) < limit and not any(current is c for c in causes):
        causes.append(current)
        current = current.__cause__ or current.__context__
    return causes


def failure_category(boundary: DiagnosticBoundary, error: BaseException) -> str:
    """The one closed category for a failure at ``boundary``."""
    causes = exception_chain(error)
    for cause in causes:
        for kinds, category in _TRANSPORT_CATEGORIES:
            if isinstance(cause, kinds):
                return category
    if boundary in _CHANNEL_BOUNDARIES or any(isinstance(cause, _NETWORK) for cause in causes):
        return "network"
    if boundary == "ledger_complete":
        return "ledger"
    if boundary == "response_codec" or isinstance(error, BrokerError) and error.code == "invalid_response":
        return "codec"
    if any(isinstance(cause, _PROVIDER_STATUS) for cause in causes):
        return "provider_status"
    if any(isinstance(cause, _PROVIDER_SCHEMA) for cause in causes):
        return "provider_schema"
    return "internal"


def record_failure(boundary: DiagnosticBoundary, error: BaseException) -> dict[str, str]:
    """Log one fixed marker and return the relayable diagnostic.

    A ``BrokerError`` that already carries a diagnostic was recorded where it occurred; its
    diagnostic is returned unchanged and nothing is logged again. An unknown boundary cannot
    escape: every ``BrokerError`` and serializer re-sanitizes against the closed vocabulary.
    """
    existing = sanitize_diagnostic(error.diagnostic) if isinstance(error, BrokerError) else None
    if existing is not None:
        return existing
    diagnostic = {"boundary": boundary, "category": failure_category(boundary, error)}
    _LOG.warning("IH_INFERENCE_FAILURE boundary=%s category=%s", boundary, diagnostic["category"])
    return diagnostic


def budget_guard(boundary: str, category: str, message: str | None = None,
                 **observations: str | int | float) -> BrokerError:
    """Log one fixed budget marker and return the rejection for the caller to raise.

    Only closed names and finite numbers are ever logged, never request or catalog content.
    """
    detail = "".join(f" {name}={value:g}" if isinstance(value, float) else f" {name}={value}"
                     for name, value in observations.items())
    _LOG.warning("IH_BUDGET_GUARD boundary=%s category=%s%s", boundary, category, detail)
    return BrokerError("budget", message)
