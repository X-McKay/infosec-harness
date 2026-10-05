"""Fixed transport categories only: never exception messages, URLs, headers or bodies."""

from __future__ import annotations

import asyncio
import logging
import ssl

import httpcore
import httpx

_LOG = logging.getLogger(__name__)
_BOUNDARIES = frozenset({"worker_controller", "json_channel", "provider_request", "server", "controller",
                         "response_codec", "inference", "ledger_complete"})
_CATEGORIES = frozenset({"cancelled", "tls", "read_timeout", "connect_timeout", "remote_protocol",
                         "wall_timeout", "network", "provider_status", "provider_schema", "codec", "ledger", "internal"})


def sanitize_diagnostic(value: object) -> dict[str, str] | None:
    """Untrusted observability only; no coercion, extra fields, or authority."""
    if (type(value) is not dict or set(value) != {"boundary", "category"}
            or type(value["boundary"]) is not str or type(value["category"]) is not str
            or value["boundary"] not in _BOUNDARIES or value["category"] not in _CATEGORIES):
        return None
    return {"boundary": value["boundary"], "category": value["category"]}


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


def transport_failure_category(error: BaseException) -> str:
    import httpx2

    for value in exception_chain(error):
        if isinstance(value, asyncio.CancelledError):
            return "cancelled"
        if isinstance(value, ssl.SSLError):
            return "tls"
        if isinstance(value, (httpx.ReadTimeout, httpx2.ReadTimeout, httpcore.ReadTimeout)):
            return "read_timeout"
        if isinstance(value, (httpx.ConnectTimeout, httpx2.ConnectTimeout, httpcore.ConnectTimeout)):
            return "connect_timeout"
        if isinstance(value, (httpx.RemoteProtocolError, httpx2.RemoteProtocolError, httpcore.RemoteProtocolError)):
            return "remote_protocol"
        if isinstance(value, TimeoutError):
            return "wall_timeout"
    return "network"


def report_transport_failure(boundary: str, error: BaseException) -> None:
    if boundary not in _BOUNDARIES:
        raise ValueError("Unknown diagnostic boundary")
    _LOG.warning("IH_TRANSPORT_FAILURE boundary=%s category=%s", boundary,
                 transport_failure_category(error))
