"""Fixed transport categories only: never exception messages, URLs, headers or bodies."""

from __future__ import annotations

import asyncio
import logging
import ssl

import httpcore
import httpx

_LOG = logging.getLogger(__name__)
_BOUNDARIES = frozenset({"worker_controller", "json_channel", "provider_request", "server", "controller"})


def transport_failure_category(error: BaseException) -> str:
    import httpx2

    causes = []
    current: BaseException | None = error
    for _ in range(8):
        if current is None or any(current is value for value in causes):
            break
        causes.append(current)
        current = current.__cause__ or current.__context__
    for value in causes:
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
