"""Nested wall deadlines enclose inner work without raising provider authority."""
from __future__ import annotations

import asyncio

import httpx
import pytest

from infosec_harness.inference import timing
from infosec_harness.inference.diagnostics import report_transport_failure
from infosec_harness.inference.http_service import JsonChannel
from infosec_harness.inference.protocol import BrokerError


def test_nested_budgets_include_setup_claim_completion_and_response_margin():
    assert timing.PROVIDER_TIMEOUT_S == 90
    assert timing.EXECUTOR_TIMEOUT_S >= 2 * timing.LEDGER_TIMEOUT_S + timing.PROVIDER_TIMEOUT_S
    assert timing.CONTROLLER_TIMEOUT_S >= timing.PREPARATION_TIMEOUT_S + timing.EXECUTOR_TIMEOUT_S + timing.RECONCILIATION_TIMEOUT_S
    assert timing.WORKER_TIMEOUT_S > timing.SERVER_TIMEOUT_S > timing.CONTROLLER_TIMEOUT_S + timing.RECONCILIATION_TIMEOUT_S
    assert timing.WORKER_TIMEOUT_S < 600  # Existing model-activity start-to-close bound.
    assert timing.remaining_timeout(101, timing.WORKER_TIMEOUT_S, now=100) == 1
    for ceiling in (0, -1, float("nan"), float("inf")):
        with pytest.raises(BrokerError, match="policy"):
            timing.remaining_timeout(101, ceiling, now=100)
    with pytest.raises(BrokerError, match="expired"):
        timing.remaining_timeout(100, 1, now=100)


async def test_json_channel_wall_timeout_cancels_even_when_transport_ignores_idle_timeout(caplog):
    sends = []
    async def slow(request):
        sends.append(request)
        await asyncio.sleep(1)
        raise AssertionError("Wall deadline must cancel this transport")
    channel = JsonChannel(transport=httpx.MockTransport(slow))
    with pytest.raises(BrokerError, match="unavailable"):
        await channel.post("https://controller.test/v1/infer", b"{}", {}, timeout=0.02)
    assert len(sends) == 1
    assert "boundary=json_channel category=wall_timeout" in caplog.text


@pytest.mark.parametrize("error,category", [(httpx.ReadTimeout("synthetic-private-body"), "read_timeout"),
    (httpx.ConnectTimeout("synthetic-private-key"), "connect_timeout"),
    (httpx.RemoteProtocolError("synthetic-private-url"), "remote_protocol"),
    (TimeoutError("synthetic-private-payload"), "wall_timeout")])
def test_diagnostics_only_emit_fixed_boundary_and_category(error, category, caplog):
    report_transport_failure("worker_controller", error)
    assert "boundary=worker_controller category=" + category in caplog.text
    assert "synthetic-private" not in caplog.text
