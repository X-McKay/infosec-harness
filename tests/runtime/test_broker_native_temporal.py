"""Explicit native lane qualification only; no automatic native lifecycle actions."""
import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.requires_service(
    "HARNESS_NATIVE_TEMPORAL_CONFIG", "IH_NATIVE_FIXTURE_CONFIG")


async def test_actual_native_agent_string_temporal_saved_retry_and_replay():
    from infosec_harness.qualification.broker.native_temporal import qualify

    report = await qualify(Path(os.environ["HARNESS_NATIVE_TEMPORAL_CONFIG"]))
    assert report["status"] == "passed", report.get("failure_class")
    assert report["provider_dispatches"] == 1
    assert report["maximum_activity_attempt"] == 2
    assert report["same_persisted_request"] is True
    assert report["replay_provider_dispatches"] == 0
    assert report["history_replay"] == report["secret_history_log_scan"] == "passed"
    assert report["worker_cleanup"] == report["workflow_cleanup"] == "passed"
