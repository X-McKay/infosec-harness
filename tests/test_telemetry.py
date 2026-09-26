"""Telemetry is configured from settings and stays inert when no endpoint is set.

The OTel SDK and a collector were already dependencies, but nothing in the code ever
installed a tracer provider, so the compose stack ran Jaeger with no spans reaching it.
"""

from __future__ import annotations

from infosec_harness import telemetry


def test_no_endpoint_means_tracing_stays_off(monkeypatch):
    """Installing a provider with nowhere to send spans silently drops them; don't."""
    telemetry.configure.cache_clear()
    monkeypatch.setenv("HARNESS_OTEL_EXPORTER_OTLP_ENDPOINT", "")
    from infosec_harness.settings import get_settings

    get_settings.cache_clear()
    try:
        assert telemetry.configure("test") is False
    finally:
        telemetry.configure.cache_clear()
        get_settings.cache_clear()


def test_required_resource_attributes_are_present():
    attrs = telemetry.resource_attributes()
    for key in (telemetry.SERVICE_NAME, telemetry.SERVICE_VERSION, telemetry.DEPLOYMENT_ENVIRONMENT):
        assert attrs.get(key), key


def test_absent_build_provenance_is_omitted_not_blank(monkeypatch):
    """An empty git.commit.sha on every span is worse than no attribute at all."""
    from infosec_harness.settings import get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("HARNESS_GIT_COMMIT_SHA", "")
    try:
        assert telemetry.GIT_COMMIT_SHA not in telemetry.resource_attributes()
        get_settings.cache_clear()
        monkeypatch.setenv("HARNESS_GIT_COMMIT_SHA", "abc123")
        assert telemetry.resource_attributes()[telemetry.GIT_COMMIT_SHA] == "abc123"
    finally:
        get_settings.cache_clear()


def test_agent_span_is_a_no_op_without_a_provider():
    """Graph code calls this unconditionally, so it must be safe with tracing off."""
    with telemetry.agent_span("verdict", {"agent.name": "verdict"}) as span:
        span.set_attributes({"agent.cost_usd": 0.0})


def test_correlation_attributes_identify_the_run():
    attrs = telemetry.agent_run_attributes("verdict", "gateway:m", "cfg123", run_id="r1")
    assert attrs["agent.name"] == "verdict"
    assert attrs["agent.config_hash"] == "cfg123"
    assert attrs["agent.model"] == "gateway:m"
    assert attrs["agent.run_id"] == "r1"


def test_outcome_attributes_keep_unknown_cost_distinguishable():
    """Reporting an unknown cost as 0.0 would understate spend; -1 is a sentinel."""
    from infosec_harness.domain.models import AgentOutcome

    outcome = AgentOutcome(output=None, agent="verdict", model_name="m", config_hash="c",
                           input_tokens=1, output_tokens=2, cost_usd=None, cost_estimated=True,
                           latency_s=0.1, tools_called=["read_file"], skills_loaded=["cwe-89"])
    attrs = telemetry.outcome_attributes(outcome)
    assert attrs["agent.cost_usd"] == -1.0
    assert attrs["agent.tools_called"] == "read_file"
    assert attrs["agent.skills_loaded"] == "cwe-89"
