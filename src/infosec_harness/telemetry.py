"""OpenTelemetry setup and the correlation attributes every span must carry (§8).

pydantic-ai emits agent, model, and tool spans; Temporal emits workflow and activity
telemetry. Those run in different processes and at different times, so spans also carry
stable logical identifiers (agent name/version, run id, config hash) that let a triage run
be reassembled across both.

Everything here is a no-op when ``HARNESS_OTEL_EXPORTER_OTLP_ENDPOINT`` is unset, so tests,
the CLI, and offline evals are unaffected.
"""

from __future__ import annotations

from contextlib import contextmanager
from functools import lru_cache
from typing import Any

from infosec_harness.settings import get_settings

# Attribute names. Resource attributes follow OpenTelemetry semantic conventions; the
# agent.* / harness.* ones are the logical correlation keys.
SERVICE_NAME = "service.name"
SERVICE_VERSION = "service.version"
DEPLOYMENT_ENVIRONMENT = "deployment.environment.name"
GIT_COMMIT_SHA = "git.commit.sha"
WORKER_BUILD_ID = "worker.build_id"


def _package_version() -> str:
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("infosec-harness")
    except PackageNotFoundError:  # editable/source checkout without metadata
        return "0.0.0+unknown"


def resource_attributes() -> dict[str, str]:
    """The required resource attributes, whatever the exporter ends up being."""
    s = get_settings()
    attrs = {
        SERVICE_NAME: s.service_name,
        SERVICE_VERSION: _package_version(),
        DEPLOYMENT_ENVIRONMENT: s.environment,
    }
    # Only emit build provenance we actually have; an empty string is worse than absent.
    if s.git_commit_sha:
        attrs[GIT_COMMIT_SHA] = s.git_commit_sha
    if s.worker_build_id:
        attrs[WORKER_BUILD_ID] = s.worker_build_id
    return attrs


@lru_cache
def configure(component: str = "harness") -> bool:
    """Install a tracer provider and OTLP exporter once per process.

    Returns whether tracing is active. Cached, so repeated calls from different entrypoints
    are harmless. With no endpoint configured this does nothing and returns False, rather
    than installing a provider that silently drops spans.
    """
    endpoint = get_settings().otel_exporter_otlp_endpoint
    if not endpoint:
        return False
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    resource = Resource.create({**resource_attributes(), "harness.component": component})
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{endpoint}/v1/traces")))
    trace.set_tracer_provider(provider)

    # Agent specs set `instrument: true`; that only produces spans once a provider exists.
    from pydantic_ai.agent import Agent

    Agent.instrument_all()
    return True


def agent_run_attributes(agent: str, model_name: str, config_hash: str,
                         run_id: str | None = None) -> dict[str, Any]:
    """Logical correlation attributes for one agent invocation."""
    attrs: dict[str, Any] = {
        "agent.name": agent,
        "agent.config_hash": config_hash,
        "agent.model": model_name,
    }
    if run_id:
        attrs["agent.run_id"] = run_id
    return attrs


def outcome_attributes(outcome: Any) -> dict[str, Any]:
    """Cost and usage attributes read off an AgentOutcome after the run."""
    return {
        "agent.input_tokens": outcome.input_tokens,
        "agent.output_tokens": outcome.output_tokens,
        "agent.cache_read_tokens": outcome.cache_read_tokens,
        "agent.cost_usd": outcome.cost_usd if outcome.cost_usd is not None else -1.0,
        "agent.cost_estimated": outcome.cost_estimated,
        "agent.tools_called": ",".join(outcome.tools_called),
        "agent.skills_loaded": ",".join(outcome.skills_loaded),
    }


@contextmanager
def agent_span(agent: str, attributes: dict[str, Any] | None = None):
    """Wrap one agent invocation in a span, or do nothing when tracing is off."""
    from opentelemetry import trace

    tracer = trace.get_tracer("infosec_harness")
    with tracer.start_as_current_span(f"agent {agent}", attributes=attributes or {}) as span:
        yield span
