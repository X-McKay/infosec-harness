"""Durable agent singletons, built once at import on the host.

Workflows import ``AGENTS`` under ``workflow.unsafe.imports_passed_through()`` so the
Temporal sandbox uses these exact instances (whose toolsets were registered for durable
execution at construction) instead of rebuilding agents inside the workflow.
"""

from __future__ import annotations

from infosec_harness.agents.registry import (
    durable_agents,
    legacy_output_agents,
    resolved_agent_configs,
    resolved_model_names,
)

AGENTS = durable_agents()
LEGACY_OUTPUT_AGENTS = legacy_output_agents()
# Both generations must remain registered on every worker which can receive an execution
# started before or after the output-contract patch marker was recorded.
AGENT_LIST = [*AGENTS.values(), *LEGACY_OUTPUT_AGENTS.values()]

# Resolve eagerly on the worker host; workflow execution must never warm these I/O caches.
CONFIGS = resolved_agent_configs()
MODELS = resolved_model_names()
