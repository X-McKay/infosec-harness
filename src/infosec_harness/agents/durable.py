"""Durable agent singletons and their configurations, built once at import on the host.

Workflows import these under ``workflow.unsafe.imports_passed_through()`` so the Temporal
sandbox uses these exact instances (whose toolsets were registered for durable execution at
construction) instead of rebuilding agents inside the workflow, and so no spec, skill or model
configuration is read as workflow I/O.
"""

from __future__ import annotations

from infosec_harness.agents.registry import durable_agents, resolved_agent_configs

AGENTS = durable_agents()
# Registered once on the worker by the PydanticAI plugin (TriageBatchWorkflow carries them).
AGENT_LIST = list(AGENTS.values())
CONFIGS = resolved_agent_configs()
