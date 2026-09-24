"""Durable agent singletons, built once at import on the host.

Workflows import ``AGENTS`` under ``workflow.unsafe.imports_passed_through()`` so the
Temporal sandbox uses these exact instances (whose toolsets were registered for durable
execution at construction) instead of rebuilding agents inside the workflow.
"""

from __future__ import annotations

from infosec_harness.agents.registry import durable_agents

AGENTS = durable_agents()
AGENT_LIST = list(AGENTS.values())
