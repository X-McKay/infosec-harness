"""Durable agent singletons, built once at import on the host.

Workflows import ``AGENTS`` under ``workflow.unsafe.imports_passed_through()`` so the
Temporal sandbox uses these exact instances (whose toolsets were registered for durable
execution at construction) instead of rebuilding agents inside the workflow.
"""

from __future__ import annotations

from pydantic_ai.agent.spec import AgentSpec

from infosec_harness.agents.intake_generations import intake_generations
from infosec_harness.agents.registry import (
    durable_agents,
    legacy_output_agents,
    resolve_agent_config,
    resolved_agent_configs,
    resolved_model_names,
)
from infosec_harness.resources import package_root

INTAKE_GENERATIONS = intake_generations()
AGENTS = {**durable_agents(), "intake": INTAKE_GENERATIONS["atomic"].agent}
LEGACY_OUTPUT_AGENTS = {**legacy_output_agents(), "intake": INTAKE_GENERATIONS["bare"].agent}
# Both generations must remain registered on every worker which can receive an execution
# started before or after the output-contract patch marker was recorded.
AGENT_LIST = [*AGENTS.values(), *LEGACY_OUTPUT_AGENTS.values(),
              INTAKE_GENERATIONS["quoted"].agent, INTAKE_GENERATIONS["atomic_v3"].agent]

# Resolve eagerly on the worker host; workflow execution must never warm these I/O caches.
CONFIGS = {**resolved_agent_configs(), "intake": INTAKE_GENERATIONS["atomic"].config}
MODELS = {**resolved_model_names(), "intake": INTAKE_GENERATIONS["atomic"].model_name}

# Preserve the specification provenance of recorded env-planner activities. Resolve on the
# worker host, never from inside a replaying workflow; live legacy frontiers remain forbidden.
LEGACY_ENV_PLANNER_CONFIG = resolve_agent_config(
    "env-planner",
    AgentSpec.from_file(package_root() / "agents/env-planner/agent-v1.0.4.yaml"),
    durable=True,
)
