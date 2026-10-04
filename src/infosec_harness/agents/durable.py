"""Durable agent singletons, built once at import on the host.

Workflows import ``AGENTS`` under ``workflow.unsafe.imports_passed_through()`` so the
Temporal sandbox uses these exact instances (whose toolsets were registered for durable
execution at construction) instead of rebuilding agents inside the workflow.
"""

from __future__ import annotations

from pydantic_ai.agent.spec import AgentSpec

from infosec_harness.agents.intake_generations import intake_generations
from infosec_harness.agents.registry import (
    build_agent,
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
# Retained pre-serial model settings and original output-v2 activity identities.
# Exact retained specs are resolved on the worker host; workflow code never reads files.
RETAINED_BUILD_SPECS = {
    name: AgentSpec.from_file(package_root() / f"agents/{name}/agent-v{version}.yaml")
    for name, version in {"build-repair": "1.0.5", "partial-build": "1.1.3"}.items()
}
RETAINED_BUILD_AGENTS = {
    name: build_agent(name, spec_override=spec, execution_name=f"{name}-output-v2")
    for name, spec in RETAINED_BUILD_SPECS.items()
}
RETAINED_BUILD_CONFIGS = {
    name: resolve_agent_config(name, spec, durable=True)
    for name, spec in RETAINED_BUILD_SPECS.items()
}
# Both generations must remain registered on every worker which can receive an execution
# started before or after the output-contract patch marker was recorded.
AGENT_LIST = [*AGENTS.values(), *LEGACY_OUTPUT_AGENTS.values(),
              *RETAINED_BUILD_AGENTS.values(),
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
