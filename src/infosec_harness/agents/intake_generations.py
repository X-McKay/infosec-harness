"""Host-built immutable intake generations: protocol and accounting move together."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from types import MappingProxyType
from typing import Any, Literal, cast

from pydantic_ai import Agent
from pydantic_ai.messages import UserContent

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.agents.intake_claims import WIRE_VERSION
from infosec_harness.agents.intake_contracts import (
    IntakeProtocol,
    render_intake_prompt,
    retained_atomic_intake_spec,
    retained_intake_spec,
)
from infosec_harness.agents.intake_evidence import INTAKE_EVIDENCE_POLICY_VERSION
from infosec_harness.agents.registry import (
    ResolvedAgentConfig,
    build_agent,
    load_spec,
    resolve_agent_config,
)
from infosec_harness.domain.models import ExtractedFinding

IntakeGenerationName = Literal["bare", "quoted", "atomic_v3", "atomic"]


@dataclass(frozen=True)
class IntakeGeneration:
    agent: Agent[AgentDeps, ExtractedFinding]
    config: ResolvedAgentConfig
    model_name: str
    protocol: IntakeProtocol

    def render_prompt(self, task: str, payload: dict[str, Any]) -> list[UserContent]:
        return render_intake_prompt(task, payload, protocol=self.protocol)


@lru_cache
def intake_generations() -> Mapping[IntakeGenerationName, IntakeGeneration]:
    retained = retained_intake_spec()
    current = load_spec("intake")
    bundles: dict[IntakeGenerationName, IntakeGeneration] = {}
    for key, spec, execution, legacy, atomic in (
        ("bare", retained, "intake", True, False),
        ("quoted", retained, "intake-output-v2", False, False),
        ("atomic_v3", retained_atomic_intake_spec(), "intake-output-v3", False, True),
        ("atomic", current, "intake-output-v4", False, True),
    ):
        config = resolve_agent_config("intake", spec, durable=True, replay_only=not atomic)
        agent = build_agent(
            "intake",
            spec_override=spec,
            execution_name=execution,
            legacy_output_contract=legacy,
            atomic_output=atomic,
            replay_only_model=not atomic,
        )
        bundles[cast(IntakeGenerationName, key)] = IntakeGeneration(
            agent=cast(Agent[AgentDeps, ExtractedFinding], agent),
            config=config,
            model_name=config.model.resolved_model,
            protocol=WIRE_VERSION if atomic else INTAKE_EVIDENCE_POLICY_VERSION,
        )
    return MappingProxyType(bundles)
