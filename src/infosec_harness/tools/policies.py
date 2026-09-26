"""Load and check the declared tool policies (agent-playbook §5).

A toolset's *effect* is what sets the minimum execution class for every agent that enables it:
a `read` toolset is satisfied by `ephemeral`, a `write_reversible` one requires `durable`, and a
`write_consequential` one requires `human_governed`. Nothing in this system declared that
before, even though it is the rule that makes an execution class meaningful rather than a label.

The directories are hyphenated to match the names agent specs use, so they are data rather than
importable packages; this module reads them.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

TOOLS_DIR = Path(__file__).parent


class ToolEffect(StrEnum):
    read = "read"
    write_reversible = "write_reversible"
    write_consequential = "write_consequential"


class RetrySafety(StrEnum):
    safe = "safe"
    idempotency_key_required = "idempotency_key_required"
    unsafe = "unsafe"


# The execution class an effect requires at minimum. An agent may declare a stronger class;
# it must never declare a weaker one.
MINIMUM_EXECUTION_CLASS: dict[ToolEffect, str] = {
    ToolEffect.read: "ephemeral",
    ToolEffect.write_reversible: "durable",
    ToolEffect.write_consequential: "human_governed",
}
EXECUTION_CLASS_ORDER = ("ephemeral", "durable", "human_governed")


class ToolEntry(BaseModel):
    name: str
    effect: ToolEffect
    notes: str = ""


class ToolPolicy(BaseModel):
    name: str
    owner: str
    toolset_id: str
    description: str
    effect: ToolEffect
    retry_safety: RetrySafety
    timeout_seconds: float = Field(gt=0)
    data_classification: str
    # Every tool must bound its output so a large result cannot flood the model's context.
    max_output_bytes: int = Field(gt=0)
    authorization_scopes: list[str] = Field(default_factory=list)
    tools: list[ToolEntry]
    constraints: list[str]
    risks: list[dict] = Field(default_factory=list)

    @property
    def minimum_execution_class(self) -> str:
        return MINIMUM_EXECUTION_CLASS[self.effect]


@lru_cache
def load_policies() -> dict[str, ToolPolicy]:
    policies: dict[str, ToolPolicy] = {}
    for path in sorted(TOOLS_DIR.glob("*/tool.yaml")):
        policy = ToolPolicy.model_validate(yaml.safe_load(path.read_text()))
        if policy.name != path.parent.name:
            raise ValueError(f"{path}: policy name {policy.name!r} != directory "
                             f"{path.parent.name!r}")
        policies[policy.name] = policy
    return policies


def required_execution_class(toolsets: list[str]) -> str:
    """The strongest class any of these toolsets requires, or `ephemeral` for none."""
    policies = load_policies()
    classes = [policies[name].minimum_execution_class for name in toolsets if name in policies]
    return max([*classes, "ephemeral"], key=EXECUTION_CLASS_ORDER.index)
