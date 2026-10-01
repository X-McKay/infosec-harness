"""Explicit tool-turn allocation; output tools and SDK hard limits are unchanged."""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import nullcontext
from dataclasses import dataclass
from typing import Any

from pydantic_ai import RunContext
from pydantic_ai.capabilities import AbstractCapability, PrepareTools, WrapRunHandler
from pydantic_ai.run import AgentRunResult
from pydantic_ai.tools import ToolDefinition
from temporalio import workflow

from infosec_harness.agents.deps import AgentDeps


@dataclass(frozen=True)
class PlanningWindow:
    policy_version: str
    target_requests: int
    baseline_requests: int

    def __post_init__(self) -> None:
        if (
            not self.policy_version
            or type(self.target_requests) is not int
            or type(self.baseline_requests) is not int
            or not 0 < self.target_requests < self.baseline_requests
        ):
            raise ValueError("Planning window requires a version and a strict positive fraction")

    @classmethod
    def from_metadata(cls, metadata: Mapping[str, Any]) -> PlanningWindow | None:
        value = metadata.get("planning_window")
        return cls(**value) if value is not None else None

    def target(self, request_limit: int | None) -> int | None:
        if type(request_limit) is not int or request_limit < 1:
            return None
        return min(
            request_limit - 1, round(request_limit * self.target_requests / self.baseline_requests)
        )

    async def prepare_tools(
        self, ctx: RunContext[AgentDeps], tool_defs: list[ToolDefinition]
    ) -> list[ToolDefinition]:
        limit = ctx.usage_limits.request_limit if ctx.usage_limits is not None else None
        target = self.target(limit)
        # Unknown allocation never grants tools. Runtime contexts carry an enforced limit.
        requests = ctx.usage.requests
        return (
            tool_defs
            if target is not None and type(requests) is int and 0 <= requests < target
            else []
        )

    def capability(self) -> PrepareTools[AgentDeps]:
        return PrepareTools(self.prepare_tools)

    def diagnostic(self, request_limit: int | None, final_requests: int | None) -> dict[str, Any]:
        target = self.target(request_limit)
        observed = final_requests if type(final_requests) is int and final_requests >= 0 else None
        return {
            "policy_version": self.policy_version,
            "target_requests": self.target_requests,
            "baseline_requests": self.baseline_requests,
            "effective_request_limit": request_limit,
            "effective_target": target,
            "final_requests": observed,
            "cutoff_hit": observed > target
            if observed is not None and target is not None
            else None,
        }


def planning_window_diagnostic(
    metadata: Mapping[str, Any], request_limit: int | None, final_requests: int | None
) -> dict[str, Any]:
    policy = PlanningWindow.from_metadata(metadata)
    return policy.diagnostic(request_limit, final_requests) if policy is not None else {}


# Observation is separate from allocation: no mutable capability counters or deps mutation.
@dataclass
class PlanningWindowTelemetry(AbstractCapability[AgentDeps]):
    policy: PlanningWindow

    async def wrap_run(
        self, ctx: RunContext[AgentDeps], *, handler: WrapRunHandler
    ) -> AgentRunResult[Any]:
        limit = ctx.usage_limits.request_limit if ctx.usage_limits is not None else None
        # SDK after_run hooks run after its invocation span closes. Workflow execution
        # uses replay-aware logging; creating OTel spans there could generate random IDs.
        durable = workflow.in_workflow()
        manager = (
            nullcontext(None)
            if durable
            else ctx.tracer.start_as_current_span(
                "planning_window", record_exception=False, set_status_on_exception=False
            )
        )
        with manager as span:
            result = None
            try:
                result = await handler()
                return result
            finally:
                requests = result.usage.requests if result is not None else None
                value = self.policy.diagnostic(limit, requests)
                if durable:
                    workflow.logger.info("planning_window %s", value)
                else:
                    span.set_attributes(
                        {
                            "agent.planning_window." + key: -1
                            if item is None
                            else int(item)
                            if isinstance(item, bool)
                            else item
                            for key, item in value.items()
                        }
                    )
