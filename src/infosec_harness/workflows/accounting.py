"""Replay-safe root reservation around a durable agent invocation."""
from __future__ import annotations

import asyncio
import hashlib
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError, ApplicationError

with workflow.unsafe.imports_passed_through():
    from pydantic_ai.exceptions import UsageLimitExceeded

    from infosec_harness.agents.registry import ACTIVITY_MAX_ATTEMPTS, ResolvedAgentConfig
    from infosec_harness.domain.models import AgentOutcome
    from infosec_harness.workflows.progress import (
        progress_activity,
        reserve_budget_activity,
        settle_budget_activity,
    )

_POLICY = dict(start_to_close_timeout=timedelta(seconds=30),
               retry_policy=RetryPolicy(maximum_attempts=3,
                   non_retryable_error_types=["UsageLimitExceeded", "ValueError"]))


class RootAccounting:
    def __init__(self) -> None:
        self.sequence = 0
        self.exact_operations: set[str] = set()
        self.zero_cost_operations: set[str] = set()

    def _root_id(self) -> str | None:
        if not workflow.patched("root-budget-v1"):
            return None
        info = workflow.info()
        root = info.root.workflow_id if info.root else info.workflow_id
        # Temporal 1.25 omits root metadata. Our preparation and finding workflows
        # are direct children of the batch, whose parent identity is still available.
        # Gate the fallback so histories which previously skipped reservations replay.
        if (not info.root and workflow.patched("root-budget-parent-v1")
                and info.parent and info.parent.workflow_id.startswith("batch:")):
            root = info.parent.workflow_id
        if not root.startswith("batch:"):
            return None
        root_id = root.removeprefix("batch:")
        return root_id

    async def reserve(self, config: ResolvedAgentConfig, *,
                      configuration_digest: str | None = None) -> tuple[str, str] | None:
        root_id = self._root_id()
        if root_id is None:
            return None
        info = workflow.info()
        operation = f"{info.workflow_id}:{self.sequence}:{config.agent_name}"
        self.sequence += 1
        budget = config.budget.effective
        # Transport/activity retries can bill without returning usage. Reserve their full
        # ceiling; do not silently release that uncertainty when a later attempt succeeds.
        factor = ACTIVITY_MAX_ATTEMPTS * (config.model.transport_retries + 1)
        reserved = {"requests": budget.max_requests * factor,
                    "tokens": (budget.max_input_tokens + budget.max_output_tokens) * factor,
                    "cost_usd": 0.0 if config.model.pricing_status == "known_zero" else budget.max_cost_usd * factor}
        if workflow.patched("root-budget-dimensions-v2"):
            reserved.update(tool_calls=budget.max_tool_calls * factor, agent_runs=1,
                            execution_seconds=budget.max_tool_calls * 300 * ACTIVITY_MAX_ATTEMPTS)
        args = {"root_id": root_id, "operation_id": operation, "requested": reserved,
                "agent": config.agent_name}
        if workflow.patched("root-config-identity-v1"):
            args["configuration_digest"] = configuration_digest
        try:
            result = await workflow.execute_activity(reserve_budget_activity, args, **_POLICY)
        except ActivityError as exc:
            if isinstance(exc.cause, ApplicationError) and exc.cause.type == "UsageLimitExceeded":
                raise UsageLimitExceeded(str(exc.cause)) from exc
            raise
        if result is not None:
            if config.model.pricing_status == "known_zero":
                self.zero_cost_operations.add(operation)
            if config.model.mode == "stub":
                self.exact_operations.add(operation)
            parts = info.workflow_id.split(":")
            fingerprint = parts[1] if parts[0] == "triage" else parts[-1]
            await workflow.execute_activity(progress_activity,
                {"batch_id": root_id, "fingerprint": fingerprint,
                 "phase": f"agent:{config.agent_name}",
                 "event_key": hashlib.sha256(operation.encode()).hexdigest()[:20],
                 "detail": f"Started {config.agent_name}; root budget reserved."}, **_POLICY)
        return (root_id, operation) if result is not None else None

    async def reserve_execution(self, name: str, seconds: float) -> tuple[str, str] | None:
        if not workflow.patched("root-execution-budget-v1"):
            return None
        root_id = self._root_id()
        if root_id is None:
            return None
        operation = f"{workflow.info().workflow_id}:{self.sequence}:{name}"
        self.sequence += 1
        try:
            result = await workflow.execute_activity(reserve_budget_activity,
                {"root_id": root_id, "operation_id": operation,
                 "requested": {"requests": 0, "tokens": 0, "cost_usd": 0,
                               "tool_calls": 0, "agent_runs": 0, "execution_seconds": seconds},
                 "agent": name, "operation_kind": "execution"}, **_POLICY)
        except ActivityError as exc:
            if isinstance(exc.cause, ApplicationError) and exc.cause.type == "UsageLimitExceeded":
                raise UsageLimitExceeded(str(exc.cause)) from exc
            raise
        return (root_id, operation) if result is not None else None

    async def settle(self, identity: tuple[str, str] | None, outcome: AgentOutcome | None,
                     failure: str = "") -> None:
        if identity is None:
            return
        record = outcome.model_dump(mode="json") if outcome else {"failure": failure, "usage": "unavailable"}
        if identity[1] in self.zero_cost_operations:
            record["pricing_status"] = "known_zero"
        # PydanticAI exposes the completed attempt, not billed usage for lost transport
        # attempts. Keep a conservative reservation until provider reconciliation exists.
        observed = None
        if (outcome is not None and identity[1] in self.exact_operations
                and (not workflow.patched("root-budget-dimensions-v2")
                     or outcome.tool_calls is not None)):
            observed = {"requests": outcome.requests,
                        "tokens": outcome.input_tokens + outcome.output_tokens,
                        "cost_usd": outcome.cost_usd or 0.0}
            if workflow.patched("root-budget-dimensions-v2"):
                observed.update(tool_calls=outcome.tool_calls or 0, agent_runs=1,
                                execution_seconds=0)  # Stub agents execute no real workloads.
        await asyncio.shield(workflow.execute_activity(settle_budget_activity,
            {"root_id": identity[0], "operation_id": identity[1], "observed": observed,
             "record": record}, **_POLICY))
