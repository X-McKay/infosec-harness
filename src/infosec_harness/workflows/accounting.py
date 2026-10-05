"""Replay-safe root reservation around a durable agent invocation or sandbox workload.

The root (batch) and the finding an operation is spent on are passed in explicitly by the
workflow that owns them; nothing here is recovered by parsing workflow identifiers. Every
durable operation is accounted: there is no unaccounted mode.
"""
from __future__ import annotations

import asyncio
import hashlib
from typing import Literal

from temporalio import workflow
from temporalio.exceptions import ActivityError, ApplicationError

with workflow.unsafe.imports_passed_through():
    from pydantic_ai.exceptions import UsageLimitExceeded

    from infosec_harness.domain.models import AgentOutcome
    from infosec_harness.runtime.registry import ACTIVITY_MAX_ATTEMPTS, ResolvedAgentConfig
    from infosec_harness.workflows.activity_options import LEDGER
    from infosec_harness.workflows.payloads import ProgressArgs, ReserveArgs, SettleArgs
    from infosec_harness.workflows.persistence_activities import (
        progress_activity,
        reserve_budget_activity,
        settle_budget_activity,
    )

Identity = tuple[str, str]


class RootAccounting:
    """Reserve and settle one workflow's operations against its batch's root budget.

    ``root_id`` is the batch id. ``fingerprint`` is the finding this workflow's operations are
    attributed to; preparation is attributed to the first finding of its component, as
    everywhere else.
    """

    def __init__(self, root_id: str, fingerprint: str) -> None:
        if not root_id or not fingerprint:
            raise ValueError("Root accounting requires the batch and the finding it is spent on")
        self.root_id = root_id
        self.fingerprint = fingerprint
        self.sequence = 0
        self.exact_operations: set[str] = set()
        self.zero_cost_operations: set[str] = set()

    def _next_operation(self, name: str, *, run_scoped: bool = False) -> str:
        info = workflow.info()
        scope = f"{info.workflow_id}:{info.run_id}" if run_scoped else info.workflow_id
        operation = f"{scope}:{self.sequence}:{name}"
        self.sequence += 1
        return operation

    async def _reserve(self, args: ReserveArgs) -> dict:
        try:
            return await workflow.execute_activity(reserve_budget_activity, args, **LEDGER)
        except ActivityError as exc:
            if isinstance(exc.cause, ApplicationError) and exc.cause.type == "UsageLimitExceeded":
                raise UsageLimitExceeded(str(exc.cause)) from exc
            raise

    def _operation_args(self, operation: str, kind: Literal["agent", "execution"], agent: str,
                        requested: dict[str, float], **ownership: str | None) -> ReserveArgs:
        return ReserveArgs(root_id=self.root_id, operation_id=operation, requested=requested,
                           agent=agent, operation_kind=kind, fingerprint=self.fingerprint,
                           **ownership)

    async def reserve(self, config: ResolvedAgentConfig, *, configuration_digest: str) -> Identity:
        broker_owned = config.model.broker_contract is not None
        operation = self._next_operation(config.agent_name, run_scoped=broker_owned)
        budget = config.budget.effective
        # Transport/activity retries can bill without returning usage. Reserve their full
        # ceiling; do not silently release that uncertainty when a later attempt succeeds.
        factor = ACTIVITY_MAX_ATTEMPTS * (config.model.transport_retries + 1)
        reserved = {"requests": budget.max_requests * factor,
                    "tokens": (budget.max_input_tokens + budget.max_output_tokens) * factor,
                    "cost_usd": (0.0 if config.model.pricing_status == "known_zero"
                                 else budget.max_cost_usd * factor),
                    "tool_calls": budget.max_tool_calls * factor, "agent_runs": 1,
                    "execution_seconds": budget.max_tool_calls * 300 * ACTIVITY_MAX_ATTEMPTS}
        ownership = ({"run_id": workflow.info().run_id, "invocation_id": operation}
                     if broker_owned else {})
        await self._reserve(self._operation_args(
            operation, "agent", config.agent_name, reserved,
            configuration_digest=configuration_digest, **ownership))
        if config.model.pricing_status == "known_zero":
            self.zero_cost_operations.add(operation)
        if config.model.mode == "stub":
            self.exact_operations.add(operation)
        await workflow.execute_activity(progress_activity, ProgressArgs(
            batch_id=self.root_id, fingerprint=self.fingerprint,
            phase=f"agent:{config.agent_name}",
            event_key=hashlib.sha256(operation.encode()).hexdigest()[:20],
            detail=f"Started {config.agent_name}; root budget reserved."), **LEDGER)
        return (self.root_id, operation)

    async def reserve_execution(self, name: str, seconds: float) -> Identity:
        operation = self._next_operation(name)
        await self._reserve(self._operation_args(operation, "execution", name, {
            "requests": 0, "tokens": 0, "cost_usd": 0, "tool_calls": 0, "agent_runs": 0,
            "execution_seconds": seconds}))
        return (self.root_id, operation)

    async def settle(self, identity: Identity, outcome: AgentOutcome | None,
                     failure: str = "", *, partial: AgentOutcome | None = None) -> None:
        """Settle one operation. ``partial`` is a failed call's own record of the requests it
        completed: kept as the record (a lower bound, never an observation that releases the
        reservation) instead of discarding the usage it did report."""
        if outcome is not None:
            record = outcome.model_dump(mode="json")
        elif partial is not None:
            record = {**partial.model_dump(mode="json"), "failure": failure,
                      "usage": "partial_lower_bound"}
        else:
            record = {"failure": failure, "usage": "unavailable"}
        if identity[1] in self.zero_cost_operations:
            record["pricing_status"] = "known_zero"
        # PydanticAI exposes the completed attempt, not billed usage for lost transport
        # attempts. Keep a conservative reservation until provider reconciliation exists.
        observed = None
        if (outcome is not None and identity[1] in self.exact_operations
                and outcome.tool_calls is not None):
            observed = {"requests": outcome.requests,
                        "tokens": outcome.input_tokens + outcome.output_tokens,
                        "cost_usd": outcome.cost_usd or 0.0,
                        "tool_calls": outcome.tool_calls, "agent_runs": 1,
                        "execution_seconds": 0}  # Stub agents execute no real workloads.
        await asyncio.shield(workflow.execute_activity(settle_budget_activity, SettleArgs(
            root_id=identity[0], operation_id=identity[1], observed=observed, record=record),
            **LEDGER))
