"""The one typed record of a run's lifecycle timing and measured usage (``TriageRun.telemetry``).

Every writer builds it through the transitions below and every reader parses it here; SQL
filters address a field only through :func:`telemetry_field`, which refuses a name the model does
not declare. Missing measurements stay ``None``: an unknown is never written as a zero.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from infosec_harness.domain.models import AgentOutcome
from infosec_harness.persistence import db

Population = Literal["operational", "demo"]


class RunTelemetry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[2] = 2
    population: Population
    phase: str
    accepted_at: datetime
    updated_at: datetime | None = None
    completed_at: datetime | None = None
    # Acceptance to the first terminal transition; computed only by :meth:`completed`.
    wall_time_s: float | None = None
    agent_time_s: float | None = None
    cost_usd: float | None = None
    known_cost_usd: float | None = None
    accounting_complete: bool | None = None
    cost_accounting_complete: bool | None = None
    known_tokens: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_coverage: float | None = None
    total_tokens: int | None = None

    @classmethod
    def accepted(cls, population: Population, now: datetime) -> RunTelemetry:
        return cls(population=population, phase="accepted", accepted_at=now)

    @classmethod
    def read(cls, value: Mapping[str, Any] | None) -> RunTelemetry | None:
        """Parse a stored record; ``None`` only for a run stored without one."""
        return None if value is None else cls.model_validate(value)

    def stored(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    def progressed(self, phase: str, now: datetime, *, terminal: bool) -> RunTelemetry:
        updated = self.model_copy(update={"phase": phase, "updated_at": now})
        return updated.completed(now) if terminal else updated

    def completed(self, now: datetime) -> RunTelemetry:
        """The first completion wins, so a late write never moves the measured wall time."""
        if self.completed_at is not None:
            return self
        return self.model_copy(update={
            "completed_at": now,
            "wall_time_s": max(0.0, (now - self.accepted_at).total_seconds())})

    def with_usage(self, invocations: Sequence[AgentOutcome],
                   agent_operations: Sequence[Mapping[str, Any]], now: datetime) -> RunTelemetry:
        """Record an output's usage against the root-ledger operations that accounted it.

        Accounting is complete only when every recorded call has exactly one ledger operation
        and every one of those settled: a call with no operation, or an operation with no
        recorded call, means the totals below cannot be shown to be whole.
        """
        accounted = len(agent_operations) == len(invocations)
        complete = accounted and all(op["status"] == "settled" for op in agent_operations)
        cost_complete = accounted and all(
            op["status"] == "settled" or op.get("record", {}).get("pricing_status") == "known_zero"
            for op in agent_operations)
        costs = [i.cost_usd for i in invocations]
        known_cost = sum(c or 0.0 for c in costs)
        known_tokens = sum(i.input_tokens + i.output_tokens for i in invocations)
        whole = bool(invocations) and complete
        return self.completed(now).model_copy(update={
            "agent_time_s": sum(i.latency_s for i in invocations),
            "cost_usd": (known_cost if cost_complete and costs
                         and all(c is not None for c in costs) else None),
            "known_cost_usd": known_cost,
            "accounting_complete": complete,
            "cost_accounting_complete": cost_complete,
            "known_tokens": known_tokens,
            "input_tokens": sum(i.input_tokens for i in invocations) if whole else None,
            "output_tokens": sum(i.output_tokens for i in invocations) if whole else None,
            "total_tokens": known_tokens if whole else None,
            "cost_coverage": sum(c is not None for c in costs) / len(costs) if costs else None,
        })


MetricField = Literal["total_tokens", "input_tokens", "output_tokens", "cost_usd", "wall_time_s",
                      "agent_time_s"]


def telemetry_field(name: str):
    """The JSON column expression for one declared telemetry field."""
    if name not in RunTelemetry.model_fields:
        raise KeyError(f"RunTelemetry declares no field {name!r}")
    return db.TriageRun.telemetry[name]
