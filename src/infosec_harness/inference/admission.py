"""Trusted catalog policy and controller-only reservation binding issuance."""
from __future__ import annotations

import math
import time
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal

from infosec_harness.inference.diagnostics import budget_guard
from infosec_harness.inference.ledger import RETRY, cas_retry, cas_root
from infosec_harness.inference.protocol import BrokerError, InferenceRequest, ReservationBinding
from infosec_harness.inference.rendering import check_request_bounds
from infosec_harness.persistence import db


@dataclass(frozen=True)
class ReservationPolicy:
    """Operator catalog bounds; never deserialize this class from a worker request."""
    agent: str
    profile: str
    contract_digest: str
    configuration_digest: str
    max_input_tokens: int
    max_output_tokens: int
    max_cost_usd: float
    input_per_mtok: float | None = None
    output_per_mtok: float | None = None

    def __post_init__(self) -> None:
        if (isinstance(self.max_input_tokens, bool) or isinstance(self.max_output_tokens, bool)
                or not isinstance(self.max_input_tokens, int) or self.max_input_tokens <= 0
                or not isinstance(self.max_output_tokens, int) or self.max_output_tokens <= 0
                or isinstance(self.max_cost_usd, bool)
                or not isinstance(self.max_cost_usd, (int, float))
                or not math.isfinite(self.max_cost_usd) or self.max_cost_usd < 0):
            raise BrokerError("budget", "Trusted request bounds must be explicit and finite")
        rates = (self.input_per_mtok, self.output_per_mtok)
        if rates == (None, None) and self.max_cost_usd == 0:
            return  # Only the operator catalog may declare a known-zero model.
        if any(rate is None or isinstance(rate, bool) or not isinstance(rate, (int, float))
               or not math.isfinite(rate) or rate < 0 for rate in rates):
            raise BrokerError("budget", "Paid model admission requires both reviewed price ceilings")


async def authorize(request: InferenceRequest, policy: ReservationPolicy) -> dict[str, float]:
    """Validate immutable catalog identity and return worst-case suballocation.

    The codec/executor must enforce these input/output caps before dispatch. Pricing
    verification is an operator-catalog responsibility; an unknown paid price has no policy.
    Expiry is checked in ledger only for new requests/claims, allowing saved-result retrieval.
    """
    if (request.binding.agent != policy.agent or request.contract.profile != policy.profile
            or request.contract.digest != policy.contract_digest):
        raise BrokerError("identity", "Request differs from the trusted admission catalog")
    input_reserve, output = await check_request_bounds(
        request, max_input_tokens=policy.max_input_tokens,
        max_output_tokens=policy.max_output_tokens, boundary="admission")
    cost = 0.0
    if policy.input_per_mtok is not None and policy.output_per_mtok is not None:
        # Exact decimal arithmetic plus an upward float step preserves a conservative
        # ceiling when returning to the existing root ledger's float representation.
        ceiling = (Decimal(input_reserve) * Decimal(str(policy.input_per_mtok))
                   + Decimal(output) * Decimal(str(policy.output_per_mtok))) / Decimal(1_000_000)
        cost = math.nextafter(float(ceiling), math.inf) if ceiling else 0.0
    if not math.isfinite(cost) or cost > policy.max_cost_usd:
        raise budget_guard("admission", "price_ceiling",
                           "Request price ceiling exceeds the trusted invocation cap")
    return {"requests": 1, "tokens": input_reserve + output, "cost_usd": cost}


async def bind_reservation(binding: ReservationBinding, *, configuration_digest: str,
                           clock: Callable[[], float] = time.time) -> None:
    """Install a trusted issuance binding on an existing invocation reservation.

    Call only after controller registration establishes run/invocation/operation ownership.
    Legacy operation JSON does not record run ownership, so worker-selected first bindings
    are not authorization evidence. Existing bindings and optional explicit owners are immutable.
    """
    encoded = binding.model_dump(mode="json")

    async def attempt(session):
        now = clock()
        root = await session.get(db.BudgetLedger, binding.root_id)
        if root is None:
            raise BrokerError("identity", "Root reservation does not exist")
        state = deepcopy(root.state)
        operation = state.get("operations", {}).get(binding.operation_id)
        if (operation is None or operation.get("agent") != binding.agent
                or operation.get("kind", "agent") != "agent"
                or operation.get("status") in {"settled", "closed_unknown"}
                or state.get("agent_config_digests", {}).get(binding.agent) != configuration_digest):
            raise BrokerError("identity", "Invocation does not match the accepted root configuration")
        existing = operation.get("broker_binding")
        if existing is not None:
            if existing != encoded or operation.get("broker_configuration_digest") != configuration_digest:
                raise BrokerError("conflict", "Reservation is already bound to another invocation")
            return None
        if (operation.get("run_id", binding.run_id) != binding.run_id
                or operation.get("invocation_id", binding.invocation_id) != binding.invocation_id):
            raise BrokerError("identity", "Invocation ownership differs from the reserved operation")
        if operation.get("broker_revoked") or binding.run_id in state.get("broker_revoked_runs", []):
            raise BrokerError("policy", "Inference run revoked")
        deadline = state.get("deadline_at")
        if (binding.expires_at <= now or deadline is None
                or binding.expires_at > datetime.fromisoformat(deadline).timestamp()
                or datetime.fromisoformat(deadline).timestamp() <= now):
            raise BrokerError("expired", "Reservation exceeds the root deadline")
        operation.update(broker_binding=encoded, broker_owned=True,
                         broker_configuration_digest=configuration_digest)
        if not await cas_root(session, root, state):
            return RETRY
        await session.commit()
        return None

    await cas_retry(attempt, exhausted="Bounded reservation binding contention exhausted")
