"""Controller-only invocation issuance against trusted catalogs and existing root reservations.

The worker never imports this module; its client is :mod:`infosec_harness.inference.worker.invocations`.
"""
from __future__ import annotations

import math
import time
from datetime import datetime
from typing import Any

from sqlalchemy.exc import IntegrityError

from infosec_harness.agents import models
from infosec_harness.inference.controller.admission import ReservationPolicy, bind_reservation
from infosec_harness.inference.wire.protocol import (
    BrokerError,
    InvocationRequest,
    ReservationBinding,
    digest,
)
from infosec_harness.persistence import budgets, db


def trusted_config(agent: str, *, durable: bool):
    from infosec_harness.agents.registry import load_spec, resolve_agent_config
    return resolve_agent_config(agent, load_spec(agent), durable=durable)


def build_reservation_policy(request) -> ReservationPolicy:
    """Never accept model, price, profile or amount choices from a caller as authority."""
    agent = request.agent if isinstance(request, InvocationRequest) else request.binding.agent
    contract = request.contract
    catalog = models.broker_catalog()
    # Durable is part of harness config identity, not the executor access contract.
    config = trusted_config(agent, durable=isinstance(request, InvocationRequest) and request.mode in {"temporal", "eval"})
    if config.model.broker_contract != contract:
        raise BrokerError("identity", "Model contract is not in the controller catalog")
    bounds = catalog.bounds_for_agent(agent)
    _, profile = catalog.profile_for_agent(agent)
    input_cap = bounds.max_input_tokens
    output_cap = bounds.max_output_tokens
    if profile.max_input_tokens_per_request is not None:
        input_cap = min(input_cap, profile.max_input_tokens_per_request,
                        config.budget.effective.max_input_tokens_per_request)
        output_cap = contract.model_settings.get("max_tokens")
        if type(output_cap) is not int or not 0 < output_cap <= bounds.max_output_tokens:
            raise BrokerError("budget", "Effective request output exceeds invocation bounds")
    price = models.custom_prices(config.model.resolved_model)
    if price is None:
        raise BrokerError("budget", "Broker v1 requires explicit reviewed backend price ceilings")
    if any(value is not None and (not math.isfinite(value) or value < 0)
           for value in price.model_dump().values()):
        raise BrokerError("budget", "Invalid reviewed price ceiling")
    # Cache writes can cost more than uncached input. Reserve the greatest input rate.
    input_rate = max(price.input_per_mtok, price.cache_read_per_mtok or 0,
                     price.cache_write_per_mtok if price.cache_write_per_mtok is not None
                     else price.input_per_mtok * 1.25)
    return ReservationPolicy(agent=agent, profile=contract.profile, contract_digest=contract.digest,
        configuration_digest=config.digest, max_input_tokens=input_cap,
        max_output_tokens=output_cap, max_cost_usd=bounds.max_cost_usd,
        input_per_mtok=input_rate, output_per_mtok=price.output_per_mtok)


async def _open_local_root(request: InvocationRequest, policy: ReservationPolicy) -> None:
    """A local or eval run's bounded root, created once and owned by exactly that run."""
    from infosec_harness.agents.registry import BINDINGS

    if request.root_id != digest({"local_run": request.run_id}):
        raise BrokerError("identity", "Local root identity is not tied to its run")
    catalog = models.broker_catalog()
    limits = catalog.root_limits
    state = budgets.initial_state(
        {"requests": limits.max_requests,
         "tokens": limits.max_input_tokens + limits.max_output_tokens,
         "cost_usd": limits.max_cost_usd}, elapsed_seconds=limits.max_duration_seconds)
    state.update(broker_run_id=request.run_id,
        agent_config_digests={name: trusted_config(name, durable=request.mode == "eval").digest
                              for name in BINDINGS})
    async with db.session() as session:
        existing = await session.get(db.BudgetLedger, request.root_id)
        if existing is None:
            session.add(db.BudgetLedger(root_id=request.root_id, state=state))
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()  # Concurrent first issuance may have won.
        elif existing.state.get("broker_run_id") != request.run_id:
            raise BrokerError("identity")
    bounds = catalog.bounds_for_agent(request.agent)
    async with db.session() as session:
        persisted = await session.get(db.BudgetLedger, request.root_id)
        previous = persisted.state.get("operations", {}).get(request.operation_id, {})
        previous_binding = previous.get("broker_binding")
    if not previous_binding:
        await budgets.reserve(request.root_id, request.operation_id,
            {"requests": bounds.max_requests,
             "tokens": bounds.max_input_tokens + bounds.max_output_tokens,
             "cost_usd": 0.0 if policy.input_per_mtok == policy.output_per_mtok == 0 else bounds.max_cost_usd},
            request.agent, request.configuration_digest,
            run_id=request.run_id, invocation_id=request.invocation_id)


async def issue_invocation(value: InvocationRequest | dict[str, Any]) -> ReservationBinding:
    """Controller-only issuance. Local roots are bounded; Temporal roots must already exist."""
    request = InvocationRequest.model_validate(value)
    policy = build_reservation_policy(request)
    if request.configuration_digest != policy.configuration_digest:
        raise BrokerError("identity", "Worker invocation configuration differs from the controller")
    if request.mode in {"local", "eval"}:
        await _open_local_root(request, policy)
    async with db.session() as session:
        root = await session.get(db.BudgetLedger, request.root_id)
        if root is None:
            raise BrokerError("identity", "Temporal root reservation is missing")
        operation = root.state.get("operations", {}).get(request.operation_id)
        if (operation is None or operation.get("agent") != request.agent
                or operation.get("run_id") != request.run_id
                or operation.get("invocation_id") != request.invocation_id):
            raise BrokerError("identity", "Invocation reservation is missing")
        existing_binding = operation.get("broker_binding")
        if existing_binding:
            binding = ReservationBinding.model_validate(existing_binding)
            if (binding.run_id != request.run_id or binding.invocation_id != request.invocation_id
                    or binding.agent != request.agent or binding.contract_digest != request.contract.digest):
                raise BrokerError("conflict")
            await bind_reservation(binding, configuration_digest=request.configuration_digest)
            return binding  # Never renew the original deadline on retry.
        deadline = root.state.get("deadline_at")
        if not deadline:
            raise BrokerError("expired")
        expires = datetime.fromisoformat(deadline).timestamp()
    if expires <= time.time():
        raise BrokerError("expired")
    binding = ReservationBinding(root_id=request.root_id, run_id=request.run_id,
        invocation_id=request.invocation_id, operation_id=request.operation_id,
        agent=request.agent, contract_digest=request.contract.digest, expires_at=expires)
    await bind_reservation(binding, configuration_digest=request.configuration_digest)
    return binding
