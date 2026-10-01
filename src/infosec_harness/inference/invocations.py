"""Trusted issuance and worker client shared by local, eval, and Temporal activities."""
from __future__ import annotations

import math
import time
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

from sqlalchemy.exc import IntegrityError

from infosec_harness.inference.admission import ReservationPolicy, bind_reservation
from infosec_harness.inference.auth import AUTH_HEADER, sign_request
from infosec_harness.inference.http_service import JsonChannel
from infosec_harness.inference.protocol import (
    BrokerError,
    InvocationRequest,
    ReservationBinding,
    canonical_bytes,
    digest,
)
from infosec_harness.persistence import budgets, db


def trusted_config(agent: str, *, durable: bool):
    from infosec_harness.agents.registry import load_spec, resolve_agent_config
    return resolve_agent_config(agent, load_spec(agent), durable=durable)


def build_reservation_policy(request) -> ReservationPolicy:
    """Never accept model, price, profile or amount choices from a caller as authority."""
    from infosec_harness.agents import models
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
    if profile.max_input_tokens_per_request is not None:
        input_cap = min(input_cap, profile.max_input_tokens_per_request,
                        config.budget.effective.max_input_tokens_per_request)
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
        max_output_tokens=bounds.max_output_tokens, max_cost_usd=bounds.max_cost_usd,
        input_per_mtok=input_rate, output_per_mtok=price.output_per_mtok)


async def issue_invocation(value: InvocationRequest | dict[str, Any]) -> ReservationBinding:
    """Controller-only issuance. Local roots are bounded; Temporal roots must already exist."""
    request = InvocationRequest.model_validate(value)
    from infosec_harness.agents import models
    from infosec_harness.inference.profiles import REGISTERED_AGENTS
    policy = build_reservation_policy(request)
    if request.configuration_digest != policy.configuration_digest:
        raise BrokerError("identity", "Worker invocation configuration differs from the controller")
    catalog = models.broker_catalog()
    if request.mode in {"local", "eval"}:
        if request.root_id != digest({"local_run": request.run_id}):
            raise BrokerError("identity", "Local root identity is not tied to its run")
        limits = catalog.root_limits
        state = budgets.initial_state(
            {"requests": limits.max_requests,
             "tokens": limits.max_input_tokens + limits.max_output_tokens,
             "cost_usd": limits.max_cost_usd}, elapsed_seconds=limits.max_duration_seconds)
        state.update(broker_run_id=request.run_id,
            agent_config_digests={name: trusted_config(name, durable=request.mode == "eval").digest
                                  for name in REGISTERED_AGENTS})
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
             "cost_usd": 0.0 if policy.input_per_mtok == policy.output_per_mtok == 0 else bounds.max_cost_usd}, request.agent, request.configuration_digest,
            run_id=request.run_id, invocation_id=request.invocation_id)
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


async def request_invocation(request: InvocationRequest) -> ReservationBinding:
    """Worker-side HTTPS; provider credentials and native authority are never loaded here."""
    import os

    from infosec_harness.agents import models
    channel = models.broker_catalog().controller
    body = canonical_bytes(request.model_dump(mode="json"))
    key = os.environ.get(channel.hmac_env or "", "").encode()
    signature = sign_request(key, "POST", "/v1/invocations", body, int(time.time()) + 30)
    client = JsonChannel(ca_file=channel.ca_file,
                         cert=(channel.client_cert, channel.client_key) if channel.client_cert else None)
    result = await client.post(channel.url + "/v1/invocations", body, {AUTH_HEADER: signature})
    binding = ReservationBinding.model_validate(result)
    if any(getattr(binding, field) != getattr(request, field) for field in
           ("root_id", "run_id", "invocation_id", "operation_id", "agent")) or binding.contract_digest != request.contract.digest:
        raise BrokerError("identity", "Controller returned a different invocation binding")
    return binding


async def close_run(run_id: str, root_id: str) -> None:
    """Authenticated scoped run cleanup; a failed close remains retryable and visible."""
    import os

    from infosec_harness.agents import models
    channel = models.broker_catalog().controller
    body = canonical_bytes({"root_id": root_id, "run_id": run_id})
    signature = sign_request(os.environ.get(channel.hmac_env or "", "").encode(),
        "POST", "/v1/runs/close", body, int(time.time()) + 30)
    client = JsonChannel(ca_file=channel.ca_file,
                         cert=(channel.client_cert, channel.client_key) if channel.client_cert else None)
    value = await client.post(channel.url + "/v1/runs/close", body, {AUTH_HEADER: signature}, timeout=100)
    if value != {"run_id": run_id, "state": "closed"}:
        raise BrokerError("unavailable", "Run cleanup was not acknowledged")


@asynccontextmanager
async def eval_invocation(agent, deps, config, *, configuration_digest):
    """Bound one local eval case to the same approved contract as production."""
    if config.model.broker_contract is None:
        yield deps
        return
    import uuid
    run_id = "eval-" + uuid.uuid4().hex
    root_id = digest({"local_run": run_id})
    invocation_id = run_id + ":0:" + agent
    binding = await request_invocation(InvocationRequest(mode="eval", root_id=root_id,
        run_id=run_id, invocation_id=invocation_id, operation_id=invocation_id, agent=agent,
        configuration_digest=configuration_digest, contract=config.model.broker_contract))
    try:
        yield deps.model_copy(update={"broker_binding": binding,
                                     "broker_contract": config.model.broker_contract})
    finally:
        await close_run(run_id, root_id)
