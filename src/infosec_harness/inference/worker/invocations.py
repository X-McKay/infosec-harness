"""Worker client for controller-issued invocations, shared by local, eval and Temporal runs.

No database, provider credential or native authority is loaded here; issuance itself is the
controller's :mod:`infosec_harness.inference.controller.issuance`.
"""
from __future__ import annotations

import uuid
from contextlib import asynccontextmanager

from infosec_harness.inference import models
from infosec_harness.inference.wire.protocol import (
    INVOCATIONS_PATH,
    RUN_CLOSE_PATH,
    BrokerError,
    InvocationRequest,
    ReservationBinding,
    canonical_bytes,
    digest,
)
from infosec_harness.inference.worker.transport import ControllerClient


async def request_invocation(request: InvocationRequest) -> ReservationBinding:
    """Ask the controller to bind one invocation; its answer must be exactly that invocation."""
    binding = ReservationBinding.model_validate(
        await ControllerClient(models.broker_catalog().controller).post(
            INVOCATIONS_PATH, canonical_bytes(request.model_dump(mode="json"))))
    if any(getattr(binding, field) != getattr(request, field) for field in
           ("root_id", "run_id", "invocation_id", "operation_id", "agent")) or binding.contract_digest != request.contract.digest:
        raise BrokerError("identity", "Controller returned a different invocation binding")
    return binding


async def close_run(run_id: str, root_id: str) -> None:
    """Authenticated scoped run cleanup; a failed close remains retryable and visible."""
    value = await ControllerClient(models.broker_catalog().controller).post(
        RUN_CLOSE_PATH, canonical_bytes({"root_id": root_id, "run_id": run_id}), timeout=100)
    if value != {"run_id": run_id, "state": "closed"}:
        raise BrokerError("unavailable", "Run cleanup was not acknowledged")


@asynccontextmanager
async def eval_invocation(agent, deps, config, *, configuration_digest):
    """Bound one local eval case to the same approved contract as production."""
    if config.model.broker_contract is None:
        yield deps
        return
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
