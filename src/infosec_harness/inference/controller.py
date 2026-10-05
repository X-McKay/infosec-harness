"""Trusted admission/lifecycle service; workers and executors have distinct authorities."""

from __future__ import annotations

import argparse
import asyncio
import importlib
import time
import weakref
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Protocol

from pydantic import Field

from .admission import ReservationPolicy, authorize
from .auth import AUTH_HEADER, header_value, sign_request, verify_headers
from .codec import decode_payload, decode_response
from .diagnostics import record_failure
from .http_service import JsonChannel, parse_request, serve, server_tls
from .ledger import DurableLedger
from .openshell import Lease, NativeSpec
from .protocol import (
    INFER_PATH,
    INVOCATIONS_PATH,
    LEDGER_CLAIM_PATH,
    LEDGER_COMPLETE_PATH,
    RESULTS_PATH,
    RUN_CLOSE_PATH,
    SIGNED_PATHS,
    BrokerError,
    DispatchPermit,
    ExecutorContract,
    InferenceRequest,
    InferenceResult,
    InvocationRequest,
    RequestState,
    ReservationBinding,
    StrictModel,
    canonical_bytes,
    parse_model,
)
from .timing import (
    CONTROLLER_TIMEOUT_S,
    EXECUTOR_TIMEOUT_S,
    PREPARATION_TIMEOUT_S,
    RECONCILIATION_TIMEOUT_S,
    remaining_timeout,
)


class RunClose(StrictModel):
    run_id: str = Field(min_length=1, max_length=128)
    root_id: str = Field(min_length=1, max_length=128)


class Claim(StrictModel):
    request: InferenceRequest
    lease_id: str = Field(min_length=1, max_length=128)


class Completion(StrictModel):
    permit: DispatchPermit
    result: InferenceResult


class NativeAdapter(Protocol):
    """Executor lease lifecycle; ``openshell.OpenShellAdapter`` is the production adapter.

    The controller sees only leases the adapter owns for its own deployment.
    """

    def spec(self, contract: ExecutorContract) -> NativeSpec: ...

    def service_url(self, lease: Lease) -> str: ...

    def is_deleted(self, lease_id: str) -> bool: ...

    def owned_leases(self) -> dict[str, Lease]: ...

    def lease_for_token(self, token: str) -> Lease: ...

    def fence_run(self, run_id: str) -> None: ...

    def is_run_fenced(self, run_id: str) -> bool: ...

    async def ensure(self, run_id: str, contract: ExecutorContract) -> Lease: ...

    async def verify(self, lease: Lease) -> dict: ...

    async def revoke(self, lease: Lease) -> None: ...

    async def revoke_run(self, run_id: str) -> None: ...

    async def reconcile_recovered(self) -> None: ...


class PolicyResolver(Protocol):
    """Operator catalog lookup; ``None`` means the request has no admission policy."""

    def __call__(self, request: InferenceRequest) -> ReservationPolicy | None: ...


InvocationIssuer = Callable[[InvocationRequest], Awaitable[ReservationBinding]]


def _catalog_resolver(policies: Mapping[tuple[str, str], ReservationPolicy]) -> PolicyResolver:
    catalog = dict(policies)

    def resolve(request: InferenceRequest) -> ReservationPolicy | None:
        return catalog.get((request.binding.agent, request.contract.digest))

    return resolve


class Controller:
    def __init__(
        self,
        *,
        adapter: NativeAdapter,
        policies: PolicyResolver | Mapping[tuple[str, str], ReservationPolicy],
        worker_key: bytes,
        executor_channel: JsonChannel | None = None,
        ledger: DurableLedger | None = None,
        issue_invocation: InvocationIssuer | None = None,
        clock: Callable[[], float] = time.time,
    ):
        if len(worker_key) < 32:
            raise BrokerError("auth")
        self.adapter, self.worker_key = adapter, worker_key
        self.resolve_policy: PolicyResolver = (
            _catalog_resolver(policies) if isinstance(policies, Mapping) else policies
        )
        self.channel = executor_channel or JsonChannel()
        self.ledger = ledger or DurableLedger(clock=clock)
        self.issue_invocation, self.clock = issue_invocation, clock
        # Per-run fence between invocation issuance and run closure; other runs never wait.
        self._run_locks: weakref.WeakValueDictionary[str, asyncio.Lock] = (
            weakref.WeakValueDictionary()
        )
        self._reconciliation_tasks: dict[str, tuple[InferenceRequest, asyncio.Task, dict]] = {}
        # Each path's wire model and handler; worker paths are HMAC-signed, ledger paths
        # authenticate one native lease by its Bearer key.
        self._routes: dict[str, tuple[type[StrictModel], Callable[..., Awaitable[dict]]]] = {
            INFER_PATH: (InferenceRequest, self._handle_infer),
            RESULTS_PATH: (InferenceRequest, self._handle_results),
            INVOCATIONS_PATH: (InvocationRequest, self._handle_invocation),
            RUN_CLOSE_PATH: (RunClose, self._handle_close),
            LEDGER_CLAIM_PATH: (Claim, self._claim),
            LEDGER_COMPLETE_PATH: (Completion, self._complete),
        }

    def _run_lock(self, run_id: str) -> asyncio.Lock:
        lock = self._run_locks.get(run_id)
        if lock is None:
            lock = self._run_locks[run_id] = asyncio.Lock()
        return lock

    async def startup(self) -> None:
        """Operator service startup: reconcile leases left non-terminal by an earlier process."""
        await self.adapter.reconcile_recovered()

    async def policy(self, request: InferenceRequest) -> tuple[ReservationPolicy, dict[str, float]]:
        """The trusted catalog policy and the request's worst-case suballocation under it."""
        policy = self.resolve_policy(request)
        if policy is None:
            raise BrokerError("identity")
        return policy, await authorize(request, policy)

    def lease_identity(self, headers: Mapping[str, str]) -> Lease:
        """The one ready owned lease presenting its exact native ledger Bearer key."""
        authorization = header_value(headers, "Authorization")
        if not authorization.startswith("Bearer "):
            raise BrokerError("auth")
        return self.adapter.lease_for_token(authorization.removeprefix("Bearer "))

    async def handle(self, path: str, body: bytes, headers: Mapping[str, str]) -> dict:
        route = self._routes.get(path)
        if route is None:
            raise BrokerError("policy")
        model, handler = route
        if path in SIGNED_PATHS:
            verify_headers(self.worker_key, path, body, headers, now=int(self.clock()))
            return await handler(parse_model(model, parse_request(body)))
        lease = self.lease_identity(headers)
        message = parse_model(model, parse_request(body))
        try:
            return await handler(lease, message)
        except BrokerError:
            raise
        except Exception:
            # Only request validation is an identity failure; ledger, database and native
            # gateway faults are infrastructure unavailability.
            raise BrokerError("unavailable") from None

    async def _handle_infer(self, request: InferenceRequest) -> dict:
        return (await self.infer(request)).model_dump(mode="json")

    async def _handle_results(self, request: InferenceRequest) -> dict:
        """Read-only saved-result recovery; never admits, provisions or dispatches."""
        decode_payload(request.payload)
        stored = await self.ledger.get(request.request_id)
        if stored is None:
            raise BrokerError("identity")
        if stored.request != request:
            raise BrokerError("conflict")
        return stored.require_completed().model_dump(mode="json")

    async def _handle_invocation(self, invocation: InvocationRequest) -> dict:
        if self.issue_invocation is None:
            raise BrokerError("unavailable")
        # Callback owns strict schema/catalog + run/reservation ownership checks.
        self.adapter.spec(invocation.contract)
        async with self._run_lock(invocation.run_id):
            if self.adapter.is_run_fenced(invocation.run_id):
                raise BrokerError("identity")
            binding = await self.issue_invocation(invocation)
        return binding.model_dump(mode="json")

    async def _handle_close(self, closure: RunClose) -> dict:
        await self.ledger.validate_run_owner(closure.run_id, closure.root_id)
        await self.revoke_run(closure.run_id, closure.root_id)
        return {"run_id": closure.run_id, "state": "closed"}

    async def _claim(self, lease: Lease, claim: Claim) -> dict:
        if claim.lease_id != lease.lease_id:
            raise BrokerError("identity")
        stored = await self.ledger.get(claim.request.request_id)
        if (
            stored is None
            or stored.lease_id != lease.lease_id
            or stored.request != claim.request
            or claim.request.binding.run_id != lease.run_id
            or claim.request.contract != lease.contract
        ):
            raise BrokerError("identity")
        await self.policy(claim.request)
        await self.adapter.verify(lease)
        permit = await self.ledger.claim(claim.request.request_id, lease_id=lease.lease_id)
        return permit.model_dump(mode="json")

    async def _complete(self, lease: Lease, completion: Completion) -> dict:
        if completion.permit.lease_id != lease.lease_id:
            raise BrokerError("identity")
        stored = await self.ledger.get(completion.result.request_id)
        if (
            stored is None
            or stored.lease_id != lease.lease_id
            or stored.request.contract != lease.contract
            or stored.request.binding.run_id != lease.run_id
        ):
            raise BrokerError("identity")
        decode_response(completion.result.response)
        observations = await self.adapter.verify(lease)
        # The executor cannot attest its own provenance; only these observations are kept.
        result = completion.result.model_copy(
            update={
                "provenance": {
                    **observations,
                    "contract_digest": lease.contract.digest,
                    "lease_id": lease.lease_id,
                }
            }
        )
        disposition = await self.ledger.complete(result, permit=completion.permit)
        if disposition.result is None:
            raise BrokerError("invalid_response")
        return disposition.result.model_dump(mode="json")

    async def infer(self, request: InferenceRequest) -> InferenceResult:
        try:
            async with asyncio.timeout(remaining_timeout(request.binding.expires_at, CONTROLLER_TIMEOUT_S, now=self.clock())):
                return await self._infer(request)
        except (TimeoutError, asyncio.CancelledError) as error:
            record_failure("controller", error)
            return await self._reconcile_interrupted_request(request, error)

    async def _reconcile_interrupted_request(self, request: InferenceRequest, error: BaseException) -> InferenceResult:
        existing = self._reconciliation_tasks.get(request.request_id)
        if existing is not None:
            previous, task, outcome = existing
            if previous != request:
                raise BrokerError("conflict") from None
        else:
            outcome: dict[str, Any] = {"state": None, "result": None}
            task = asyncio.create_task(self._reconcile_interrupted(request, outcome))
            self._reconciliation_tasks[request.request_id] = (request, task, outcome)
            task.add_done_callback(lambda completed: self._reconciliation_done(request.request_id, completed))
        try:
            done, _ = await asyncio.wait({task}, timeout=RECONCILIATION_TIMEOUT_S)
            if done:
                # An outer wall timeout can cancel this shared child before
                # re-entering reconciliation. That is not caller cancellation.
                if not task.cancelled():
                    task.result()
            else:
                # Joining a cancelled task can wait indefinitely for its finally
                # cleanup. The durable fence precedes native cleanup below.
                task.cancel()
                record_failure("controller", TimeoutError())
        except asyncio.CancelledError:
            task.cancel()
            raise
        except BrokerError as reconciliation_error:
            if reconciliation_error.code == "conflict":
                raise
            record_failure("controller", reconciliation_error)
        except Exception as reconciliation_error:
            record_failure("controller", reconciliation_error)
        if isinstance(error, asyncio.CancelledError):
            raise error
        if outcome["state"] == RequestState.COMPLETED and outcome["result"] is not None:
            return outcome["result"]
        if outcome["state"] == RequestState.COMPLETION_UNKNOWN:
            diagnostic = error.diagnostic if isinstance(error, BrokerError) else None
            raise BrokerError("completion_unknown", diagnostic=diagnostic) from None
        if isinstance(error, BrokerError):
            raise error
        raise BrokerError("unavailable") from None

    def _reconciliation_done(self, request_id: str, task: asyncio.Task) -> None:
        existing = self._reconciliation_tasks.get(request_id)
        if existing is not None and existing[1] is task:
            del self._reconciliation_tasks[request_id]
        if not task.cancelled():
            task.exception()  # Consume errors without exposing exception content.

    async def _reconcile_interrupted(self, request: InferenceRequest, outcome: dict) -> None:
        stored = await self.ledger.get(request.request_id)
        if stored is None:
            return
        if stored.request != request:
            raise BrokerError("conflict")
        if stored.state == RequestState.ACCEPTED:
            try:
                stored = await self.ledger.fail_before_dispatch(request.request_id, lease_id=stored.lease_id)
            except BrokerError as error:
                if error.code != "completion_unknown":
                    raise
                # The claim CAS may have won the race against the preclaim fence.
                stored = await self.ledger.get(request.request_id)
        if stored.state == RequestState.DISPATCH_INTENT:
            stored = await self.ledger.recover(request.request_id, lease_id=stored.lease_id)
        outcome.update(state=stored.state, result=stored.result)
        if stored.state not in {RequestState.FAILED_BEFORE_DISPATCH, RequestState.COMPLETION_UNKNOWN}:
            return
        lease = self.adapter.owned_leases().get(stored.lease_id)
        if lease is None and self.adapter.is_deleted(stored.lease_id):
            return  # Already cleaned up and retired by an earlier revocation.
        if lease is None:
            raise BrokerError("identity")
        # Fencing the durable row first prevents late claims/results even if native
        # cleanup stalls, is cancelled, or needs a later idempotent retry. The adapter
        # serializes this with every other revocation of the lease.
        await self.adapter.revoke(lease)

    async def _infer(self, request: InferenceRequest) -> InferenceResult:
        policy, allocation = await self.policy(request)
        stored = await self.ledger.get(request.request_id)
        if stored is not None:
            if stored.request != request:
                raise BrokerError("conflict")
            if stored.state != RequestState.ACCEPTED:
                return stored.require_completed()
            lease = self.adapter.owned_leases().get(stored.lease_id)
            if lease is None or lease.status != "ready":
                raise BrokerError("unavailable")
            await self.adapter.verify(lease)
        else:
            if request.binding.expires_at <= self.clock():
                raise BrokerError("expired")
            async with asyncio.timeout(remaining_timeout(request.binding.expires_at, PREPARATION_TIMEOUT_S, now=self.clock())):
                lease = await self.adapter.ensure(request.binding.run_id, request.contract)
            stored = await self.ledger.admit(request, lease_id=lease.lease_id, allocation=allocation)
            if stored.state == RequestState.COMPLETED and stored.result:
                return stored.result
            if stored.state != RequestState.ACCEPTED:
                raise BrokerError("pending")
        body = canonical_bytes(request.model_dump(mode="json"))
        signature = sign_request(
            bytes.fromhex(lease.ingress_key_hex), "POST", INFER_PATH, body, int(self.clock()) + 30
        )
        try:
            await self.channel.post(
                self.adapter.service_url(lease), body, {AUTH_HEADER: signature},
                timeout=remaining_timeout(request.binding.expires_at, EXECUTOR_TIMEOUT_S, now=self.clock())
            )
        except BrokerError as error:
            # A losing duplicate has no dispatch permit; it must not fence the winner.
            if error.code in {"pending", "conflict"}:
                raise
            # A channel timeout is mapped to unavailable: fence before native cleanup
            # here too, including an accepted request whose remote claim is delayed.
            return await self._reconcile_interrupted_request(request, error)

        observed = await self.ledger.get(request.request_id)
        if observed is None or observed.state != RequestState.COMPLETED or observed.result is None:
            return await self._reconcile_interrupted_request(request, BrokerError("completion_unknown"))
        return observed.result

    async def revoke_run(self, run_id: str, root_id: str) -> None:
        """Close one authenticated run: fence issuance and claims, then delete its leases."""
        async with self._run_lock(run_id):
            # Fence issuance and durable claims before waiting for creation/cleanup.
            self.adapter.fence_run(run_id)
            await self.ledger.revoke_run(run_id, root_id=root_id)
            await self.adapter.revoke_run(run_id)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--factory", required=True, help="Trusted installed module:function returning Controller"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18444)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--client-ca")
    args = parser.parse_args()
    module, attribute = args.factory.split(":", 1)
    # Operator CLI code selection is not accessible from any worker/executor request.
    factory = getattr(importlib.import_module(module), attribute)
    core = factory()
    serve(
        core,
        host=args.host,
        port=args.port,
        tls=server_tls(args.cert, args.key, client_ca=args.client_ca),
        startup=core.startup,
    )


if __name__ == "__main__":
    main()
