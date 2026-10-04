"""Trusted admission/lifecycle service; workers and executors have distinct authorities."""

from __future__ import annotations

import argparse
import asyncio
import importlib
import secrets
import time

from pydantic import Field

from . import ledger as durable_ledger
from .admission import ReservationPolicy, authorize
from .auth import AUTH_HEADER, sign_request, verify_request
from .codec import decode_payload, decode_response
from .diagnostics import report_transport_failure
from .http_service import JsonChannel, parse_body, serve, server_tls
from .protocol import (
    BrokerError,
    DispatchPermit,
    InferenceRequest,
    InferenceResult,
    InvocationRequest,
    StrictModel,
    canonical_bytes,
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


class Controller:
    def __init__(
        self,
        *,
        adapter,
        policies: dict[tuple[str, str], ReservationPolicy],
        worker_key: bytes,
        executor_channel=None,
        ledger=durable_ledger,
        issue_invocation=None,
        clock=time.time,
    ):
        if len(worker_key) < 32:
            raise BrokerError("auth")
        self.adapter, self.policies, self.worker_key = adapter, policies, worker_key
        self.channel = executor_channel or JsonChannel()
        self.ledger, self.issue_invocation, self.clock = ledger, issue_invocation, clock
        self.lifecycle_lock = asyncio.Lock()
        self._reconciliation_tasks: dict[str, tuple[InferenceRequest, asyncio.Task, dict]] = {}

    async def policy(self, request: InferenceRequest) -> ReservationPolicy:
        policy = (
            self.policies(request)
            if callable(self.policies)
            else self.policies.get((request.binding.agent, request.contract.digest))
        )
        if policy is None:
            raise BrokerError("identity")
        await authorize(request, policy)
        return policy

    def lease_identity(self, authorization: str):
        if not authorization.startswith("Bearer "):
            raise BrokerError("auth")
        token = authorization[7:]
        matches = [
            lease
            for lease in self.adapter.leases.values()
            if lease.status == "ready"
            and lease.deployment == self.adapter.deployment
            and secrets.compare_digest(lease.ledger_key, token)
        ]
        if len(matches) != 1:
            raise BrokerError("auth")
        return matches[0]

    async def handle(self, path: str, body: bytes, headers: dict[str, str]) -> dict:
        lower = {key.lower(): value for key, value in headers.items()}
        if path in {"/v1/infer", "/v1/invocations", "/v1/results", "/v1/runs/close"}:
            verify_request(
                self.worker_key,
                "POST",
                path,
                body,
                lower.get(AUTH_HEADER.lower(), ""),
                now=int(self.clock()),
            )
            if path == "/v1/runs/close":
                try:
                    closure = RunClose.model_validate(parse_body(body))
                except Exception:
                    raise BrokerError("identity") from None
                await self.ledger.validate_run_owner(closure.run_id, closure.root_id)
                await self.revoke_run(closure.run_id)
                return {"run_id": closure.run_id, "state": "closed"}
            if path == "/v1/invocations":
                if self.issue_invocation is None:
                    raise BrokerError("unavailable")
                # Callback owns strict schema/catalog + run/reservation ownership checks.
                try:
                    invocation = InvocationRequest.model_validate(parse_body(body))
                    self.adapter.spec(invocation.contract)
                except BrokerError:
                    raise
                except Exception:
                    raise BrokerError("identity") from None
                async with self.lifecycle_lock:
                    if self.adapter.store.is_run_revoked(invocation.run_id):
                        raise BrokerError("identity")
                    binding = await self.issue_invocation(invocation)
                return binding.model_dump(mode="json")
            try:
                request = InferenceRequest.model_validate(parse_body(body))
                decode_payload(request.payload)
            except BrokerError:
                raise
            except Exception:
                raise BrokerError("identity") from None
            if path == "/v1/results":
                stored = await self.ledger.get(request.request_id)
                if stored is None:
                    raise BrokerError("identity")
                if stored.request != request:
                    raise BrokerError("conflict")
                if stored.state == "completed" and stored.result is not None:
                    return stored.result.model_dump(mode="json")
                if stored.state == "completion_unknown":
                    raise BrokerError("completion_unknown")
                if stored.state in {"accepted", "dispatch_intent"}:
                    raise BrokerError("pending")
                raise BrokerError("expired")
            return (await self.infer(request)).model_dump(mode="json")
        if path not in {"/v1/ledger/claim", "/v1/ledger/complete"}:
            raise BrokerError("policy")
        lease = self.lease_identity(lower.get("authorization", ""))
        value = parse_body(body)
        try:
            if path == "/v1/ledger/claim":
                claim = Claim.model_validate(value)
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
            completion = Completion.model_validate(value)
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
        except BrokerError:
            raise
        except Exception:
            raise BrokerError("identity") from None

    async def infer(self, request: InferenceRequest) -> InferenceResult:
        try:
            async with asyncio.timeout(remaining_timeout(request.binding.expires_at, CONTROLLER_TIMEOUT_S, now=self.clock())):
                return await self._infer(request)
        except (TimeoutError, asyncio.CancelledError) as error:
            report_transport_failure("controller", error)
            return await self._reconcile_interrupted_request(request, error)

    async def _reconcile_interrupted_request(self, request: InferenceRequest, error: BaseException) -> InferenceResult:
        existing = self._reconciliation_tasks.get(request.request_id)
        if existing is not None:
            previous, task, outcome = existing
            if previous != request:
                raise BrokerError("conflict") from None
        else:
            outcome = {"state": None, "result": None}
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
                report_transport_failure("controller", TimeoutError())
        except asyncio.CancelledError:
            task.cancel()
            raise
        except BrokerError as reconciliation_error:
            if reconciliation_error.code == "conflict":
                raise
            report_transport_failure("controller", reconciliation_error)
        except Exception as reconciliation_error:
            report_transport_failure("controller", reconciliation_error)
        if isinstance(error, asyncio.CancelledError):
            raise error
        if outcome["state"] == "completed" and outcome["result"] is not None:
            return outcome["result"]
        if outcome["state"] == "completion_unknown":
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
        if stored.state == "accepted":
            try:
                stored = await self.ledger.fail_before_dispatch(request.request_id, lease_id=stored.lease_id)
            except BrokerError as error:
                if error.code != "completion_unknown":
                    raise
                # The claim CAS may have won the race against the preclaim fence.
                stored = await self.ledger.get(request.request_id)
        if stored.state == "dispatch_intent":
            stored = await self.ledger.recover(request.request_id, lease_id=stored.lease_id)
        outcome.update(state=stored.state, result=stored.result)
        if stored.state not in {"failed_before_dispatch", "completion_unknown"}:
            return
        lease = self.adapter.leases.get(stored.lease_id)
        if lease is None or lease.deployment != self.adapter.deployment:
            raise BrokerError("identity")
        # Fencing the durable row first prevents late claims/results even if native
        # cleanup stalls, is cancelled, or needs a later idempotent retry.
        await self.adapter.revoke(lease)

    async def _infer(self, request: InferenceRequest) -> InferenceResult:
        policy = await self.policy(request)
        stored = await self.ledger.get(request.request_id)
        if stored is not None:
            if stored.request != request:
                raise BrokerError("conflict")
            if stored.state == "completed" and stored.result is not None:
                return stored.result
            if stored.state == "dispatch_intent":
                raise BrokerError("pending")
            if stored.state != "accepted":
                raise BrokerError(
                    "completion_unknown" if stored.state == "completion_unknown" else "policy"
                )
            lease = self.adapter.leases.get(stored.lease_id)
            if lease is None or lease.status != "ready":
                raise BrokerError("unavailable")
            await self.adapter.verify(lease)
        else:
            if request.binding.expires_at <= self.clock():
                raise BrokerError("expired")
            async with asyncio.timeout(remaining_timeout(request.binding.expires_at, PREPARATION_TIMEOUT_S, now=self.clock())):
                lease = await self.adapter.ensure(request.binding.run_id, request.contract)
            stored = await self.ledger.admit(
                request, lease_id=lease.lease_id, allocation=await authorize(request, policy)
            )
            if stored.state == "completed" and stored.result:
                return stored.result
            if stored.state != "accepted":
                raise BrokerError("pending")
        body = canonical_bytes(request.model_dump(mode="json"))
        signature = sign_request(
            bytes.fromhex(lease.ingress_key_hex), "POST", "/v1/infer", body, int(self.clock()) + 30
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
        if observed is None or observed.state != "completed" or observed.result is None:
            return await self._reconcile_interrupted_request(request, BrokerError("completion_unknown"))
        return observed.result

    async def recover(self, request_id: str) -> InferenceResult | None:
        stored = await self.ledger.get(request_id)
        if stored is None:
            raise BrokerError("identity")
        lease = self.adapter.leases.get(stored.lease_id)
        if lease is None or lease.deployment != self.adapter.deployment:
            raise BrokerError("identity")
        if stored.state == "dispatch_intent":
            try:
                await self.adapter.revoke(lease)
            finally:
                disposition = await self.ledger.recover(request_id, lease_id=lease.lease_id)
        else:
            disposition = await self.ledger.recover(request_id, lease_id=lease.lease_id)
        return disposition.result

    async def revoke_run(self, run_id: str) -> None:
        async with self.lifecycle_lock:
            # Fence issuance and durable claims before waiting for creation/cleanup.
            self.adapter.store.revoke_run(run_id)
            await self.ledger.revoke_run(run_id)
            async with self.adapter.lock:
                for lease in list(self.adapter.leases.values()):
                    if (
                        lease.run_id == run_id
                        and lease.deployment == self.adapter.deployment
                        and lease.status != "deleted"
                    ):
                        await self.adapter.revoke(lease)


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
    )


if __name__ == "__main__":
    main()
