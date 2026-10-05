"""PydanticAI adapter that sends requests only through the authenticated broker."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from typing import Any

import httpx
from pydantic_ai.messages import ModelMessage, ModelResponse
from pydantic_ai.models import Model, ModelRequestParameters

from infosec_harness.inference.catalog.profiles import ControllerChannel
from infosec_harness.inference.executor.compat import contract_profile
from infosec_harness.inference.wire.auth import AUTH_HEADER, sign_request
from infosec_harness.inference.wire.codec import decode_response, encode_payload
from infosec_harness.inference.wire.http_service import JsonChannel
from infosec_harness.inference.wire.protocol import (
    INFER_PATH,
    RESULTS_PATH,
    BrokerError,
    ExecutorContract,
    InferenceRequest,
    InferenceResult,
    ReservationBinding,
    canonical_bytes,
    digest,
    logical_request_id,
)
from infosec_harness.inference.wire.timing import WORKER_TIMEOUT_S, remaining_timeout
from infosec_harness.inference.worker.provenance import (
    CompletedBrokerProvenance,
    TrustedBrokerProvenance,
)


def _durable_request_identity(callback: Callable[[], str] | None) -> str:
    # Temporal activity IDs remain stable across activity retries and take precedence over
    # the local run-step ContextVar, which does not propagate into activity workers.
    try:
        from temporalio import activity

        if activity.in_activity():
            identity = activity.info().activity_id
            if identity:
                return identity
    except (ImportError, RuntimeError):
        pass
    if callback is None:
        raise BrokerError("identity")
    try:
        identity = callback()
    except BrokerError:
        raise
    except Exception:
        raise BrokerError("identity") from None
    if not isinstance(identity, str) or not identity:
        raise BrokerError("identity")
    return identity


class ControllerClient:
    """The worker's one signed controller channel, shared by dispatch and lifecycle calls."""

    def __init__(self, configuration: ControllerChannel, *, transport=None):
        if configuration.url is None or configuration.hmac_env is None:
            raise BrokerError("policy")
        self.configuration, self.transport = configuration, transport

    async def post(self, path: str, body: bytes, *, timeout: float = 30,
                   expires_at: int | None = None) -> dict:
        config = self.configuration
        secret = os.environ.get(config.hmac_env, "").encode()
        expiry = int(time.time()) + 30 if expires_at is None else expires_at
        signature = sign_request(secret, "POST", path, body, expiry)
        channel = JsonChannel(
            ca_file=config.ca_file,
            cert=(config.client_cert, config.client_key) if config.client_cert else None,
            transport=self.transport, boundary="worker_controller",
        )
        return await channel.post(config.url + path, body, {AUTH_HEADER: signature}, timeout=timeout)


class BrokerModel(Model):
    """A static-profile PydanticAI model with no provider client or direct fallback.

    The HTTP client and HMAC key are resolved only while making a request. Each model is
    created for one executor binding; no provider/model cache can cross reservation scope.
    """

    def __init__(
        self,
        *,
        contract: ExecutorContract,
        binding: ReservationBinding,
        controller: ControllerChannel,
        request_identity: Callable[[], str] | None = None,
        http_transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = WORKER_TIMEOUT_S,
    ) -> None:
        if binding.contract_digest != contract.digest:
            raise BrokerError("identity")
        try:
            profile = contract_profile(contract.model, atomic_intake=contract.atomic_intake)
        except Exception:
            raise BrokerError("policy") from None

        super().__init__(settings=contract.model_settings, profile=profile)
        self.contract = contract
        self.binding = binding
        self.controller = ControllerClient(controller, transport=http_transport)
        self.request_identity = request_identity
        self.timeout = timeout

    @property
    def model_name(self) -> str:
        return self.contract.model

    @property
    def system(self) -> str:
        return "openai"

    def _corroborated(self, result: InferenceResult) -> dict[str, Any]:
        """Controller observations are mandatory and must match the admitted contract."""
        provenance = TrustedBrokerProvenance.model_validate(result.provenance)
        if (
            provenance.contract_digest != self.contract.digest
            or provenance.policy_digest != self.contract.policy_digest
            or provenance.executor_image != self.contract.executor_image
            or provenance.supervisor_image != self.contract.supervisor_image
            or provenance.profile != self.contract.profile
        ):
            raise ValueError("Controller provenance differs from the admitted contract")
        return CompletedBrokerProvenance(state="completed", request_id=result.request_id,
                                         **provenance.model_dump()).model_dump(mode="json")

    async def request(
        self,
        messages: list[ModelMessage],
        model_settings: dict[str, Any] | None,
        model_request_parameters: ModelRequestParameters,
    ) -> ModelResponse:
        now = int(time.time())
        expired = self.binding.expires_at <= now
        request_path = RESULTS_PATH if expired else INFER_PATH
        effective_settings = dict(
            self.contract.model_settings if model_settings is None else model_settings
        )
        if effective_settings != self.contract.model_settings:
            raise BrokerError("policy")
        try:
            payload = encode_payload(messages, effective_settings, model_request_parameters)
            identity = _durable_request_identity(self.request_identity)
            request_id = logical_request_id(self.binding, identity)
            request = InferenceRequest(
                request_id=request_id,
                binding=self.binding,
                contract=self.contract,
                payload=payload,
                payload_digest=digest(payload.model_dump(mode="json")),
            )
            body = canonical_bytes(request.model_dump(mode="json"))
            expiry = now + 30 if expired else min(now + 60, int(self.binding.expires_at))
            if expiry <= now:
                raise BrokerError("expired")
        except BrokerError:
            raise
        except Exception:
            raise BrokerError("policy") from None

        timeout = (self.timeout if request_path == RESULTS_PATH
                   else remaining_timeout(request.binding.expires_at, self.timeout))
        value = await self.controller.post(request_path, body, timeout=timeout, expires_at=expiry)
        try:
            result = InferenceResult.model_validate(value)
            if result.request_id != request_id:
                raise ValueError("Controller returned a different request")
            response = decode_response(result.response)
            response.metadata = {**(response.metadata or {}),
                                 "harness_broker": self._corroborated(result)}
            return response
        except Exception:
            raise BrokerError("invalid_response") from None
