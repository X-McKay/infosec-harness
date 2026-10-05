"""PydanticAI adapter that sends requests only through the authenticated broker."""

from __future__ import annotations

import os
import re
import time
from collections.abc import Callable
from typing import Any

import httpx
from pydantic_ai.messages import ModelMessage, ModelResponse
from pydantic_ai.models import Model, ModelRequestParameters

from infosec_harness.inference.auth import AUTH_HEADER, sign_request
from infosec_harness.inference.codec import decode_response, encode_payload
from infosec_harness.inference.compat import contract_profile
from infosec_harness.inference.http_service import JsonChannel
from infosec_harness.inference.protocol import (
    ENV_NAME_PATTERN,
    INFER_PATH,
    RESULTS_PATH,
    BrokerError,
    ExecutorContract,
    InferenceRequest,
    InferenceResult,
    ReservationBinding,
    canonical_bytes,
    digest,
    fixed_https_url,
    logical_request_id,
)
from infosec_harness.inference.provenance import TrustedBrokerProvenance
from infosec_harness.inference.timing import WORKER_TIMEOUT_S, remaining_timeout


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
        controller_url: str,
        secret_env: str,
        ca_file: str | None,
        client_cert: str | None,
        client_key: str | None,
        request_identity: Callable[[], str] | None = None,
        http_transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = WORKER_TIMEOUT_S,
    ) -> None:
        if binding.contract_digest != contract.digest:
            raise BrokerError("identity")
        if not secret_env or not re.fullmatch(ENV_NAME_PATTERN, secret_env):
            raise BrokerError("auth")
        if (client_cert is None) != (client_key is None):
            raise BrokerError("policy")
        try:
            controller_url = fixed_https_url(controller_url, require_origin=True)
        except ValueError:
            raise BrokerError("policy") from None
        try:
            profile = contract_profile(contract.model, atomic_intake=contract.atomic_intake)
        except Exception:
            raise BrokerError("policy") from None

        super().__init__(settings=contract.model_settings, profile=profile)
        self.contract = contract
        self.binding = binding
        self.controller_url = controller_url
        self.secret_env = secret_env
        self.ca_file = ca_file
        self.client_cert = client_cert
        self.client_key = client_key
        self.request_identity = request_identity
        self.http_transport = http_transport
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
        return {"state": "completed", "request_id": result.request_id,
                **provenance.model_dump(mode="json")}

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
            secret_text = os.environ.get(self.secret_env)
            if secret_text is None:
                raise BrokerError("auth")
            secret = secret_text.encode("utf-8")
            expiry = now + 30 if expired else min(now + 60, int(self.binding.expires_at))
            if expiry <= now:
                raise BrokerError("expired")
            authorization = sign_request(secret, "POST", request_path, body, expiry)
        except BrokerError:
            raise
        except Exception:
            raise BrokerError("policy") from None

        timeout = (self.timeout if request_path == RESULTS_PATH
                   else remaining_timeout(request.binding.expires_at, self.timeout))
        channel = JsonChannel(
            ca_file=self.ca_file,
            cert=(self.client_cert, self.client_key) if self.client_cert and self.client_key else None,
            transport=self.http_transport, boundary="worker_controller",
        )
        value = await channel.post(self.controller_url + request_path, body,
                                   {AUTH_HEADER: authorization}, timeout=timeout)
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
