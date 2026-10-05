"""PydanticAI adapter that sends requests only through the authenticated broker."""

from __future__ import annotations

import os
import ssl
import time
from collections.abc import Callable
from typing import Any

import httpx
from pydantic import Field
from pydantic_ai.messages import ModelMessage, ModelResponse
from pydantic_ai.models import Model, ModelRequestParameters
from pydantic_ai.profiles import ModelProfileSpec
from pydantic_ai.providers.openai import OpenAIProvider

from infosec_harness.agents.intake_schema import intake_openai_profile
from infosec_harness.inference.auth import AUTH_HEADER, sign_request
from infosec_harness.inference.codec import decode_response, encode_payload
from infosec_harness.inference.diagnostics import report_transport_failure
from infosec_harness.inference.http_service import (
    TRANSPORT_ERRORS,
    parse_response,
    post_bounded,
    response_error,
)
from infosec_harness.inference.protocol import (
    DIGEST_PATTERN,
    IMAGE_DIGEST_PATTERN,
    BrokerError,
    ExecutorContract,
    InferenceRequest,
    InferenceResult,
    ReservationBinding,
    StrictModel,
    TransientBrokerError,
    canonical_bytes,
    digest,
    fixed_https_url,
    logical_request_id,
)
from infosec_harness.inference.timing import WORKER_TIMEOUT_S, remaining_timeout

INFER_PATH = "/v1/infer"
RESULTS_PATH = "/v1/results"
class _TrustedBrokerProvenance(StrictModel):
    """Only the native observations emitted after controller-side verification."""

    native_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    policy_digest: str = Field(pattern=DIGEST_PATTERN)
    executor_image: str = Field(pattern=IMAGE_DIGEST_PATTERN)
    supervisor_image: str = Field(pattern=IMAGE_DIGEST_PATTERN)
    profile: str = Field(pattern=r"^[a-z][a-z0-9._-]{0,63}$")
    credential_revision: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    contract_digest: str = Field(pattern=DIGEST_PATTERN)
    lease_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")


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


def _response_error(status: int, body: bytes) -> BrokerError:
    """Worker view of a non-200 response: infrastructure/pending dispositions may retry."""
    error = response_error(status, body)
    if error.code in {"unavailable", "pending"}:
        transient = TransientBrokerError(error.code)
        transient.diagnostic = error.diagnostic
        return transient
    return error


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
        if not secret_env or not secret_env.replace("_", "a").isalnum():
            raise BrokerError("auth")
        if (client_cert is None) != (client_key is None):
            raise BrokerError("policy")
        try:
            controller_url = fixed_https_url(controller_url, require_origin=True)
        except ValueError:
            raise BrokerError("policy") from None
        try:
            profile: ModelProfileSpec = OpenAIProvider.model_profile(contract.model) or {}
            if contract.atomic_intake:
                profile = intake_openai_profile(profile)
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

        try:
            context = ssl.create_default_context(cafile=self.ca_file)
            if self.client_cert and self.client_key:
                context.load_cert_chain(self.client_cert, self.client_key)
            timeout = (self.timeout if request_path == RESULTS_PATH
                       else remaining_timeout(request.binding.expires_at, self.timeout))
            status, response_body = await post_bounded(
                self.controller_url + request_path, body, {AUTH_HEADER: authorization},
                timeout=timeout, verify=context, transport=self.http_transport,
            )
        except TRANSPORT_ERRORS as error:
            report_transport_failure("worker_controller", error)
            raise TransientBrokerError("unavailable") from None
        if status != 200:
            raise _response_error(status, response_body)

        try:
            result = InferenceResult.model_validate(parse_response(response_body))
            if result.request_id != request_id:
                raise ValueError
            response = decode_response(result.response)
            if result.provenance:
                provenance = _TrustedBrokerProvenance.model_validate(result.provenance)
                if (
                    provenance.contract_digest != self.contract.digest
                    or provenance.policy_digest != self.contract.policy_digest
                    or provenance.executor_image != self.contract.executor_image
                    or provenance.supervisor_image != self.contract.supervisor_image
                    or provenance.profile != self.contract.profile
                ):
                    raise ValueError
                response.metadata = {
                    **(response.metadata or {}),
                    "harness_broker": {
                        "state": "completed",
                        "request_id": result.request_id,
                        **provenance.model_dump(mode="json"),
                    },
                }
            return response
        except Exception:
            raise BrokerError("invalid_response") from None
