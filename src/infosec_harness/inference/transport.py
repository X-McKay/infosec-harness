"""PydanticAI adapter that sends requests only through the authenticated broker."""

from __future__ import annotations

import os
import ssl
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import httpx
from pydantic import Field
from pydantic_ai.messages import ModelMessage, ModelResponse
from pydantic_ai.models import Model, ModelRequestParameters
from pydantic_ai.profiles import ModelProfileSpec
from pydantic_ai.providers.openai import OpenAIProvider

from infosec_harness.agents.intake_schema import intake_openai_profile
from infosec_harness.inference.auth import AUTH_HEADER, sign_request
from infosec_harness.inference.codec import decode_response, encode_payload
from infosec_harness.inference.http_service import parse_body
from infosec_harness.inference.protocol import (
    BrokerError,
    ExecutorContract,
    InferenceRequest,
    InferenceResult,
    ReservationBinding,
    StrictModel,
    TransientBrokerError,
    canonical_bytes,
    digest,
    logical_request_id,
)

INFER_PATH = "/v1/infer"
RESULTS_PATH = "/v1/results"
_ERROR_CODES = {
    "auth",
    "policy",
    "identity",
    "budget",
    "expired",
    "conflict",
    "pending",
    "completion_unknown",
    "unavailable",
    "invalid_response",
}


class _TrustedBrokerProvenance(StrictModel):
    """Only the native observations emitted after controller-side verification."""

    native_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    policy_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    executor_image: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    supervisor_image: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    profile: str = Field(pattern=r"^[a-z][a-z0-9._-]{0,63}$")
    credential_revision: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    contract_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
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
    """Map known remote dispositions without propagating response or transport text."""
    try:
        value = parse_body(body)
    except BrokerError:
        value = None
    code = value.get("error") if isinstance(value, dict) else None
    if status != 200:
        code = code if code in _ERROR_CODES else "unavailable"
        return TransientBrokerError(code) if code in {"unavailable", "pending"} else BrokerError(code)
    return BrokerError("invalid_response")


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
        timeout: float = 90.0,
    ) -> None:
        if binding.contract_digest != contract.digest:
            raise BrokerError("identity")
        if not secret_env or not secret_env.replace("_", "a").isalnum():
            raise BrokerError("auth")
        if (client_cert is None) != (client_key is None):
            raise BrokerError("policy")
        parsed = urlsplit(controller_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise BrokerError("policy")
        try:
            _ = parsed.port
            profile: ModelProfileSpec = OpenAIProvider.model_profile(contract.model) or {}
            if contract.atomic_intake:
                profile = intake_openai_profile(profile)
        except Exception:
            raise BrokerError("policy") from None

        super().__init__(settings=contract.model_settings, profile=profile)
        self.contract = contract
        self.binding = binding
        self.controller_url = controller_url.rstrip("/")
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
            cert: str | tuple[str, str] | None = None
            if self.client_cert and self.client_key:
                cert = (self.client_cert, self.client_key)
                context.load_cert_chain(*cert)
            async with (
                httpx.AsyncClient(
                    verify=context,
                    cert=cert,
                    trust_env=False,
                    follow_redirects=False,
                    transport=self.http_transport,
                    timeout=self.timeout,
                ) as client,
                client.stream(
                    "POST",
                    self.controller_url + request_path,
                    content=body,
                    headers={"Content-Type": "application/json", AUTH_HEADER: authorization},
                ) as response,
            ):
                received = bytearray()
                async for chunk in response.aiter_bytes():
                    received.extend(chunk)
                    if len(received) > 4 * 1024 * 1024:
                        raise BrokerError("invalid_response")
                response_body = bytes(received)
                if response.status_code != 200:
                    raise _response_error(response.status_code, response_body)
        except BrokerError:
            raise
        except (httpx.HTTPError, OSError, ssl.SSLError, ValueError):
            raise TransientBrokerError("unavailable") from None
        except Exception:
            raise TransientBrokerError("unavailable") from None

        try:
            value = parse_body(response_body)
            result = InferenceResult.model_validate(value)
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
