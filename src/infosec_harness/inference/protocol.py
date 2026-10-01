"""Credential broker wire contract v1; authority is held by the controller ledger.

Identifiers and contracts are safe to persist. Channel credentials are deliberately absent.
Canonical digests include payloads, never authentication or provider secret material.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

PROTOCOL_VERSION = "ih-inference-v1"
MAX_BODY_BYTES = 4 * 1024 * 1024
DIGEST_PATTERN = r"^[a-f0-9]{64}$"


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class ExtensionBinding(StrictModel):
    implementation: str
    version: str
    required: bool = True


class ExecutorContract(StrictModel):
    protocol: Literal["ih-inference-v1"] = PROTOCOL_VERSION
    backend: str = Field(min_length=1, max_length=64)
    model: str = Field(min_length=1, max_length=256)
    profile: str = Field(min_length=1, max_length=64)
    profile_digest: str = Field(pattern=DIGEST_PATTERN)
    endpoint: str
    provider_binding: str = Field(min_length=1, max_length=64)
    executor_image: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    supervisor_image: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    openshell_version: Literal["0.1.2"] = "0.1.2"
    sdk_version: Literal["pydantic-ai-2.49.0"] = "pydantic-ai-2.49.0"
    policy_digest: str = Field(pattern=DIGEST_PATTERN)
    model_settings: dict[str, Any]
    merge_system_messages: bool = True
    min_max_tokens: int = Field(default=0, ge=0)
    atomic_intake: bool = False
    provider_retries: Literal[0] = 0
    credential_driver: Literal["native"] = "native"
    inspection: tuple[ExtensionBinding, ...] = ()

    @field_validator("endpoint")
    @classmethod
    def endpoint_is_fixed_https(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or parsed.path.rstrip("/") != "/v1"):
            raise ValueError("Only a fixed HTTPS /v1 provider endpoint is supported")
        return value.rstrip("/")

    @field_validator("inspection")
    @classmethod
    def reject_extensions(cls, value: tuple[ExtensionBinding, ...]) -> tuple[ExtensionBinding, ...]:
        if value:
            raise ValueError("Inspection bindings are unsupported in protocol v1")
        return value

    @property
    def digest(self) -> str:
        return digest(self.model_dump(mode="json"))


class ReservationBinding(StrictModel):
    """Nonsecret reference; the controller checks the existing root reservation."""
    root_id: str = Field(min_length=1, max_length=64)
    run_id: str = Field(min_length=1, max_length=128)
    invocation_id: str = Field(min_length=1, max_length=255)
    operation_id: str = Field(min_length=1, max_length=512)
    agent: str = Field(min_length=1, max_length=48)
    contract_digest: str = Field(pattern=DIGEST_PATTERN)
    expires_at: float = Field(gt=0)


class InferencePayload(StrictModel):
    # Typed PydanticAI JSON, validated before dispatch by codec.py.
    messages: list[dict[str, Any]] = Field(min_length=1)
    parameters: dict[str, Any]
    model_settings: dict[str, Any]

    @model_validator(mode="after")
    def bounded(self) -> InferencePayload:
        if len(canonical_bytes(self.model_dump(mode="json"))) > MAX_BODY_BYTES:
            raise ValueError("Inference payload exceeds protocol limit")
        return self


class InferenceRequest(StrictModel):
    protocol: Literal["ih-inference-v1"] = PROTOCOL_VERSION
    request_id: str = Field(pattern=DIGEST_PATTERN)
    binding: ReservationBinding
    contract: ExecutorContract
    payload: InferencePayload
    payload_digest: str = Field(pattern=DIGEST_PATTERN)

    @model_validator(mode="after")
    def consistent(self) -> InferenceRequest:
        if self.binding.contract_digest != self.contract.digest:
            raise ValueError("Reservation contract mismatch")
        if self.payload_digest != digest(self.payload.model_dump(mode="json")):
            raise ValueError("Payload digest mismatch")
        if self.payload.model_settings != self.contract.model_settings:
            raise ValueError("Effective settings differ from admitted contract")
        return self


RequestState = Literal["accepted", "dispatch_intent", "completed", "failed_before_dispatch",
                       "completion_unknown"]
ErrorCode = Literal["auth", "policy", "identity", "budget", "expired", "conflict", "pending",
                    "completion_unknown", "unavailable", "invalid_response"]


class BrokerError(RuntimeError):
    """Sanitized typed disposition: unknown completion is never retried as a fresh request."""
    def __init__(self, code: ErrorCode, message: str | None = None):
        self.code = code
        super().__init__(f"Inference broker: {code}" + (f"; {message}" if message else ""))


class DispatchPermit(StrictModel):
    request_id: str = Field(pattern=DIGEST_PATTERN)
    fence: str = Field(min_length=1, max_length=128)
    lease_id: str = Field(min_length=1, max_length=128)


class InferenceResult(StrictModel):
    protocol: Literal["ih-inference-v1"] = PROTOCOL_VERSION
    request_id: str = Field(pattern=DIGEST_PATTERN)
    response: dict[str, Any]
    usage: dict[str, int] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)


def logical_request_id(binding: ReservationBinding, request_identity: str) -> str:
    """Temporal activity ID or persisted local ordinal; attempt number is excluded."""
    if not request_identity or re.search(r"[\x00-\x1f]", request_identity):
        raise ValueError("A stable model request scheduling identity is required")
    return digest({"run": binding.run_id, "invocation": binding.invocation_id,
                   "request": request_identity, "protocol": PROTOCOL_VERSION})


def required_input_reserve(payload: InferencePayload) -> int:
    """Conservative byte/framing bound for operator-qualified byte tokenizers only.

    Qualification of a provider's tokenizer/context cap is required independently.
    Unknown tokenizers cannot use this bound as evidence of admission safety.
    """
    parts = sum(len(message.get("parts", [])) for message in payload.messages)
    tools = sum(len(payload.parameters.get(key, []) or []) for key in
                ("function_tools", "output_tools", "builtin_tools"))
    return len(canonical_bytes(payload.model_dump(mode="json"))) + 1024 * (parts + tools + 1)


class InvocationRequest(StrictModel):
    mode: Literal["local", "temporal"]
    root_id: str = Field(min_length=1, max_length=64)
    run_id: str = Field(min_length=1, max_length=128)
    invocation_id: str = Field(min_length=1, max_length=255)
    operation_id: str = Field(min_length=1, max_length=512)
    agent: str = Field(min_length=1, max_length=48)
    configuration_digest: str = Field(min_length=1, max_length=64)
    contract: ExecutorContract



def verify_sdk_version() -> None:
    import importlib.metadata
    if importlib.metadata.version("pydantic-ai-slim") != "2.49.0":
        raise BrokerError("policy", "Broker protocol v1 requires PydanticAI 2.49.0")
