"""Credential broker wire contract v1; authority is held by the controller ledger.

Identifiers and contracts are safe to persist. Channel credentials are deliberately absent.
Canonical digests include payloads, never authentication or provider secret material.
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    field_validator,
    model_validator,
)

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
    required: StrictBool = True


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
    merge_system_messages: StrictBool = True
    min_max_tokens: int = Field(default=0, ge=0, strict=True)
    atomic_intake: StrictBool = False
    strict_closed_output_tools: StrictBool = Field(default=False, exclude_if=lambda value: value is False)
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
    expires_at: float = Field(gt=0, strict=True)


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
    def __init__(self, code: ErrorCode, message: str | None = None, *, diagnostic: object = None):
        from .diagnostics import sanitize_diagnostic

        self.code = code
        self.diagnostic = sanitize_diagnostic(diagnostic)
        super().__init__(f"Inference broker: {code}" + (f"; {message}" if message else ""))


class TransientBrokerError(BrokerError):
    """Bounded activity retry of the identical request; never a fresh dispatch identity."""
    def __init__(self, code: Literal["unavailable", "pending"]):
        if code not in {"unavailable", "pending"}:
            raise ValueError("Only infrastructure/pending dispositions may retry")
        super().__init__(code)


class DispatchPermit(StrictModel):
    request_id: str = Field(pattern=DIGEST_PATTERN)
    fence: str = Field(min_length=1, max_length=128)
    lease_id: str = Field(min_length=1, max_length=128)


class InferenceResult(StrictModel):
    protocol: Literal["ih-inference-v1"] = PROTOCOL_VERSION
    request_id: str = Field(pattern=DIGEST_PATTERN)
    response: dict[str, Any]
    usage: dict[str, StrictInt] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)


def logical_request_id(binding: ReservationBinding, request_identity: str) -> str:
    """Temporal activity ID or persisted local ordinal; attempt number is excluded."""
    if not request_identity or re.search(r"[\x00-\x1f]", request_identity):
        raise ValueError("A stable model request scheduling identity is required")
    return digest({"run": binding.run_id, "invocation": binding.invocation_id,
                   "request": request_identity, "protocol": PROTOCOL_VERSION})


def _ascii_normalized_size(value: Any, _depth: int = 0) -> int:
    """Sum without normalizing mapping keys into collisions.

    NFD decomposes every canonical equivalent before ASCII escaping. Taking the
    larger original/NFD size covers original Jinja JSON and NFC UTF-8 bytes. JSON
    punctuation/spacing and HTML-safe escaping are included, not guessed.
    """
    if _depth > 64:
        raise BrokerError("policy", "Admission rendering exceeds nesting bound")
    if isinstance(value, str):
        sizes = []
        # Some supplementary CJK compatibility characters decompose to one BMP
        # character: NFD alone would shrink Jinja's original surrogate-pair JSON.
        for text in (value, unicodedata.normalize("NFD", value)):
            encoded = json.dumps(text, ensure_ascii=True)
            for character, escape in (("<", "\\u003c"), (">", "\\u003e"),
                                      ("&", "\\u0026"), ("'", "\\u0027")):
                encoded = encoded.replace(character, escape)
            sizes.append(len(encoded))
        return max(sizes)
    if isinstance(value, dict):
        return 2 + sum(_ascii_normalized_size(key, _depth + 1) + 2 + _ascii_normalized_size(item, _depth + 1)
                       for key, item in value.items()) + 2 * max(0, len(value) - 1)
    if isinstance(value, (list, tuple)):
        return 2 + sum(_ascii_normalized_size(item, _depth + 1) for item in value) + 2 * max(0, len(value) - 1)
    try:
        return len(json.dumps(value, ensure_ascii=True, allow_nan=False))
    except (ValueError, TypeError, RecursionError) as exc:
        raise BrokerError("policy", "Admission value cannot be rendered") from exc


async def required_input_reserve(payload: InferencePayload, contract: ExecutorContract) -> int:
    """Byte-BPE bound over actual SDK shaping, without provider I/O.

    Requires operator qualification of the tokenizer AND chat template. This covers
    the published Qwen3.6 tokenizer/template at revision
    6c7f09d4036e97393f82e9f9ecd1a5c35ca5ee92: NFC + byte-level BPE gives at most
    one token per normalized byte; all 26 special-token literals consume fewer tokens
    than their byte lengths. The template's fixed tools/system/generation literals
    total <2048 bytes, each role/thinking/tool-response envelope <128 bytes, each
    function-call envelope <128 bytes, and each parameter envelope <64 bytes.
    Content is emitted once; stripping/thinking extraction cannot increase it.

    SDK schema expansion, return-schema descriptions, and retry formatting are
    measured AFTER transformation. Jinja HTML-safe ASCII JSON is bounded by the larger original/NFD
    escaped size. Parsed call arguments are additionally counted because vLLM
    decodes their JSON before XML rendering. Unknown templates/tokenizers need
    separate qualification; a model name is never runtime execution evidence.
    Wire digests/identities remain unchanged. Existing held allocations must not be
    released or dispatched under a different executor image/contract.
    """
    from .compat import input_wire

    wire = await input_wire(payload, contract)
    messages = wire["messages"]
    reserve = _ascii_normalized_size(wire) + 2048 + 128 * len(messages)
    for message in messages:
        for call in message.get("tool_calls", []) or []:
            function = call.get("function", {})
            arguments = function.get("arguments", {})
            try:
                arguments = json.loads(arguments) if isinstance(arguments, str) else arguments
            except (ValueError, TypeError, RecursionError) as exc:
                raise BrokerError("policy", "Tool-call arguments cannot be rendered") from exc
            if not isinstance(arguments, dict):
                raise BrokerError("policy", "Tool-call arguments must be an object")
            reserve += 128 + 64 * len(arguments) + _ascii_normalized_size(arguments)
    return reserve


class InvocationRequest(StrictModel):
    mode: Literal["local", "temporal", "eval"]
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
