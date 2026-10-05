"""Credential broker wire contract v1; authority is held by the controller ledger.

Identifiers and contracts are safe to persist. Channel credentials are deliberately absent.
Canonical digests include payloads, never authentication or provider secret material.
"""
from __future__ import annotations

import importlib.metadata
import re
from enum import StrEnum
from functools import cache
from typing import Annotated, Any, Literal, get_args
from urllib.parse import urlsplit

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    ValidationError,
    model_validator,
)

from infosec_harness.domain.canonical import SHA256_PATTERN, canonical_bytes, digest

PROTOCOL_VERSION = "ih-inference-v1"
MAX_BODY_BYTES = 4 * 1024 * 1024
DIGEST_PATTERN = SHA256_PATTERN
IMAGE_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
ENV_NAME_PATTERN = r"^[A-Za-z_][A-Za-z0-9_]*$"
LOGICAL_NAME_PATTERN = r"^[a-z][a-z0-9._-]{0,63}$"
NATIVE_NAME_PATTERN = r"^[A-Za-z0-9._-]{1,128}$"
OpenShellVersion = Literal["0.1.2"]
OPENSHELL_VERSION: str = get_args(OpenShellVersion)[0]

# Worker paths are HMAC-signed (``auth.sign_request``); ledger paths carry only the native
# lease Bearer key and are never signed.
INFER_PATH = "/v1/infer"
INVOCATIONS_PATH = "/v1/invocations"
RESULTS_PATH = "/v1/results"
RUN_CLOSE_PATH = "/v1/runs/close"
LEDGER_CLAIM_PATH = "/v1/ledger/claim"
LEDGER_COMPLETE_PATH = "/v1/ledger/complete"
SIGNED_PATHS: frozenset[str] = frozenset({INFER_PATH, INVOCATIONS_PATH, RESULTS_PATH, RUN_CLOSE_PATH})
# The executor's environment name for its native ledger credential placeholder.
LEDGER_CREDENTIAL_ENV = "IH_LEDGER_TOKEN"


def fixed_https_url(value: str, *, require_origin: bool = False,
                    require_path: str | None = None) -> str:
    """The one fixed-HTTPS URL rule; returns the value without a trailing slash.

    Rejects other schemes, missing hosts, userinfo, queries, fragments and invalid ports.
    ``require_origin`` additionally rejects any path; ``require_path`` requires exactly that
    path (trailing slash ignored). Raises ``ValueError`` so model validators can use it.
    """
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError, AttributeError):
        raise ValueError("Only fixed HTTPS endpoints are supported") from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
        or (require_origin and parsed.path not in {"", "/"})
        or (require_path is not None and parsed.path.rstrip("/") != require_path)
    ):
        raise ValueError("Only fixed HTTPS endpoints are supported")
    return value.rstrip("/")


# The shared field vocabulary of contracts, profiles, settings and provenance.
EnvName = Annotated[str, Field(pattern=ENV_NAME_PATTERN)]
LogicalName = Annotated[str, Field(pattern=LOGICAL_NAME_PATTERN)]
NativeName = Annotated[str, Field(pattern=NATIVE_NAME_PATTERN)]
Sha256 = Annotated[str, Field(pattern=DIGEST_PATTERN)]
ImageDigest = Annotated[str, Field(pattern=IMAGE_DIGEST_PATTERN)]
HttpsOrigin = Annotated[str, AfterValidator(lambda value: fixed_https_url(value, require_origin=True))]
ProviderEndpoint = Annotated[str, AfterValidator(lambda value: fixed_https_url(value, require_path="/v1"))]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


def parse_model[M: BaseModel](cls: type[M], value: Any) -> M:
    """Validate an untrusted wire object; any schema failure is a caller identity failure."""
    try:
        return cls.model_validate(value)
    except ValidationError:
        raise BrokerError("identity") from None


# Closed diagnostic vocabulary: error responses may relay exactly this two-field object.
DiagnosticBoundary = Literal["worker_controller", "json_channel", "provider_request", "server",
                             "controller", "response_codec", "inference", "ledger_complete"]
DiagnosticCategory = Literal["cancelled", "tls", "read_timeout", "connect_timeout", "remote_protocol",
                             "wall_timeout", "network", "provider_status", "provider_schema", "codec",
                             "ledger", "internal"]
DIAGNOSTIC_BOUNDARIES: frozenset[str] = frozenset(get_args(DiagnosticBoundary))
DIAGNOSTIC_CATEGORIES: frozenset[str] = frozenset(get_args(DiagnosticCategory))


def sanitize_diagnostic(value: object) -> dict[str, str] | None:
    """Untrusted observability only; no coercion, extra fields, or authority."""
    if (type(value) is not dict or set(value) != {"boundary", "category"}
            or type(value["boundary"]) is not str or type(value["category"]) is not str
            or value["boundary"] not in DIAGNOSTIC_BOUNDARIES
            or value["category"] not in DIAGNOSTIC_CATEGORIES):
        return None
    return {"boundary": value["boundary"], "category": value["category"]}


def validate_thinking_token_budget(
    budget: int | None, enable_thinking: bool | None, maximum: Any = None,
    *, require_output_cap: bool = False,
) -> None:
    """Validate the typed operator cap, leaving space for an actionable answer."""
    if budget is None:
        return
    if type(budget) is not int or budget <= 0:
        raise ValueError("Thinking token budget must be a strict positive integer")
    if enable_thinking is False:
        raise ValueError("Thinking token budget conflicts with disabled thinking")
    if (require_output_cap or maximum is not None) and (
        type(maximum) is not int or maximum <= budget
    ):
        raise ValueError("Thinking token budget must be below the effective output cap")


class ProviderAdaptation(BaseModel):
    """Opt-in request adaptations shared by operator profiles and executor contracts.

    Defaults are omitted from serialized identities, so profiles and contracts that never
    opted in keep their historical digests.
    """

    strict_closed_output_tools: StrictBool = Field(default=False, exclude_if=lambda value: value is False)
    enable_thinking: StrictBool | None = Field(default=None, exclude_if=lambda value: value is None)
    thinking_token_budget: int | None = Field(
        default=None, gt=0, strict=True, exclude_if=lambda value: value is None)

    @model_validator(mode="after")
    def thinking_budget_leaves_answer_room(self):
        validate_thinking_token_budget(self.thinking_token_budget, self.enable_thinking)
        return self


class ExecutorContract(StrictModel, ProviderAdaptation):
    protocol: Literal["ih-inference-v1"] = PROTOCOL_VERSION
    backend: str = Field(min_length=1, max_length=64)
    model: str = Field(min_length=1, max_length=256)
    profile: str = Field(min_length=1, max_length=64)
    profile_digest: Sha256
    endpoint: ProviderEndpoint
    provider_binding: str = Field(min_length=1, max_length=64)
    executor_image: ImageDigest
    supervisor_image: ImageDigest
    openshell_version: OpenShellVersion = OPENSHELL_VERSION
    sdk_version: Literal["pydantic-ai-2.49.0"] = "pydantic-ai-2.49.0"
    policy_digest: Sha256
    model_settings: dict[str, Any]
    merge_system_messages: StrictBool = True
    min_max_tokens: int = Field(default=0, ge=0, strict=True)
    atomic_intake: StrictBool = False
    provider_retries: Literal[0] = 0
    credential_driver: Literal["native"] = "native"
    inspection: tuple[()] = ()

    @model_validator(mode="after")
    def thinking_budget_fits_output(self):
        validate_thinking_token_budget(self.thinking_token_budget, self.enable_thinking,
                                       self.model_settings.get("max_tokens"), require_output_cap=True)
        return self

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
    contract_digest: Sha256
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
    request_id: Sha256
    binding: ReservationBinding
    contract: ExecutorContract
    payload: InferencePayload
    payload_digest: Sha256

    @model_validator(mode="after")
    def consistent(self) -> InferenceRequest:
        if self.binding.contract_digest != self.contract.digest:
            raise ValueError("Reservation contract mismatch")
        if self.payload_digest != digest(self.payload.model_dump(mode="json")):
            raise ValueError("Payload digest mismatch")
        if self.payload.model_settings != self.contract.model_settings:
            raise ValueError("Effective settings differ from admitted contract")
        return self


class RequestState(StrEnum):
    """Persisted ledger states. Values are the stored strings; never rename them."""

    ACCEPTED = "accepted"
    DISPATCH_INTENT = "dispatch_intent"
    COMPLETED = "completed"
    FAILED_BEFORE_DISPATCH = "failed_before_dispatch"
    COMPLETION_UNKNOWN = "completion_unknown"


ErrorCode = Literal["auth", "policy", "identity", "budget", "expired", "conflict", "pending",
                    "completion_unknown", "unavailable", "invalid_response"]
ERROR_CODES: frozenset[str] = frozenset(get_args(ErrorCode))
# Infrastructure and in-flight dispositions: the identical request may be retried, bounded.
RETRYABLE_CODES: frozenset[str] = frozenset({"unavailable", "pending"})
# HTTP status of each disposition; anything unlisted is served as 503.
ERROR_STATUS: dict[str, int] = {"auth": 401, "policy": 403, "identity": 400, "conflict": 409,
                                "pending": 409, "completion_unknown": 409, "expired": 410}


class BrokerError(RuntimeError):
    """Sanitized typed disposition: unknown completion is never retried as a fresh request."""
    def __init__(self, code: ErrorCode, message: str | None = None, *, diagnostic: object = None):
        self.code = code
        self.diagnostic = sanitize_diagnostic(diagnostic)
        super().__init__(f"Inference broker: {code}" + (f"; {message}" if message else ""))

    @staticmethod
    def of(code: str, *, diagnostic: object = None) -> BrokerError:
        """The worker-visible error: retryable codes keep their distinct activity-retry type."""
        if code in RETRYABLE_CODES:
            return TransientBrokerError(code, diagnostic=diagnostic)  # type: ignore[arg-type]
        return BrokerError(code, diagnostic=diagnostic)  # type: ignore[arg-type]


class TransientBrokerError(BrokerError):
    """Bounded activity retry of the identical request; never a fresh dispatch identity.

    Temporal classifies activity failures by exception type name, and ``BrokerError`` is a
    non-retryable model-activity error type. This distinct type is what lets an unavailable
    or pending model request retry within ``ACTIVITY_RETRY``.
    """
    def __init__(self, code: Literal["unavailable", "pending"], *, diagnostic: object = None):
        if code not in RETRYABLE_CODES:
            raise ValueError("Only infrastructure/pending dispositions may retry")
        super().__init__(code, diagnostic=diagnostic)


class DispatchPermit(StrictModel):
    request_id: Sha256
    fence: str = Field(min_length=1, max_length=128)
    lease_id: str = Field(min_length=1, max_length=128)


class InferenceResult(StrictModel):
    protocol: Literal["ih-inference-v1"] = PROTOCOL_VERSION
    request_id: Sha256
    response: dict[str, Any]
    usage: dict[str, StrictInt] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)


def logical_request_id(binding: ReservationBinding, request_identity: str) -> str:
    """Temporal activity ID or persisted local ordinal; attempt number is excluded."""
    if not request_identity or re.search(r"[\x00-\x1f]", request_identity):
        raise ValueError("A stable model request scheduling identity is required")
    return digest({"run": binding.run_id, "invocation": binding.invocation_id,
                   "request": request_identity, "protocol": PROTOCOL_VERSION})


class InvocationRequest(StrictModel):
    mode: Literal["local", "temporal", "eval"]
    root_id: str = Field(min_length=1, max_length=64)
    run_id: str = Field(min_length=1, max_length=128)
    invocation_id: str = Field(min_length=1, max_length=255)
    operation_id: str = Field(min_length=1, max_length=512)
    agent: str = Field(min_length=1, max_length=48)
    configuration_digest: str = Field(min_length=1, max_length=64)
    contract: ExecutorContract


@cache
def verify_sdk_version() -> None:
    """The installed SDK cannot change within a process; only a passing check is cached."""
    if importlib.metadata.version("pydantic-ai-slim") != "2.49.0":
        raise BrokerError("policy", "Broker protocol v1 requires PydanticAI 2.49.0")
