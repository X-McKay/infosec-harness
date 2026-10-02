"""Strict operator-owned access profiles for the brokered model transport.

The packaged catalog is disabled until an operator supplies an approved effective
OpenShell policy and controller channel. It never contains credential values.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PositiveFloat,
    PositiveInt,
    field_validator,
    model_validator,
)

from infosec_harness.inference.policy import canonical_policy
from infosec_harness.inference.policy import policy_digest as effective_policy_digest
from infosec_harness.inference.protocol import (
    ExecutorContract,
    ExtensionBinding,
    digest,
    validate_thinking_token_budget,
)
from infosec_harness.resources import package_root

_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_NAME = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
_IMAGE = re.compile(r"^sha256:[a-f0-9]{64}$")
_SECRET_KEYS = re.compile(r"authorization|api[_-]?key|secret|credential|bearer|token", re.I)
REGISTERED_AGENTS = (
    "intake",
    "recon",
    "env-planner",
    "build-repair",
    "partial-build",
    "context",
    "probe-planner",
    "probe-author",
    "probe-diagnosis",
    "probe-repair",
    "verdict",
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False, strict=True)


class InvocationBounds(_StrictModel):
    """Trusted ceilings issued from existing root accounting, never worker input."""

    max_requests: PositiveInt
    max_input_tokens: PositiveInt
    max_output_tokens: PositiveInt
    max_cost_usd: PositiveFloat
    max_duration_seconds: PositiveFloat


class ControllerChannel(_StrictModel):
    """Deployment references for the worker-to-controller HTTPS channel."""

    url: str | None = None
    hmac_env: str | None = None
    ca_file: str | None = None
    client_cert: str | None = None
    client_key: str | None = None

    @field_validator("url")
    @classmethod
    def fixed_https_origin(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = _https_url(value, require_origin=True)
        return parsed

    @field_validator("hmac_env")
    @classmethod
    def environment_reference(cls, value: str | None) -> str | None:
        if value is not None and not _ENV_NAME.fullmatch(value):
            raise ValueError("HMAC key must be referenced by an environment variable name")
        return value

    @field_validator("ca_file", "client_cert", "client_key")
    @classmethod
    def absolute_file_reference(cls, value: str | None) -> str | None:
        if value is not None and (not Path(value).is_absolute() or "\x00" in value):
            raise ValueError("TLS files must use absolute operator-owned paths")
        return value

    @model_validator(mode="after")
    def client_certificate_pair(self) -> ControllerChannel:
        if (self.client_cert is None) != (self.client_key is None):
            raise ValueError("TLS client certificate and key must be configured together")
        return self

    def require_ready(self) -> None:
        if self.url is None or self.hmac_env is None:
            raise ValueError("Broker controller channel is not configured")
        if self.hmac_env not in os.environ:
            raise ValueError("Broker HMAC environment reference is unavailable")
        if len(os.environ[self.hmac_env].encode("utf-8")) < 32:
            raise ValueError("Broker HMAC environment reference must contain at least 32 bytes")
        for path in (self.ca_file, self.client_cert, self.client_key):
            if path is not None and not Path(path).is_file():
                raise ValueError("Configured TLS file is unavailable")


def _https_url(value: str, *, require_origin: bool) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Only fixed HTTPS endpoints are supported") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (require_origin and parsed.path not in {"", "/"})
    ):
        raise ValueError("Only fixed HTTPS endpoints are supported")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("HTTPS endpoint port is invalid")
    return value.rstrip("/")


def _reject_secret_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if _SECRET_KEYS.search(str(key)):
                raise ValueError("Approved policy cannot contain secret or header values")
            _reject_secret_keys(child)
    elif isinstance(value, list):
        for child in value:
            _reject_secret_keys(child)


class ExecutorProfile(_StrictModel):
    """Operator-approved executor template; credentials remain native attachments."""

    backend_name: str | None = None
    backend_kind: Literal["openai_compatible"] = "openai_compatible"
    endpoint: str | None = None
    provider_binding: str | None = None
    provider_env: str | None = None
    ledger_origin: str | None = None
    ledger_profile: str | None = None
    executor_image: str | None = None
    supervisor_image: str | None = None
    approved_policy: dict[str, Any] | None = None
    merge_system_messages: bool = True
    min_max_tokens: int = Field(default=0, ge=0)
    strict_closed_output_tools: bool = Field(default=False, exclude_if=lambda value: value is False)
    enable_thinking: bool | None = Field(default=None, exclude_if=lambda value: value is None)
    thinking_token_budget: int | None = Field(
        default=None, gt=0, strict=True, exclude_if=lambda value: value is None)
    # Request context admission is separate from cumulative invocation allocation.
    # Omission preserves the identity and behavior of existing operator profiles.
    max_input_tokens_per_request: int | None = Field(
        default=None, gt=0, exclude_if=lambda value: value is None)
    credential_driver: Literal["native"] = "native"
    inspection: tuple[ExtensionBinding, ...] = ()
    provider_retries: Literal[0] = 0

    @model_validator(mode="after")
    def thinking_budget_is_consistent(self):
        validate_thinking_token_budget(self.thinking_token_budget, self.enable_thinking)
        return self

    @field_validator("backend_name", "provider_binding", "ledger_profile")
    @classmethod
    def logical_names_only(cls, value: str | None) -> str | None:
        if value is not None and not _NAME.fullmatch(value):
            raise ValueError("Expected a fixed logical name")
        return value

    @field_validator("provider_env")
    @classmethod
    def environment_name_only(cls, value: str | None) -> str | None:
        if value is not None and not _ENV_NAME.fullmatch(value):
            raise ValueError("Provider environment binding must be a variable name")
        return value

    @field_validator("endpoint")
    @classmethod
    def fixed_provider_endpoint(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = urlsplit(_https_url(value, require_origin=False))
        if parsed.path.rstrip("/") != "/v1":
            raise ValueError("Provider endpoint must be a fixed HTTPS /v1 URL")
        return value.rstrip("/")

    @field_validator("ledger_origin")
    @classmethod
    def fixed_ledger_origin(cls, value: str | None) -> str | None:
        return _https_url(value, require_origin=True) if value is not None else None

    @field_validator("executor_image", "supervisor_image")
    @classmethod
    def immutable_image_only(cls, value: str | None) -> str | None:
        if value is not None and not _IMAGE.fullmatch(value):
            raise ValueError("Executor images must be pinned by SHA-256 digest")
        return value

    @field_validator("approved_policy")
    @classmethod
    def policy_is_secret_free_json(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is not None:
            _reject_secret_keys(value)
            # Canonical policy identity validates JSON-only content and rejects malformed
            # effective policy maps before the catalog is trusted.
            effective_policy_digest(value)
        return value

    @field_validator("inspection")
    @classmethod
    def unsupported_inspection_fails_closed(
        cls, value: tuple[ExtensionBinding, ...]
    ) -> tuple[ExtensionBinding, ...]:
        if value:
            raise ValueError("Inspection bindings are unsupported by protocol v1")
        return value

    @property
    def policy_digest(self) -> str | None:
        return (
            effective_policy_digest(self.approved_policy)
            if self.approved_policy is not None
            else None
        )

    @property
    def profile_digest(self) -> str:
        profile = self.model_dump(mode="json", exclude={"backend_name", "min_max_tokens"})
        if self.approved_policy is not None:
            profile["approved_policy"] = canonical_policy(self.approved_policy)
        return digest(profile)

    def require_complete(self) -> None:
        required = (
            self.backend_name,
            self.endpoint,
            self.provider_binding,
            self.provider_env,
            self.ledger_origin,
            self.ledger_profile,
            self.executor_image,
            self.supervisor_image,
            self.approved_policy,
        )
        if any(value is None for value in required):
            raise ValueError("Executor profile is incomplete")


class BrokerConfig(_StrictModel):
    """Packaged catalog plus operator-selected transport and trusted invocation ceilings."""

    version: Literal[1] = 1
    enabled: bool = False
    controller: ControllerChannel = Field(default_factory=ControllerChannel)
    profiles: dict[str, ExecutorProfile]
    agent_profiles: dict[str, str]
    root_limits: InvocationBounds
    agent_limits: dict[str, InvocationBounds]
    pricing_identity: str | None = None

    @field_validator("pricing_identity")
    @classmethod
    def nonsecret_pricing_identity(cls, value: str | None) -> str | None:
        if value is not None and (not value or len(value) > 256 or _SECRET_KEYS.search(value)):
            raise ValueError("Pricing identity must be nonsecret metadata")
        return value

    @model_validator(mode="after")
    def catalog_is_complete(self) -> BrokerConfig:
        agents = set(REGISTERED_AGENTS)
        if set(self.agent_profiles) != agents or set(self.agent_limits) != agents:
            missing_profile = sorted(agents - set(self.agent_profiles))
            extra_profile = sorted(set(self.agent_profiles) - agents)
            missing_limits = sorted(agents - set(self.agent_limits))
            extra_limits = sorted(set(self.agent_limits) - agents)
            raise ValueError(
                "Agent catalog mismatch "
                f"(profile missing={missing_profile}, extra={extra_profile}; "
                f"limits missing={missing_limits}, extra={extra_limits})"
            )
        if not self.profiles or any(not _NAME.fullmatch(name) for name in self.profiles):
            raise ValueError("At least one fixed named executor profile is required")
        if set(self.agent_profiles.values()) - set(self.profiles):
            raise ValueError("Every agent must name a catalog profile")
        for name, limits in self.agent_limits.items():
            if (
                limits.max_requests > self.root_limits.max_requests
                or limits.max_input_tokens > self.root_limits.max_input_tokens
                or limits.max_output_tokens > self.root_limits.max_output_tokens
                or limits.max_cost_usd > self.root_limits.max_cost_usd
                or limits.max_duration_seconds > self.root_limits.max_duration_seconds
            ):
                raise ValueError(f"Agent bounds exceed root limits for {name}")
        if self.enabled:
            if self.controller.url is None or self.controller.hmac_env is None:
                raise ValueError("Enabled broker requires an authenticated controller channel")
            for name, profile in self.profiles.items():
                try:
                    profile.require_complete()
                except ValueError as exc:
                    raise ValueError(f"Enabled profile {name!r} is incomplete") from exc
        return self

    def bounds_for_agent(self, agent: str) -> InvocationBounds:
        try:
            return self.agent_limits[agent]
        except KeyError as exc:
            raise ValueError("Unknown registered agent") from exc

    def profile_for_agent(self, agent: str) -> tuple[str, ExecutorProfile]:
        try:
            profile_name = self.agent_profiles[agent]
            return profile_name, self.profiles[profile_name]
        except KeyError as exc:
            raise ValueError("Unknown registered agent or access profile") from exc

    def resolve_contract(
        self,
        agent: str,
        backend: str,
        model: str,
        model_settings: dict[str, Any],
        *,
        backend_endpoint: str,
        atomic_intake: bool = False,
        merge_system_messages: bool = True,
        min_max_tokens: int = 0,
        strict_closed_output_tools: bool = False,
        enable_thinking: bool | None = None,
        thinking_token_budget: int | None = None,
    ) -> ExecutorContract:
        """Resolve a secret-free executor contract from trusted effective settings."""
        if not self.enabled:
            raise ValueError("Brokered model transport is disabled")
        profile_name, profile = self.profile_for_agent(agent)
        profile.require_complete()
        if profile.backend_name != backend:
            raise ValueError("Backend is not admitted by the selected access profile")
        if _https_url(backend_endpoint, require_origin=False) != profile.endpoint:
            raise ValueError("Backend endpoint differs from the operator-approved profile")
        if merge_system_messages != profile.merge_system_messages:
            raise ValueError("Message adaptation differs from the approved profile")
        if min_max_tokens != profile.min_max_tokens:
            raise ValueError("Output-token floor differs from the approved profile")
        if enable_thinking is not profile.enable_thinking:
            raise ValueError("Thinking control differs from the approved profile")
        validate_thinking_token_budget(thinking_token_budget, enable_thinking)
        if thinking_token_budget != profile.thinking_token_budget:
            raise ValueError("Thinking token budget differs from the approved profile")
        if strict_closed_output_tools != profile.strict_closed_output_tools:
            raise ValueError("Strict output adaptation differs from the approved profile")
        if atomic_intake != (agent == "intake"):
            raise ValueError("Atomic intake profile is valid only for the intake agent")

        from infosec_harness.inference.codec import validate_settings

        effective = dict(model_settings)
        validate_settings(effective)
        maximum = effective.get("max_tokens")
        if type(maximum) is not int or maximum > self.bounds_for_agent(agent).max_output_tokens:
            raise ValueError("Effective output tokens exceed the trusted agent bound")
        assert profile.endpoint is not None
        assert profile.provider_binding is not None
        assert profile.executor_image is not None
        assert profile.supervisor_image is not None
        assert profile.policy_digest is not None
        return ExecutorContract(
            backend=backend,
            model=model,
            profile=profile_name,
            profile_digest=profile.profile_digest,
            endpoint=profile.endpoint,
            provider_binding=profile.provider_binding,
            executor_image=profile.executor_image,
            supervisor_image=profile.supervisor_image,
            policy_digest=profile.policy_digest,
            model_settings=effective,
            merge_system_messages=merge_system_messages,
            min_max_tokens=min_max_tokens,
            atomic_intake=atomic_intake,
            strict_closed_output_tools=strict_closed_output_tools,
            enable_thinking=enable_thinking,
            thinking_token_budget=thinking_token_budget,
            provider_retries=0,
            credential_driver="native",
            inspection=(),
        )


def load_broker_config(path: Path | None = None) -> BrokerConfig:
    """Load and validate packaged/operator YAML, including full registry coverage."""
    source = path or (package_root() / "config" / "credential-broker.yaml")
    try:
        value = yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ValueError("Broker profile catalog cannot be loaded") from exc
    try:
        # Pydantic's strict Python-mode validation intentionally rejects list-to-tuple
        # coercion. YAML sequences are JSON arrays at this boundary, so validate their
        # JSON representation instead of weakening strict field validation.
        encoded = json.dumps(value, allow_nan=False, separators=(",", ":"))
        config = BrokerConfig.model_validate_json(encoded)
    except (TypeError, ValueError) as exc:
        raise ValueError("Broker profile catalog is invalid") from exc

    # Keep the registry as source of truth without importing it at module load time.
    from infosec_harness.agents.registry import AGENT_BINDINGS

    if set(config.agent_profiles) != set(AGENT_BINDINGS):
        raise ValueError("Broker profile mappings do not match the registered agent set")
    return config
