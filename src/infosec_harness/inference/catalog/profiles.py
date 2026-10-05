"""Strict operator-owned access profiles for the brokered model transport.

The packaged catalog is disabled until an operator supplies an approved effective
OpenShell policy and controller channel. It never contains credential values.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Literal, Protocol

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

from infosec_harness.inference.catalog.policy import canonical_policy
from infosec_harness.inference.catalog.policy import policy_digest as effective_policy_digest
from infosec_harness.inference.wire.codec import validate_settings
from infosec_harness.inference.wire.protocol import (
    LOGICAL_NAME_PATTERN,
    EnvName,
    ExecutorContract,
    ExtensionBinding,
    HttpsOrigin,
    ImageDigest,
    LogicalName,
    ProviderAdaptation,
    ProviderEndpoint,
    digest,
    fixed_https_url,
)
from infosec_harness.resources import package_root

_SECRET_KEYS = re.compile(r"authorization|api[_-]?key|secret|credential|bearer|token", re.I)


class BackendAdaptation(Protocol):
    """The operator backend fields a contract must match; ``models.BackendConfig`` provides them."""

    base_url: str | None
    merge_system_messages: bool
    min_max_tokens: int
    strict_closed_output_tools: bool
    enable_thinking: bool | None
    thinking_token_budget: int | None


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

    url: HttpsOrigin | None = None
    hmac_env: EnvName | None = None
    ca_file: str | None = None
    client_cert: str | None = None
    client_key: str | None = None

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


def _reject_secret_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if _SECRET_KEYS.search(str(key)):
                raise ValueError("Approved policy cannot contain secret or header values")
            _reject_secret_keys(child)
    elif isinstance(value, list):
        for child in value:
            _reject_secret_keys(child)


class ExecutorProfile(_StrictModel, ProviderAdaptation):
    """Operator-approved executor template; credentials remain native attachments."""

    backend_name: LogicalName | None = None
    backend_kind: Literal["openai_compatible"] = "openai_compatible"
    endpoint: ProviderEndpoint | None = None
    provider_binding: LogicalName | None = None
    provider_env: EnvName | None = None
    ledger_origin: HttpsOrigin | None = None
    ledger_profile: LogicalName | None = None
    executor_image: ImageDigest | None = None
    supervisor_image: ImageDigest | None = None
    approved_policy: dict[str, Any] | None = None
    merge_system_messages: bool = True
    min_max_tokens: int = Field(default=0, ge=0)
    # Request context admission is separate from cumulative invocation allocation.
    # Omission preserves the identity and behavior of existing operator profiles.
    max_input_tokens_per_request: int | None = Field(
        default=None, gt=0, exclude_if=lambda value: value is None)
    credential_driver: Literal["native"] = "native"
    inspection: tuple[ExtensionBinding, ...] = ()
    provider_retries: Literal[0] = 0

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
    def catalog_is_consistent(self) -> BrokerConfig:
        if set(self.agent_profiles) != set(self.agent_limits):
            raise ValueError("Every catalog agent needs exactly one profile and one limit")
        if not self.profiles or any(not re.fullmatch(LOGICAL_NAME_PATTERN, name) for name in self.profiles):
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

    def require_agents(self, agents: Iterable[str]) -> BrokerConfig:
        """The registered agent list is the only source of truth for catalog completeness."""
        expected = set(agents)
        if set(self.agent_profiles) != expected:
            missing = sorted(expected - set(self.agent_profiles))
            extra = sorted(set(self.agent_profiles) - expected)
            raise ValueError(f"Agent catalog mismatch (missing={missing}, extra={extra})")
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
        backend_name: str,
        model: str,
        model_settings: dict[str, Any],
        *,
        backend: BackendAdaptation,
        atomic_intake: bool = False,
    ) -> ExecutorContract:
        """Resolve a secret-free executor contract from trusted effective settings."""
        if not self.enabled:
            raise ValueError("Brokered model transport is disabled")
        profile_name, profile = self.profile_for_agent(agent)
        profile.require_complete()
        if profile.backend_name != backend_name:
            raise ValueError("Backend is not admitted by the selected access profile")
        if backend.base_url is None or fixed_https_url(backend.base_url) != profile.endpoint:
            raise ValueError("Backend endpoint differs from the operator-approved profile")
        for field, message in (
            ("merge_system_messages", "Message adaptation differs from the approved profile"),
            ("min_max_tokens", "Output-token floor differs from the approved profile"),
            ("enable_thinking", "Thinking control differs from the approved profile"),
            ("thinking_token_budget", "Thinking token budget differs from the approved profile"),
            ("strict_closed_output_tools", "Strict output adaptation differs from the approved profile"),
        ):
            if getattr(backend, field) != getattr(profile, field) or (
                    type(getattr(backend, field)) is not type(getattr(profile, field))):
                raise ValueError(message)
        if atomic_intake != (agent == "intake"):
            raise ValueError("Atomic intake profile is valid only for the intake agent")
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
            backend=backend_name,
            model=model,
            profile=profile_name,
            profile_digest=profile.profile_digest,
            endpoint=profile.endpoint,
            provider_binding=profile.provider_binding,
            executor_image=profile.executor_image,
            supervisor_image=profile.supervisor_image,
            policy_digest=profile.policy_digest,
            model_settings=effective,
            merge_system_messages=profile.merge_system_messages,
            min_max_tokens=profile.min_max_tokens,
            atomic_intake=atomic_intake,
            strict_closed_output_tools=profile.strict_closed_output_tools,
            enable_thinking=profile.enable_thinking,
            thinking_token_budget=profile.thinking_token_budget,
            provider_retries=0,
            credential_driver="native",
            inspection=(),
        )


def load_broker_config(path: Path | None = None, *, agents: Iterable[str]) -> BrokerConfig:
    """Load and validate packaged/operator YAML, including full coverage of ``agents``.

    Callers pass the registered agent names (``agents.registry.BINDINGS``).
    """
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
        config = BrokerConfig.model_validate_json(encoded).require_agents(agents)
    except (TypeError, ValueError) as exc:
        raise ValueError("Broker profile catalog is invalid") from exc
    return config
