"""Read-only broker evidence and bounded unsigned controller-channel observation."""

from __future__ import annotations

import asyncio
import json
import ssl
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, TypedDict

import httpx
from pydantic import ConfigDict

from infosec_harness.api.contracts import BrokerStatus
from infosec_harness.api.evidence_io import (
    STRICT,
    Commit,
    EvidenceReference,
    Sha256,
    Timestamp,
    Version1,
    exact,
    file_sha256,
    read_bytes,
    read_evidence,
    read_reference,
    reject_duplicate_fields,
    validated,
)
from infosec_harness.domain.canonical import sha256_hex
from infosec_harness.persistence import store
from infosec_harness.resources import source_checkout
from infosec_harness.runtime.registry import BINDINGS
from infosec_harness.settings import get_settings

# Modules outside `inference/` that the controller loads: the canonical digest encoding and the
# bounded subprocess runner. A loaded-module attestation that omits them is incomplete.
CONTROLLER_SHARED_MODULES = (
    "src/infosec_harness/domain/canonical.py",
    "src/infosec_harness/sandbox/process.py",
)
# The controller-loaded adapters whose source the owner proof pins, relative to `inference/`.
_ADAPTERS = ("controller/service.py", "native/openshell.py", "worker/transport.py")

# The three proofs are hash-pinned operator artifacts. Strict about every field the service
# relies on; fields it never reads are ignored rather than refused, since they cannot promote
# a status and the artifact cannot change without its pinned hash changing too.
_PROOF = ConfigDict(extra="ignore", strict=True)


class BrokerEvidence(TypedDict):
    __pydantic_config__ = STRICT  # type: ignore[misc]
    owner: EvidenceReference
    health: EvidenceReference
    readiness: EvidenceReference


class BrokerMeasurement(TypedDict):
    __pydantic_config__ = STRICT  # type: ignore[misc]
    version: Version1
    checked_at: Timestamp
    valid_until: Timestamp
    status: Literal["passed", "failed", "not_checked"]
    catalog_sha256: Sha256
    dependencies: dict[str, Sha256]
    evidence: BrokerEvidence


class OwnerProof(TypedDict):
    __pydantic_config__ = _PROOF  # type: ignore[misc]
    status: Literal["passed"]
    source_end_commit: Commit
    owned_container_ids: dict[str, str]
    loaded_controller_adapter_source_sha256: dict[str, Sha256]
    candidate_config_files_sha256: dict[str, Sha256]


class UnsignedAdmission(TypedDict):
    __pydantic_config__ = _PROOF  # type: ignore[misc]
    status: Annotated[Literal[401], exact(int)]
    tls_verified: Annotated[Literal[True], exact(bool)]
    no_admission: Annotated[Literal[True], exact(bool)]


class HealthProof(TypedDict):
    __pydantic_config__ = _PROOF  # type: ignore[misc]
    status: Literal["passed"]
    source_commit: Commit
    new_owner_sha256: Sha256
    new_controller_id: Sha256
    controller_configuration_sha256: Sha256
    actual_tls_unsigned_401: UnsignedAdmission
    loaded_module_attestation: dict[str, Sha256]


class NativeObservation(TypedDict):
    __pydantic_config__ = _PROOF  # type: ignore[misc]
    state: Literal["ready"]
    contract_digest: Sha256
    profile: str
    executor_image: str
    supervisor_image: str
    policy_digest: str


class ReadinessLease(TypedDict):
    __pydantic_config__ = _PROOF  # type: ignore[misc]
    agent: str
    contract_digest: Sha256


class ReadinessProof(TypedDict):
    __pydantic_config__ = _PROOF  # type: ignore[misc]
    status: Literal["passed"]
    source_commit: Commit
    owner_sha256: Sha256
    registered_contracts: int
    native_inventory: Annotated[Literal[0], exact(int)]
    owned_test_leases_deleted: Annotated[Literal[True], exact(bool)]
    loaded_module_sha256_start_end_equal: dict[str, Sha256]
    native_observations: dict[str, NativeObservation]
    issued_owned_readiness_leases: dict[str, ReadinessLease]


def _observation() -> object:
    """The operator-recorded measurement named by HARNESS_BROKER_OBSERVATION."""
    path = get_settings().broker_observation
    if path is None:
        raise ValueError("evidence unavailable")
    return read_evidence(path)


def broker_measurement() -> tuple[BrokerMeasurement, bool]:
    """The verified measurement and whether it is stale; raises ``ValueError`` otherwise."""
    value = validated(BrokerMeasurement, _observation())
    checked, until = (datetime.fromisoformat(value[k]) for k in ("checked_at", "valid_until"))
    now = datetime.now(UTC)
    if checked > now or until <= checked:
        raise ValueError("invalid measurement time")
    cap = get_settings().qualification_observation_max_age_seconds
    if (until - checked).total_seconds() > cap:
        raise ValueError("measurement lifetime too long")
    stale = now >= until or (now - checked).total_seconds() > cap
    catalog = get_settings().broker_config
    if catalog is None or file_sha256(catalog) != value["catalog_sha256"]:
        raise ValueError("configuration drift")
    references = value["evidence"]
    owner = validated(OwnerProof, read_reference(references["owner"]))
    health = validated(HealthProof, read_reference(references["health"]))
    ready = validated(ReadinessProof, read_reference(references["readiness"]))
    owner_digest = references["owner"]["sha256"]
    source = owner["source_end_commit"]
    if health["source_commit"] != source or ready["source_commit"] != source:
        raise ValueError("source identity mismatch")
    if health["new_owner_sha256"] != owner_digest or ready["owner_sha256"] != owner_digest:
        raise ValueError("owner identity mismatch")
    if (ready["registered_contracts"] != len(BINDINGS)
            or ready["loaded_module_sha256_start_end_equal"]
            != owner["loaded_controller_adapter_source_sha256"]):
        raise ValueError("incomplete native readiness measurement")
    modules = health["loaded_module_attestation"]
    root = source_checkout()
    if root is None or not modules:
        raise ValueError("source inventory unavailable")
    required_modules = {
        str(p.relative_to(root))
        for p in (Path(root) / "src/infosec_harness/inference").rglob("*.py")
        if p.name != "__init__.py"
    } | set(CONTROLLER_SHARED_MODULES)
    if set(modules) != required_modules:
        raise ValueError("incomplete source inventory")
    if health["new_controller_id"] != owner["owned_container_ids"].get("ih-live-controller"):
        raise ValueError("controller identity mismatch")
    from infosec_harness.inference.catalog.profiles import load_broker_config

    config = load_broker_config(catalog, agents=tuple(BINDINGS))
    observations = ready["native_observations"]
    leases = ready["issued_owned_readiness_leases"]
    if set(observations) != set(BINDINGS) or len(leases) != len(BINDINGS):
        raise ValueError("incomplete contract readiness")
    by_agent = {row["agent"]: row for row in leases.values()}
    if set(by_agent) != set(BINDINGS):
        raise ValueError("incomplete lease readiness")
    for agent, observation in observations.items():
        name, profile = config.profile_for_agent(agent)
        if (
            observation["contract_digest"] != by_agent[agent]["contract_digest"]
            or any(
                observation[k] != expected
                for k, expected in {
                    "profile": name,
                    "executor_image": profile.executor_image,
                    "supervisor_image": profile.supervisor_image,
                    "policy_digest": profile.policy_digest,
                }.items()
            )
        ):
            raise ValueError("contract readiness mismatch")
    if any(".." in Path(name).parts for name in modules):
        raise ValueError("invalid module identity")
    expected_dependencies = {str(Path(root) / name): digest for name, digest in modules.items()}
    if value["dependencies"] != expected_dependencies:
        raise ValueError("dependency inventory mismatch")
    adapters = owner["loaded_controller_adapter_source_sha256"]
    if any(adapters.get(name) != modules.get("src/infosec_harness/inference/" + name)
           for name in _ADAPTERS):
        raise ValueError("adapter identity mismatch")
    config_files = owner["candidate_config_files_sha256"]
    if config_files.get(str(catalog)) != value["catalog_sha256"]:
        raise ValueError("catalog measurement mismatch")
    for path, digest in {**expected_dependencies, **config_files}.items():
        if file_sha256(path) != digest:
            raise ValueError("runtime dependency drift")
    return value, stale


_probe_lock = asyncio.Lock()
_probe_cache: tuple[str, float, bool] | None = None


async def admission_reachable() -> bool:
    """Unsigned rejection proves only the controller channel, never native readiness."""
    global _probe_cache
    settings = get_settings()
    if settings.broker_config is None:
        return False
    from infosec_harness.inference.catalog.profiles import load_broker_config

    catalog = load_broker_config(settings.broker_config, agents=tuple(BINDINGS))
    channel = catalog.controller
    if channel.url is None:
        return False
    identity = sha256_hex(
        read_bytes(settings.broker_config)
        + (read_bytes(channel.ca_file) if channel.ca_file else b"")
    )
    async with _probe_lock:
        if (
            _probe_cache is not None
            and _probe_cache[0] == identity
            and time.monotonic() - _probe_cache[1] < 30
        ):
            return _probe_cache[2]
        context = ssl.create_default_context(cafile=channel.ca_file)
        try:
            async with (
                asyncio.timeout(3),
                httpx.AsyncClient(
                    verify=context, trust_env=False, follow_redirects=False, timeout=3
                ) as client,
                client.stream(
                    "POST",
                    channel.url + "/v1/infer",
                    content=b"{}",
                    headers={"Content-Type": "application/json"},
                ) as response,
            ):
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > 1024:
                        raise ValueError("oversized rejection")
                okay = response.status_code == 401 and json.loads(
                    body, object_pairs_hook=reject_duplicate_fields
                ) == {"error": "auth"}
        except (httpx.HTTPError, ValueError, TimeoutError):
            okay = False
        _probe_cache = (identity, time.monotonic(), okay)
        return okay


async def broker_status() -> BrokerStatus:
    settings = get_settings()
    broker = BrokerStatus(
        configured=settings.broker_config is not None,
        status="not_checked",
        detail="No verified current broker measurement is available.",
    )
    if broker.configured:
        try:
            async with asyncio.timeout(3):
                unresolved, closed = await store.completion_unknown_requests()
            broker.conservatively_closed_requests = closed
            broker.unresolved_requests = unresolved
            measurement, stale = await asyncio.to_thread(broker_measurement)
            broker.checked_at = datetime.fromisoformat(measurement["checked_at"]).isoformat()
            broker.stale = stale
            reachable = await admission_reachable()
            broker.status = (
                "not_checked" if stale else measurement["status"] if reachable else "failed"
            )
            broker.detail = (
                "Retained readiness measurement verified; live TLS admission rejects unsigned requests. No model call was made."
                if not stale and reachable
                else "Readiness measurement is stale or the controller channel could not be verified."
            )
        except Exception:
            # Database/provider exceptions may contain credentials: never echo them.
            broker.status = "not_checked"
            broker.detail = "Broker observation is unavailable or invalid; configuration alone is not execution evidence."
    return broker
