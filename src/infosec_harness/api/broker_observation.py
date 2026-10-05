"""Read-only broker evidence and bounded unsigned controller-channel observation."""

from __future__ import annotations

import asyncio
import hashlib
import json
import ssl
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, TypedDict

import httpx
from sqlalchemy import select

from infosec_harness.agents.registry import AGENT_BINDINGS
from infosec_harness.api.contracts import BrokerStatus
from infosec_harness.api.evidence_io import (
    COMMIT,
    EvidenceReference,
    read_bytes,
    read_evidence,
    read_reference,
    reject_duplicate_fields,
)
from infosec_harness.domain.canonical import is_sha256
from infosec_harness.persistence import db
from infosec_harness.persistence.reconciliation import is_conservatively_closed
from infosec_harness.resources import source_checkout
from infosec_harness.settings import get_settings

# Modules outside `inference/` that the controller loads: the canonical digest encoding and the
# bounded subprocess runner. A loaded-module attestation that omits them is incomplete.
CONTROLLER_SHARED_MODULES = (
    "src/infosec_harness/domain/canonical.py",
    "src/infosec_harness/sandbox/process.py",
)


class BrokerMeasurement(TypedDict):
    version: int
    checked_at: str
    valid_until: str
    status: Literal["passed", "failed", "not_checked"]
    catalog_sha256: str
    dependencies: dict[str, str]
    evidence: dict[str, EvidenceReference]


def _observation() -> object:
    """The operator-recorded measurement named by HARNESS_BROKER_OBSERVATION."""
    path = get_settings().broker_observation
    if path is None:
        raise ValueError("evidence unavailable")
    return read_evidence(path)


def broker_measurement() -> tuple[BrokerMeasurement, bool]:
    value = _observation()
    fields = {
        "version",
        "checked_at",
        "valid_until",
        "status",
        "catalog_sha256",
        "dependencies",
        "evidence",
    }
    if (
        set(value) != fields
        or type(value["version"]) is not int
        or value["version"] != 1
        or value["status"] not in {"passed", "failed", "not_checked"}
    ):
        raise ValueError("invalid observation")
    checked, until = (datetime.fromisoformat(value[k]) for k in ("checked_at", "valid_until"))
    now = datetime.now(UTC)
    if checked.tzinfo is None or until.tzinfo is None or checked > now or until <= checked:
        raise ValueError("invalid measurement time")
    cap = get_settings().qualification_observation_max_age_seconds
    if (until - checked).total_seconds() > cap:
        raise ValueError("measurement lifetime too long")
    stale = now >= until or (now - checked).total_seconds() > cap
    catalog = get_settings().broker_config
    if (
        catalog is None
        or not is_sha256(value["catalog_sha256"])
        or hashlib.sha256(read_bytes(catalog)).hexdigest() != value["catalog_sha256"]
    ):
        raise ValueError("configuration drift")
    if not isinstance(value["evidence"], dict) or set(value["evidence"]) != {
        "owner",
        "health",
        "readiness",
    }:
        raise ValueError("missing scoped measurement provenance")
    owner, health, ready = (
        read_reference(value["evidence"][k]) for k in ("owner", "health", "readiness")
    )
    if any(proof.get("status") != "passed" for proof in (owner, health, ready)):
        raise ValueError("measurement did not pass")
    owner_digest = value["evidence"]["owner"]["sha256"]
    source = owner.get("source_end_commit")
    if (
        not isinstance(source, str)
        or not COMMIT.fullmatch(source)
        or health.get("source_commit") != source
        or ready.get("source_commit") != source
    ):
        raise ValueError("source identity mismatch")
    if health.get("new_owner_sha256") != owner_digest or ready.get("owner_sha256") != owner_digest:
        raise ValueError("owner identity mismatch")
    admission = health.get("actual_tls_unsigned_401", {})
    if (
        admission.get("status") != 401
        or admission.get("tls_verified") is not True
        or admission.get("no_admission") is not True
    ):
        raise ValueError("channel measurement missing")
    if (
        type(ready.get("registered_contracts")) is not int
        or ready["registered_contracts"] != len(AGENT_BINDINGS)
        or ready.get("owned_test_leases_deleted") is not True
        or type(ready.get("native_inventory")) is not int
        or ready["native_inventory"] != 0
        or ready.get("loaded_module_sha256_start_end_equal")
        != owner.get("loaded_controller_adapter_source_sha256")
    ):
        raise ValueError("incomplete native readiness measurement")
    modules = health.get("loaded_module_attestation", {})
    root = source_checkout()
    if root is None or not isinstance(modules, dict) or not modules:
        raise ValueError("source inventory unavailable")
    required_modules = {
        str(p.relative_to(root))
        for p in (Path(root) / "src/infosec_harness/inference").glob("*.py")
        if p.name != "__init__.py"
    } | set(CONTROLLER_SHARED_MODULES)
    if set(modules) != required_modules:
        raise ValueError("incomplete source inventory")
    if (
        health.get("new_controller_id")
        != owner.get("owned_container_ids", {}).get("ih-live-controller")
        or not isinstance(health.get("new_controller_id"), str)
        or not is_sha256(health.get("new_controller_id"))
        or not is_sha256(health.get("controller_configuration_sha256"))
    ):
        raise ValueError("controller identity mismatch")
    from infosec_harness.inference.profiles import load_broker_config

    config = load_broker_config(catalog)
    observations = ready.get("native_observations", {})
    leases = ready.get("issued_owned_readiness_leases", {})
    if (
        not isinstance(observations, dict)
        or set(observations) != set(AGENT_BINDINGS)
        or not isinstance(leases, dict)
        or len(leases) != len(AGENT_BINDINGS)
    ):
        raise ValueError("incomplete contract readiness")
    by_agent = {row["agent"]: row for row in leases.values()}
    if set(by_agent) != set(AGENT_BINDINGS):
        raise ValueError("incomplete lease readiness")
    for agent, observation in observations.items():
        name, profile = config.profile_for_agent(agent)
        if (
            observation.get("state") != "ready"
            or not is_sha256(observation.get("contract_digest"))
            or observation.get("contract_digest") != by_agent[agent].get("contract_digest")
            or any(
                observation.get(k) != expected
                for k, expected in {
                    "profile": name,
                    "executor_image": profile.executor_image,
                    "supervisor_image": profile.supervisor_image,
                    "policy_digest": profile.policy_digest,
                }.items()
            )
        ):
            raise ValueError("contract readiness mismatch")
    expected_dependencies = {}
    for name, digest in modules.items():
        if (
            not isinstance(name, str)
            or name not in required_modules
            or ".." in Path(name).parts
            or not is_sha256(digest)
        ):
            raise ValueError("invalid module identity")
        expected_dependencies[str(Path(root) / name)] = digest
    if value["dependencies"] != expected_dependencies:
        raise ValueError("dependency inventory mismatch")
    adapters = owner.get("loaded_controller_adapter_source_sha256", {})
    for name in ("controller.py", "openshell.py", "transport.py"):
        if adapters.get(name) != modules.get(
            "src/infosec_harness/inference/" + name
        ) or not is_sha256(adapters.get(name)):
            raise ValueError("adapter identity mismatch")
    config_files = owner.get("candidate_config_files_sha256", {})
    if (
        not isinstance(config_files, dict)
        or config_files.get(str(catalog)) != value["catalog_sha256"]
    ):
        raise ValueError("catalog measurement mismatch")
    for path, digest in {**expected_dependencies, **config_files}.items():
        if not is_sha256(digest) or hashlib.sha256(read_bytes(path)).hexdigest() != digest:
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
    from infosec_harness.inference.profiles import load_broker_config

    catalog = load_broker_config(settings.broker_config)
    channel = catalog.controller
    if channel.url is None:
        return False
    identity = hashlib.sha256(
        read_bytes(settings.broker_config)
        + (read_bytes(channel.ca_file) if channel.ca_file else b"")
    ).hexdigest()
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
            async with asyncio.timeout(3), db.session() as session:
                rows = (await session.execute(
                    select(db.InferenceRequestRecord, db.BudgetLedger)
                    .outerjoin(db.BudgetLedger, db.InferenceRequestRecord.root_id == db.BudgetLedger.root_id)
                    .where(db.InferenceRequestRecord.state == "completion_unknown")
                )).all()
                closed = sum(is_conservatively_closed(root, request) for request, root in rows)
                broker.conservatively_closed_requests = closed
                broker.unresolved_requests = len(rows) - closed
            measurement, stale = await asyncio.to_thread(broker_measurement)
            broker.checked_at = measurement["checked_at"]
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
