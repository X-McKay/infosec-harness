"""Public-safe read-only evidence projection. Configuration never grants execution authority."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import ssl
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx
from fastapi import APIRouter
from sqlalchemy import func, select
from sqlalchemy.engine import make_url

from infosec_harness.agents.registry import AGENT_BINDINGS
from infosec_harness.api.contracts import (
    BrokerStatus,
    QualificationStatus,
    QualifiedComponent,
    RuntimeStatus,
)
from infosec_harness.persistence import db
from infosec_harness.qualification.ledger import assess, is_hash, read_bytes
from infosec_harness.resources import source_checkout
from infosec_harness.settings import get_settings

router = APIRouter(prefix="/api")
_HASH = re.compile(r"^[a-f0-9]{64}$")
_COMMIT = re.compile(r"^[a-f0-9]{40}$")
_LABEL = re.compile(r"^[a-zA-Z0-9._-]{1,64}$")
_LIMITATIONS = [
    "Fresh full-suite qualification is not established by this component view.",
    "Hosted and Kubernetes qualification require their own measured evidence.",
    "Missing historical replay coverage remains not checked.",
]


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _read(path: Path, expected: str | None = None):
    data = read_bytes(path)
    if expected is not None and (
        not _HASH.fullmatch(expected) or hashlib.sha256(data).hexdigest() != expected
    ):
        raise ValueError("evidence drift")
    return json.loads(data, object_pairs_hook=_pairs)


def _ref(ref):
    if not isinstance(ref, dict) or set(ref) != {"file", "sha256"}:
        raise ValueError("invalid reference")
    return _read(Path(ref["file"]), ref["sha256"])


def _bundle():
    settings = get_settings()
    if settings.qualification_bundle is None:
        raise ValueError("evidence unavailable")
    value = _read(settings.qualification_bundle)
    if (
        set(value) != {"version", "ledger", "current", "reviews", "selection", "broker_observation"}
        or type(value["version"]) is not int
        or value["version"] != 1
    ):
        raise ValueError("invalid bundle")
    return value


def _unknown_components():
    return [
        QualifiedComponent(
            agent=agent,
            scope="agent_semantics",
            status="not_checked",
            freshness="unavailable",
            reason="Verified evidence is unavailable.",
        )
        for agent in AGENT_BINDINGS
    ]


def qualification_status() -> QualificationStatus:
    now = datetime.now(UTC).isoformat()
    try:
        bundle = _bundle()
        ledger, current, reviews = (_ref(bundle[k]) for k in ("ledger", "current", "reviews"))
        if set(bundle["selection"]) != set(AGENT_BINDINGS):
            raise ValueError("incomplete selection")
        # A deployed build label does not replace actual dependency hashing.
        if _COMMIT.fullmatch(get_settings().git_commit_sha):
            current["qualification_candidate_commit"] = get_settings().git_commit_sha
        assessment = assess(ledger, current, reviews, root=source_checkout())
        records = {r["id"]: r for r in ledger["records"]}
        results = {r["record_id"]: r for r in assessment["results"]}
        projected = []
        for agent, identity in bundle["selection"].items():
            record, result = records[identity], results[identity]
            if record["component"] != agent or record["scope"] != "agent_semantics":
                raise ValueError("selection identity mismatch")
            status = result["status"]
            if status not in {"passed", "failed", "not_checked"}:
                status = "not_checked"
            witness_ref = record["evidence"].get("completion_witness") or record["evidence"].get(
                "cardinality"
            )
            witness = _ref(witness_ref) if witness_ref else {}
            n, passed = witness.get("n"), witness.get("passed")
            n = n if type(n) is int and n >= 0 else None
            passed = (
                passed
                if type(passed) is int and passed >= 0 and n is not None and passed <= n
                else None
            )
            changed = bool(result["changed_dependencies"])
            verified = status == "passed"
            fresh = (
                verified
                and record["measured_source_commit"] == current["qualification_candidate_commit"]
            )
            projected.append(
                QualifiedComponent(
                    agent=agent,
                    scope="agent_semantics",
                    status=status,
                    measured_commit=record["measured_source_commit"]
                    if _COMMIT.fullmatch(record["measured_source_commit"])
                    else None,
                    freshness="fresh"
                    if fresh
                    else "reused"
                    if verified
                    else "stale"
                    if changed
                    else "unavailable",
                    reason="Complete measured cohort; dependencies verified."
                    if verified
                    else "Dependencies changed; retest or review is required."
                    if changed
                    else "Verified evidence is unavailable or the measured gate did not pass.",
                    cases=n,
                    passed_cases=passed,
                )
            )
        overall = (
            "passed"
            if all(p.status == "passed" for p in projected)
            else "failed"
            if any(p.status == "failed" for p in projected)
            else "not_checked"
        )
        return QualificationStatus(
            as_of=now,
            candidate_commit=current["qualification_candidate_commit"],
            status=overall,
            detail="Selected complete component cohorts assessed against actual dependencies.",
            components=projected,
            limitations=_LIMITATIONS,
        )
    except (OSError, ValueError, TypeError, KeyError):
        return QualificationStatus(
            as_of=now,
            status="not_checked",
            detail="Qualification evidence is unavailable, invalid, or incomplete.",
            components=_unknown_components(),
            limitations=_LIMITATIONS,
        )


def _measurement():
    value = _ref(_bundle()["broker_observation"])
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
        or not is_hash(value["catalog_sha256"])
        or hashlib.sha256(read_bytes(catalog)).hexdigest() != value["catalog_sha256"]
    ):
        raise ValueError("configuration drift")
    if not isinstance(value["evidence"], dict) or set(value["evidence"]) != {
        "owner",
        "health",
        "readiness",
    }:
        raise ValueError("missing scoped measurement provenance")
    owner, health, ready = (_ref(value["evidence"][k]) for k in ("owner", "health", "readiness"))
    if any(proof.get("status") != "passed" for proof in (owner, health, ready)):
        raise ValueError("measurement did not pass")
    owner_digest = value["evidence"]["owner"]["sha256"]
    source = owner.get("source_end_commit")
    if (
        not isinstance(source, str)
        or not _COMMIT.fullmatch(source)
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
    }
    if set(modules) != required_modules:
        raise ValueError("incomplete source inventory")
    if (
        health.get("new_controller_id")
        != owner.get("owned_container_ids", {}).get("ih-live-controller")
        or not isinstance(health.get("new_controller_id"), str)
        or not is_hash(health.get("new_controller_id"))
        or not is_hash(health.get("controller_configuration_sha256"))
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
            or not is_hash(observation.get("contract_digest"))
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
            or not name.startswith("src/infosec_harness/inference/")
            or ".." in Path(name).parts
            or not is_hash(digest)
        ):
            raise ValueError("invalid module identity")
        expected_dependencies[str(Path(root) / name)] = digest
    if value["dependencies"] != expected_dependencies:
        raise ValueError("dependency inventory mismatch")
    adapters = owner.get("loaded_controller_adapter_source_sha256", {})
    for name in ("controller.py", "openshell.py", "transport.py"):
        if adapters.get(name) != modules.get(
            "src/infosec_harness/inference/" + name
        ) or not is_hash(adapters.get(name)):
            raise ValueError("adapter identity mismatch")
    config_files = owner.get("candidate_config_files_sha256", {})
    if (
        not isinstance(config_files, dict)
        or config_files.get(str(catalog)) != value["catalog_sha256"]
    ):
        raise ValueError("catalog measurement mismatch")
    for path, digest in {**expected_dependencies, **config_files}.items():
        if not is_hash(digest) or hashlib.sha256(read_bytes(path)).hexdigest() != digest:
            raise ValueError("runtime dependency drift")
    return value, stale


_probe_lock = asyncio.Lock()
_probe_cache: tuple[str, float, bool] | None = None


async def _admission_reachable() -> bool:
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
                    body, object_pairs_hook=_pairs
                ) == {"error": "auth"}
        except (httpx.HTTPError, ValueError, TimeoutError):
            okay = False
        _probe_cache = (identity, time.monotonic(), okay)
        return okay


@router.get("/qualification", response_model=QualificationStatus)
async def qualification() -> QualificationStatus:
    return await asyncio.to_thread(qualification_status)


@router.get("/runtime-status", response_model=RuntimeStatus)
async def runtime_status() -> RuntimeStatus:
    settings = get_settings()
    broker = BrokerStatus(
        configured=settings.broker_config is not None,
        status="not_checked",
        detail="No verified current broker measurement is available.",
    )
    if broker.configured:
        try:
            async with asyncio.timeout(3), db.session() as session:
                broker.unresolved_requests = await session.scalar(
                    select(func.count())
                    .select_from(db.InferenceRequestRecord)
                    .where(db.InferenceRequestRecord.state == "completion_unknown")
                )
            measurement, stale = await asyncio.to_thread(_measurement)
            broker.checked_at = measurement["checked_at"]
            broker.stale = stale
            reachable = await _admission_reachable()
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
    return RuntimeStatus(
        environment=settings.environment if _LABEL.fullmatch(settings.environment) else "unknown",
        model_mode=settings.model_mode,
        assessment_transport="brokered" if settings.broker_config else "direct",
        api_source_commit=settings.git_commit_sha
        if _COMMIT.fullmatch(settings.git_commit_sha)
        else None,
        as_of=datetime.now(UTC).isoformat(),
        database_backend=make_url(settings.database_url).get_backend_name(),
        temporal_mode="tls" if settings.temporal_tls else "plaintext",
        broker=broker,
    )
