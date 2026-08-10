"""Signed contract for an independently deployed host-side flow observer.

The harness does not collect host flows itself.  A separately operated collector
(for example, a privileged eBPF service) must emit this envelope and own its
signing key.  This keeps a compromised worker and the controller from claiming
their own network observations.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import shutil
import stat
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

OBSERVER_EVIDENCE_MAX_AGE = timedelta(minutes=2)


class HostObserverError(ValueError):
    pass


class ObserverCapabilityReport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    admitted: bool
    bpftool_available: bool
    host_bpf_access: bool
    reason: str


class ObservedFlow(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workload_id: str = Field(min_length=1, max_length=128)
    experiment_id: str = Field(min_length=12)
    verdict: Literal["allowed", "denied"]
    protocol: Literal["tcp", "udp"]
    destination_ip: str
    destination_port: int = Field(ge=1, le=65535)
    policy_decision_id: str = Field(min_length=12)
    observed_at: datetime


class HostObserverEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: int = 1
    observer_id: str = Field(min_length=1, max_length=128)
    observer_mode: Literal["host-side"]
    collector_version: str = Field(min_length=1, max_length=128)
    healthy: bool
    collected_at: datetime
    flows: list[ObservedFlow] = Field(min_length=2, max_length=128)
    signature: str = Field(min_length=64)


def _payload(evidence: HostObserverEvidence) -> bytes:
    return json.dumps(
        evidence.model_dump(mode="json", exclude={"signature"}),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sign_observer_evidence(evidence: HostObserverEvidence, key: bytes) -> HostObserverEvidence:
    return evidence.model_copy(update={"signature": hmac.new(key, _payload(evidence), hashlib.sha256).hexdigest()})


def verify_observer_evidence(
    evidence: HostObserverEvidence,
    key: bytes,
    *,
    experiment_id: str,
    workload_id: str,
    destination_ip: str,
) -> None:
    expected = hmac.new(key, _payload(evidence), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(evidence.signature, expected):
        raise HostObserverError("host observer evidence signature is invalid")
    if not evidence.healthy:
        raise HostObserverError("host observer reports unhealthy")
    if evidence.collected_at < datetime.now(UTC) - OBSERVER_EVIDENCE_MAX_AGE:
        raise HostObserverError("host observer evidence is stale")
    matching = [
        flow
        for flow in evidence.flows
        if flow.experiment_id == experiment_id
        and flow.workload_id == workload_id
        and flow.protocol == "tcp"
        and flow.destination_ip == destination_ip
        and flow.destination_port == 8080
    ]
    if {flow.verdict for flow in matching} != {"allowed", "denied"}:
        raise HostObserverError("host observer lacks bound allowed and denied flow evidence")
    if any(flow.observed_at < datetime.now(UTC) - OBSERVER_EVIDENCE_MAX_AGE for flow in matching):
        raise HostObserverError("host observer flow evidence is stale")


def load_observer_key(path: Path) -> bytes:
    """Load an externally provisioned observer key with strict local permissions."""

    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise HostObserverError("host observer key permissions are unsafe")
    key = path.read_bytes()
    if len(key) < 32:
        raise HostObserverError("host observer key is too short")
    return key


def observer_self_test() -> ObserverCapabilityReport:
    """Report whether this account could even inspect host BPF state.

    Access alone is deliberately insufficient for admission: a separately
    operated collector and signed flow evidence are still required.
    """

    if shutil.which("bpftool") is None:
        return ObserverCapabilityReport(
            admitted=False,
            bpftool_available=False,
            host_bpf_access=False,
            reason="bpftool is unavailable; no host-side observer collector can be verified",
        )
    completed = subprocess.run(["bpftool", "prog", "show"], check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        return ObserverCapabilityReport(
            admitted=False,
            bpftool_available=True,
            host_bpf_access=False,
            reason="host BPF inspection is unavailable to this account",
        )
    return ObserverCapabilityReport(
        admitted=False,
        bpftool_available=True,
        host_bpf_access=True,
        reason="no independently operated host-side collector has supplied signed flow evidence",
    )
