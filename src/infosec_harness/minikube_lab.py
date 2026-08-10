"""Controller-side admission checks for the local Minikube synthetic lab."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from .host_observer import HostObserverError, HostObserverEvidence, verify_observer_evidence
from .lab_evidence import EXPERIMENT_EVIDENCE_MAX_AGE, SyntheticExperimentEvidence


class MinikubeLabStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")
    profile: str
    minikube_version: str
    cluster_running: bool
    namespace_ready: bool
    default_deny_enforced: bool
    observer_healthy: bool
    observer_mode: str
    synthetic_oracle_healthy: bool
    collected_at: datetime


class LabAdmissionError(ValueError):
    pass


def load_lab_status(path: Path) -> MinikubeLabStatus:
    return MinikubeLabStatus.model_validate(json.loads(path.read_text(encoding="utf-8")))


def admit_noexec_worker(
    status: MinikubeLabStatus,
    experiment: SyntheticExperimentEvidence | None = None,
    observer: HostObserverEvidence | None = None,
    observer_key: bytes | None = None,
) -> None:
    if status.minikube_version != "v1.38.1":
        raise LabAdmissionError("unapproved minikube version")
    if not status.cluster_running or not status.namespace_ready:
        raise LabAdmissionError("minikube lab is not ready")
    if not status.default_deny_enforced:
        raise LabAdmissionError("default-deny network policy is not verified")
    if not status.observer_healthy or status.observer_mode != "host-side":
        raise LabAdmissionError("independent host-side observer is not healthy")
    if observer is None:
        raise LabAdmissionError("signed host observer evidence is unavailable")
    if not status.synthetic_oracle_healthy:
        raise LabAdmissionError("synthetic oracle is not healthy")
    if experiment is None:
        raise LabAdmissionError("signed synthetic experiment evidence is unavailable")
    if experiment.profile != status.profile or experiment.minikube_version != status.minikube_version:
        raise LabAdmissionError("synthetic experiment evidence is bound to a different lab")
    if experiment.recorded_at < datetime.now(UTC) - EXPERIMENT_EVIDENCE_MAX_AGE:
        raise LabAdmissionError("signed synthetic experiment evidence is stale")
    if observer_key is None:
        raise LabAdmissionError("host observer verification key is unavailable")
    try:
        verify_observer_evidence(
            observer,
            observer_key,
            experiment_id=experiment.experiment_id,
            workload_id="minikube:synthetic-probe",
            destination_ip=experiment.oracle_cluster_ip,
        )
    except HostObserverError as exc:
        raise LabAdmissionError(str(exc)) from exc
    if status.collected_at < datetime.now(UTC).replace(year=datetime.now(UTC).year - 1):
        raise LabAdmissionError("lab status is stale")


def admission_report(
    status: MinikubeLabStatus,
    experiment: SyntheticExperimentEvidence | None = None,
    observer: HostObserverEvidence | None = None,
    observer_key: bytes | None = None,
) -> dict[str, str | bool]:
    try:
        admit_noexec_worker(status, experiment, observer, observer_key)
    except LabAdmissionError as exc:
        return {"admitted": False, "reason": str(exc), "profile": status.profile}
    return {"admitted": True, "reason": "all lab gates verified", "profile": status.profile}
