"""Durable, locally signed evidence for controller-owned Minikube experiments."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import stat
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .policy import digest
from .stores import ArtifactStore

EXPERIMENT_EVIDENCE_MAX_AGE = timedelta(minutes=10)
_KEY_NAME = "minikube-lab-evidence.key"


class LabEvidenceError(ValueError):
    pass


class SyntheticExperimentEvidence(BaseModel):
    """A record of the exact synthetic allow/deny policy experiment."""

    model_config = ConfigDict(extra="forbid")
    schema_version: int = 1
    experiment_id: str = Field(min_length=12)
    profile: str
    namespace: str
    minikube_version: str
    cni_identity: str
    oracle_cluster_ip: str
    approved_job_uid: str
    denied_job_uid: str
    approved_log_artifact: str
    denied_log_artifact: str
    manifest_hashes: dict[str, str]
    recorded_at: datetime
    signature: str = Field(min_length=64)


def _payload(evidence: SyntheticExperimentEvidence) -> bytes:
    return json.dumps(
        evidence.model_dump(mode="json", exclude={"signature"}),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sign_evidence(evidence: SyntheticExperimentEvidence, key: bytes) -> SyntheticExperimentEvidence:
    signature = hmac.new(key, _payload(evidence), hashlib.sha256).hexdigest()
    return evidence.model_copy(update={"signature": signature})


def verify_evidence(evidence: SyntheticExperimentEvidence, key: bytes) -> None:
    expected = hmac.new(key, _payload(evidence), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(evidence.signature, expected):
        raise LabEvidenceError("synthetic experiment evidence signature is invalid")
    if evidence.recorded_at < datetime.now(UTC) - EXPERIMENT_EVIDENCE_MAX_AGE:
        raise LabEvidenceError("synthetic experiment evidence is stale")


def local_evidence_key(data_root: Path, *, create: bool) -> bytes:
    """Load the local lab-integrity key without treating it as an observer key."""

    data_root.mkdir(parents=True, exist_ok=True)
    path = data_root / _KEY_NAME
    if not path.exists():
        if not create:
            raise LabEvidenceError("local synthetic experiment key is unavailable")
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, secrets.token_bytes(32))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise LabEvidenceError("local synthetic experiment key permissions are unsafe")
    return path.read_bytes()


def _kubectl(profile: str, *args: str, text: bool = False) -> str | dict[str, Any]:
    kubeconfig = os.environ.get("KUBECONFIG")
    if not kubeconfig or os.pathsep in kubeconfig or not Path(kubeconfig).is_absolute():
        raise LabEvidenceError(
            "synthetic experiment collection requires one explicit absolute KUBECONFIG; "
            "use the repository Minikube wrapper"
        )
    command = ["kubectl", "--kubeconfig", kubeconfig, "--context", profile, *args]
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        raise LabEvidenceError(f"kubectl evidence collection failed for {' '.join(args[:3])}")
    return completed.stdout if text else json.loads(completed.stdout)


def _complete_job(job: dict[str, Any], label: str) -> str:
    conditions = job.get("status", {}).get("conditions", [])
    if not any(item.get("type") == "Complete" and item.get("status") == "True" for item in conditions):
        raise LabEvidenceError(f"{label} synthetic probe did not complete")
    uid = job.get("metadata", {}).get("uid")
    if not isinstance(uid, str) or not uid:
        raise LabEvidenceError(f"{label} synthetic probe identity is unavailable")
    return uid


def _job_log(profile: str, namespace: str, job_name: str) -> str:
    pods = _kubectl(profile, "-n", namespace, "get", "pods", "-l", f"job-name={job_name}", "-o", "json")
    assert isinstance(pods, dict)
    items = pods.get("items", [])
    if len(items) != 1:
        raise LabEvidenceError(f"{job_name} probe pod identity is ambiguous")
    pod_name = items[0].get("metadata", {}).get("name")
    if not isinstance(pod_name, str):
        raise LabEvidenceError(f"{job_name} probe pod identity is unavailable")
    logs = _kubectl(profile, "-n", namespace, "logs", pod_name, "--tail=32", text=True)
    assert isinstance(logs, str)
    if len(logs.encode("utf-8")) > 4096:
        raise LabEvidenceError(f"{job_name} probe log exceeds evidence limit")
    return logs


def _cni_identity(profile: str) -> str:
    daemonsets = _kubectl(profile, "-n", "kube-system", "get", "daemonset", "-o", "json")
    assert isinstance(daemonsets, dict)
    identities: list[str] = []
    for item in daemonsets.get("items", []):
        name = item.get("metadata", {}).get("name", "")
        if name == "kube-proxy":
            continue
        images = [container.get("image", "") for container in item.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])]
        if images:
            identities.append(f"{name}={'|'.join(images)}")
    if not identities:
        raise LabEvidenceError("CNI identity is unavailable")
    return ";".join(sorted(identities))


def record_live_experiment(data_root: Path, profile: str, namespace: str) -> tuple[SyntheticExperimentEvidence, str]:
    """Collect and sign one completed synthetic experiment without starting workloads."""

    approved = _kubectl(profile, "-n", namespace, "get", "job", "synthetic-approved-probe", "-o", "json")
    denied = _kubectl(profile, "-n", namespace, "get", "job", "synthetic-denied-probe", "-o", "json")
    service = _kubectl(profile, "-n", namespace, "get", "service", "synthetic-oracle", "-o", "json")
    assert isinstance(approved, dict) and isinstance(denied, dict) and isinstance(service, dict)
    approved_uid = _complete_job(approved, "approved")
    denied_uid = _complete_job(denied, "denied")
    cluster_ip = service.get("spec", {}).get("clusterIP")
    if not isinstance(cluster_ip, str) or not cluster_ip:
        raise LabEvidenceError("synthetic oracle ClusterIP is unavailable")
    artifact_store = ArtifactStore(data_root)
    approved_log = artifact_store.put_text(_job_log(profile, namespace, "synthetic-approved-probe"))
    denied_log = artifact_store.put_text(_job_log(profile, namespace, "synthetic-denied-probe"))
    manifest_hashes = {
        path.name: digest(path.read_bytes())
        for path in (
            Path("infra/kubernetes/base/default-deny.yaml"),
            Path("infra/kubernetes/base/oracle.yaml"),
            Path("infra/kubernetes/probes/oracle-probes.yaml"),
        )
    }
    seed = "|".join((profile, namespace, approved_uid, denied_uid, cluster_ip, approved_log, denied_log))
    unsigned = SyntheticExperimentEvidence(
        experiment_id=digest(seed).removeprefix("sha256:")[:24],
        profile=profile,
        namespace=namespace,
        minikube_version=subprocess.run(
            ["minikube", "version", "--short"], check=True, capture_output=True, text=True
        ).stdout.strip(),
        cni_identity=_cni_identity(profile),
        oracle_cluster_ip=cluster_ip,
        approved_job_uid=approved_uid,
        denied_job_uid=denied_uid,
        approved_log_artifact=approved_log,
        denied_log_artifact=denied_log,
        manifest_hashes=manifest_hashes,
        recorded_at=datetime.now(UTC),
        signature="0" * 64,
    )
    evidence = sign_evidence(unsigned, local_evidence_key(data_root, create=True))
    evidence_root = data_root / "minikube-lab"
    evidence_root.mkdir(exist_ok=True)
    rendered = evidence.model_dump_json(indent=2)
    record_path = evidence_root / f"{evidence.experiment_id}.json"
    record_path.write_text(rendered + "\n", encoding="utf-8")
    (evidence_root / "latest.json").write_text(rendered + "\n", encoding="utf-8")
    return evidence, artifact_store.put_json(evidence.model_dump(mode="json"))


def load_and_verify_evidence(data_root: Path, path: Path) -> SyntheticExperimentEvidence:
    evidence = SyntheticExperimentEvidence.model_validate_json(path.read_text(encoding="utf-8"))
    verify_evidence(evidence, local_evidence_key(data_root, create=False))
    return evidence
