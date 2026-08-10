"""Fail-closed benchmark admission; evaluation remains outside the triage import path."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class BenchmarkLane(StrEnum):
    REGRESSION = "regression"
    RELEASE = "release"
    DEFENSIVE_RESEARCH = "defensive_research"
    HIGH_RISK_CAPABILITY = "high_risk_capability"


class RightsState(StrEnum):
    APPROVED_INTERNAL_EVAL = "approved_internal_eval"
    APPROVED_WITH_OBLIGATIONS = "approved_with_obligations"
    NEEDS_REVIEW = "needs_review"
    PROHIBITED = "prohibited"
    UNKNOWN = "unknown"


class BenchmarkManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    task_id: str = Field(min_length=1)
    lane: BenchmarkLane
    target_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    task_manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    harness_revision: str = Field(min_length=1)
    rights_state: RightsState
    oracle_self_test: bool
    clean_control: bool
    network_profile: str
    expires_at: datetime
    owner: str = Field(min_length=1)


class BenchmarkAdmissionError(ValueError):
    pass


def load_registry(path: Path) -> list[BenchmarkManifest]:
    return [BenchmarkManifest.model_validate(entry) for entry in json.loads(path.read_text(encoding="utf-8"))["tasks"]]


def admit(manifest: BenchmarkManifest, requested_lane: BenchmarkLane) -> None:
    if manifest.lane != requested_lane:
        raise BenchmarkAdmissionError("requested lane does not match manifest")
    if manifest.expires_at <= datetime.now(UTC):
        raise BenchmarkAdmissionError("benchmark approval expired")
    if manifest.rights_state not in {
        RightsState.APPROVED_INTERNAL_EVAL,
        RightsState.APPROVED_WITH_OBLIGATIONS,
    }:
        raise BenchmarkAdmissionError("benchmark rights are not approved")
    if not manifest.oracle_self_test or not manifest.clean_control:
        raise BenchmarkAdmissionError("benchmark lacks oracle or clean-control evidence")
    if manifest.lane in {BenchmarkLane.REGRESSION, BenchmarkLane.RELEASE} and manifest.network_profile != "deny":
        raise BenchmarkAdmissionError("ordinary evaluation lanes require deny-network profile")
    if manifest.lane == BenchmarkLane.HIGH_RISK_CAPABILITY:
        raise BenchmarkAdmissionError("high-risk capability work requires separately approved range controller")


def dry_run(manifest: BenchmarkManifest, requested_lane: BenchmarkLane) -> dict[str, str | bool]:
    """Validate admission only; this intentionally does not materialize or execute benchmark code."""
    admit(manifest, requested_lane)
    return {
        "task_id": manifest.task_id,
        "lane": manifest.lane.value,
        "admitted": True,
        "execution_started": False,
        "network_profile": manifest.network_profile,
        "target_digest": manifest.target_digest,
        "task_manifest_digest": manifest.task_manifest_digest,
    }
