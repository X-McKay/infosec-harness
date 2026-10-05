"""Configured model names and exact-profile operator connectivity receipts."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Literal, TypedDict

from infosec_harness.agents.registry import AGENT_BINDINGS
from infosec_harness.api.contracts import ModelConnectivity
from infosec_harness.api.evidence_io import (
    STRICT,
    Commit,
    Sha256,
    Timestamp,
    Version1,
    file_sha256,
    read_evidence,
    validated,
)
from infosec_harness.settings import get_settings

RECEIPT_LIFETIME_SECONDS = 3600


class ModelConnectionReceipt(TypedDict):
    """One operator-recorded inference check of an exact model and transport profile."""

    __pydantic_config__ = STRICT  # type: ignore[misc]
    version: Version1
    checked_at: Timestamp
    source_commit: Commit
    model_config_sha256: Sha256
    broker_config_sha256: Sha256 | None
    mode: Literal["live"]
    transport: Literal["direct", "brokered"]
    status: Literal["passed", "failed"]


def model_runtime() -> tuple[list[str], ModelConnectivity]:
    """Configuration plus an optional operator-recorded check, never a live inference probe."""
    from infosec_harness.agents import models
    from infosec_harness.agents.registry import load_spec

    settings = get_settings()
    observation = ModelConnectivity()
    names = []
    try:
        for name in AGENT_BINDINGS:
            label = models.resolved_model_name(name, load_spec(name).model)
            if not re.fullmatch(r"[a-zA-Z0-9._:/-]{1,200}", label):
                raise ValueError("invalid model label")
            names.append(label)
        names = sorted(set(names))
    except Exception:
        return [], observation
    path = settings.model_connection_observation
    if path is None or settings.model_mode != "live":
        return names, observation
    try:
        receipt = validated(ModelConnectionReceipt, read_evidence(path))
        profile = {
            "source_commit": settings.git_commit_sha,
            "mode": settings.model_mode,
            "transport": "brokered" if settings.broker_config else "direct",
            "model_config_sha256": file_sha256(settings.models_config),
            "broker_config_sha256": (file_sha256(settings.broker_config)
                                     if settings.broker_config else None),
        }
        if any(receipt[key] != expected for key, expected in profile.items()):
            raise ValueError("profile evidence mismatch")
        checked = datetime.fromisoformat(receipt["checked_at"])
        now = datetime.now(UTC)
        if checked > now:
            raise ValueError("invalid check time")
        observation.checked_at = checked.isoformat()
        if (now - checked).total_seconds() > RECEIPT_LIFETIME_SECONDS:
            observation.detail = (
                "Recorded inference check has expired; current connectivity is not checked."
            )
        else:
            observation.status = receipt["status"]
            observation.detail = "Operator-recorded inference check for this exact profile; this is not a continuous health probe."
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        observation = ModelConnectivity(
            detail="Recorded inference check is unavailable or does not match the active profile."
        )
    return names, observation
