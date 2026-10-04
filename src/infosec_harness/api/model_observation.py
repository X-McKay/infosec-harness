"""Configured model names and exact-profile operator connectivity receipts."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Literal, TypedDict

from infosec_harness.agents.registry import AGENT_BINDINGS
from infosec_harness.api.contracts import ModelConnectivity
from infosec_harness.api.evidence_io import COMMIT, read_evidence
from infosec_harness.qualification.ledger import read_bytes
from infosec_harness.settings import get_settings


class ModelConnectionReceipt(TypedDict):
    version: int
    checked_at: str
    source_commit: str
    model_config_sha256: str
    broker_config_sha256: str | None
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
    path = getattr(settings, "model_connection_observation", None)
    if path is None or settings.model_mode != "live":
        return names, observation
    try:
        value: ModelConnectionReceipt = read_evidence(path)
        required = {
            "version",
            "checked_at",
            "source_commit",
            "model_config_sha256",
            "broker_config_sha256",
            "mode",
            "transport",
            "status",
        }
        if (
            not isinstance(value, dict)
            or set(value) != required
            or type(value["version"]) is not int
            or value["version"] != 1
            or value["status"] not in {"passed", "failed"}
            or value["source_commit"] != settings.git_commit_sha
            or not COMMIT.fullmatch(value["source_commit"])
            or value["mode"] != settings.model_mode
            or value["transport"] != ("brokered" if settings.broker_config else "direct")
            or value["model_config_sha256"]
            != hashlib.sha256(read_bytes(settings.models_config)).hexdigest()
            or value["broker_config_sha256"]
            != (
                hashlib.sha256(read_bytes(settings.broker_config)).hexdigest()
                if settings.broker_config
                else None
            )
        ):
            raise ValueError("profile evidence mismatch")
        checked = datetime.fromisoformat(value["checked_at"])
        now = datetime.now(UTC)
        if checked.tzinfo is None or checked > now:
            raise ValueError("invalid check time")
        observation.checked_at = checked.isoformat()
        if (now - checked).total_seconds() > 3600:
            observation.detail = (
                "Recorded inference check has expired; current connectivity is not checked."
            )
        else:
            observation.status = value["status"]
            observation.detail = "Operator-recorded inference check for this exact profile; this is not a continuous health probe."
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        observation = ModelConnectivity(
            detail="Recorded inference check is unavailable or does not match the active profile."
        )
    return names, observation
