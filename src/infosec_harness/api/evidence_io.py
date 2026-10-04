"""Bounded, duplicate-rejecting evidence reads shared by status projections."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, TypedDict, cast

from infosec_harness.qualification.ledger import read_bytes
from infosec_harness.settings import get_settings

COMMIT = re.compile(r"^[a-f0-9]{40}$")
_HASH = re.compile(r"^[a-f0-9]{64}$")


class EvidenceReference(TypedDict):
    file: str
    sha256: str


class QualificationBundle(TypedDict):
    version: int
    ledger: EvidenceReference
    current: EvidenceReference
    reviews: EvidenceReference
    selection: dict[str, str]
    broker_observation: EvidenceReference


def reject_duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def read_evidence(path: Path, expected: str | None = None) -> Any:
    data = read_bytes(path)
    if expected is not None and (
        not _HASH.fullmatch(expected) or hashlib.sha256(data).hexdigest() != expected
    ):
        raise ValueError("evidence drift")
    return json.loads(data, object_pairs_hook=reject_duplicate_fields)


def read_reference(ref: EvidenceReference) -> Any:
    if not isinstance(ref, dict) or set(ref) != {"file", "sha256"}:
        raise ValueError("invalid reference")
    return read_evidence(Path(ref["file"]), ref["sha256"])


def load_bundle() -> QualificationBundle:
    settings = get_settings()
    if settings.qualification_bundle is None:
        raise ValueError("evidence unavailable")
    value = read_evidence(settings.qualification_bundle)
    if (
        set(value) != {"version", "ledger", "current", "reviews", "selection", "broker_observation"}
        or type(value["version"]) is not int
        or value["version"] != 1
    ):
        raise ValueError("invalid bundle")
    return cast(QualificationBundle, value)
