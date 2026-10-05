"""Bounded, duplicate-rejecting evidence reads shared by status projections."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, TypedDict

from infosec_harness.domain.canonical import is_sha256, sha256_hex

COMMIT = re.compile(r"^[a-f0-9]{40}$")
MAX_EVIDENCE_BYTES = 32 * 1024 * 1024


class EvidenceUnavailable(ValueError):
    pass


def read_bytes(path: str | Path, *, limit: int = MAX_EVIDENCE_BYTES) -> bytes:
    """Bounded read of an operator-owned regular file; symlinks anywhere on the path refuse."""
    p = Path(path).absolute()
    if any(part.is_symlink() for part in (p, *p.parents)) or not p.is_file():
        raise EvidenceUnavailable("artifact unavailable")
    with p.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise EvidenceUnavailable("artifact oversized")
    return data


class EvidenceReference(TypedDict):
    file: str
    sha256: str


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
        not is_sha256(expected) or sha256_hex(data) != expected
    ):
        raise ValueError("evidence drift")
    return json.loads(data, object_pairs_hook=reject_duplicate_fields)


def read_reference(ref: EvidenceReference) -> Any:
    if not isinstance(ref, dict) or set(ref) != {"file", "sha256"}:
        raise ValueError("invalid reference")
    return read_evidence(Path(ref["file"]), ref["sha256"])

