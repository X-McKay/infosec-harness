"""Bounded, duplicate-rejecting evidence reads and the strict schema vocabulary they validate.

Evidence documents are typed dictionaries validated in pydantic strict mode: unknown fields are
refused, booleans are never integers, versions are exact literals and hashes are lowercase
SHA-256. A projection that fails any check reports ``not_checked``; it never repairs a document.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from functools import cache
from pathlib import Path
from typing import Annotated, Any, Literal, TypedDict

from pydantic import AfterValidator, BeforeValidator, ConfigDict, StringConstraints, TypeAdapter

from infosec_harness.domain.canonical import SHA256_PATTERN, is_sha256, sha256_hex

COMMIT = re.compile(r"^[a-f0-9]{40}$")
MAX_EVIDENCE_BYTES = 32 * 1024 * 1024

# Strict: no coercion and no unknown fields.
STRICT = ConfigDict(extra="forbid", strict=True)


class EvidenceUnavailable(ValueError):
    pass


def exact(kind: type) -> BeforeValidator:
    """Require exactly ``kind``. A ``Literal`` alone compares by equality, so ``Literal[1]``
    accepts ``True`` and ``Literal[True]`` accepts ``1``, even in strict mode."""
    def check(value: object) -> object:
        if type(value) is not kind:
            raise ValueError(f"expected {kind.__name__}")
        return value
    return BeforeValidator(check)


def _aware_timestamp(value: str) -> str:
    if datetime.fromisoformat(value).tzinfo is None:
        raise ValueError("timestamp has no timezone")
    return value


Sha256 = Annotated[str, StringConstraints(pattern=SHA256_PATTERN)]
Commit = Annotated[str, StringConstraints(pattern=COMMIT.pattern)]
# ISO-8601 with an explicit offset, kept as the recorded text.
Timestamp = Annotated[str, AfterValidator(_aware_timestamp)]
Version1 = Annotated[Literal[1], exact(int)]


class EvidenceReference(TypedDict):
    __pydantic_config__ = STRICT  # type: ignore[misc]
    file: Annotated[str, StringConstraints(min_length=1)]
    sha256: Sha256


@cache
def _adapter(schema: type) -> TypeAdapter:
    return TypeAdapter(schema)


def validated[T](schema: type[T], value: object) -> T:
    """``value`` checked against ``schema`` in strict mode; raises ``ValueError`` otherwise."""
    return _adapter(schema).validate_python(value)


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


def file_sha256(path: str | Path) -> str:
    return sha256_hex(read_bytes(path))


def reject_duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def read_evidence(path: Path, expected: str | None = None) -> Any:
    data = read_bytes(path)
    if expected is not None and (not is_sha256(expected) or sha256_hex(data) != expected):
        raise ValueError("evidence drift")
    return json.loads(data, object_pairs_hook=reject_duplicate_fields)


def read_reference(ref: EvidenceReference) -> Any:
    ref = validated(EvidenceReference, ref)
    return read_evidence(Path(ref["file"]), ref["sha256"])
