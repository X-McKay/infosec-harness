"""Canonical JSON bytes, SHA-256 digests and hex-digest validation.

Standard library only: this module is part of the isolated inference executor's source
closure, so it must not import the rest of the harness.

``canonical_bytes`` is the one canonical encoding: sorted keys, no insignificant whitespace,
UTF-8 output and no NaN/Infinity. Persisted digests that were produced with a different
encoding keep a purpose-named frozen function next to their owner (for example
``persistence.reconciliation.reconciliation_digest``); never "fix" one of those to this
encoding, because existing stored values would stop verifying.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SHA256 = re.compile(r"[0-9a-f]{64}")


def canonical_bytes(value: Any, *, ascii_only: bool = False) -> bytes:
    """Byte-stable JSON. Raises ``ValueError`` for NaN/Infinity, ``TypeError`` for non-JSON."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=ascii_only, allow_nan=False
    ).encode("utf-8")


def sha256_hex(data: bytes | str) -> str:
    return hashlib.sha256(data.encode("utf-8") if isinstance(data, str) else data).hexdigest()


def digest(value: Any) -> str:
    """SHA-256 of :func:`canonical_bytes`. Wire identities and ledger rows use this encoding."""
    return sha256_hex(canonical_bytes(value))


def is_sha256(value: object) -> bool:
    """Exactly 64 lowercase hex characters; never coerces non-strings."""
    return type(value) is str and _SHA256.fullmatch(value) is not None
