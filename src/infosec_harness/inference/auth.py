"""Exact-request authentication; channel keys never enter durable wire schemas."""

from __future__ import annotations

import hashlib
import hmac
import re
import time

from .protocol import MAX_BODY_BYTES, BrokerError

AUTH_HEADER = "X-Harness-Admission"
MAX_AUTH_LIFETIME = 60


def _material(method: str, path: str, body: bytes, expires_at: int) -> bytes:
    if (
        method != "POST"
        or path
        not in {
            "/v1/infer",
            "/v1/invocations",
            "/v1/results",
            "/v1/runs/close",
            "/v1/ledger/claim",
            "/v1/ledger/complete",
        }
        or len(body) > MAX_BODY_BYTES
    ):
        raise BrokerError("auth")
    return (
        b"ih-auth-v1\n"
        + method.encode()
        + b"\n"
        + path.encode()
        + b"\n"
        + str(expires_at).encode()
        + b"\n"
        + body
    )


def sign_request(secret: bytes, method: str, path: str, body: bytes, expires_at: int) -> str:
    if len(secret) < 32 or not isinstance(expires_at, int) or isinstance(expires_at, bool):
        raise BrokerError("auth")
    signature = hmac.new(
        secret, _material(method, path, body, expires_at), hashlib.sha256
    ).hexdigest()
    return f"v1:{expires_at}:{signature}"


def verify_request(
    secret: bytes, method: str, path: str, body: bytes, header: str, *, now: int | None = None
) -> None:
    match = re.fullmatch(r"v1:([0-9]{1,12}):([a-f0-9]{64})", header)
    if match is None:
        raise BrokerError("auth")
    expiry = int(match[1])
    current = int(time.time()) if now is None else now
    if expiry <= current or expiry > current + MAX_AUTH_LIFETIME:
        raise BrokerError("auth")
    expected = sign_request(secret, method, path, body, expiry)
    if not hmac.compare_digest(expected, header):
        raise BrokerError("auth")
