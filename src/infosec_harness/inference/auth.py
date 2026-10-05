"""Exact-request authentication; channel keys never enter durable wire schemas."""

from __future__ import annotations

import hashlib
import hmac
import re
import time
from collections.abc import Mapping

from .protocol import MAX_BODY_BYTES, SIGNED_PATHS, BrokerError

AUTH_HEADER = "X-Harness-Admission"
# Credential headers: a request may carry each at most once.
CREDENTIAL_HEADERS = ("Authorization", AUTH_HEADER)
MAX_AUTH_LIFETIME = 60


def _material(method: str, path: str, body: bytes, expires_at: int) -> bytes:
    if method != "POST" or path not in SIGNED_PATHS or len(body) > MAX_BODY_BYTES:
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


def header_value(headers: Mapping[str, str], name: str) -> str:
    """The single value of a case-insensitive header; absent or repeated is empty."""
    values = [value for key, value in headers.items() if key.lower() == name.lower()]
    return values[0] if len(values) == 1 else ""


def verify_headers(secret: bytes, path: str, body: bytes, headers: Mapping[str, str], *,
                   now: int) -> None:
    """Authenticate one signed POST from its admission header."""
    verify_request(secret, "POST", path, body, header_value(headers, AUTH_HEADER), now=now)
