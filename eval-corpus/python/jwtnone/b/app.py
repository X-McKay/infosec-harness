"""A hand-rolled JWT-style token: base64url(header).base64url(payload).signature."""

import base64
import hashlib
import hmac
import json


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _sign(signing_input: bytes, secret: bytes) -> str:
    return _b64e(hmac.new(secret, signing_input, hashlib.sha256).digest())


def issue_token(claims: dict, secret: bytes) -> str:
    header = _b64e(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64e(json.dumps(claims).encode())
    signing_input = f"{header}.{payload}".encode()
    return f"{header}.{payload}.{_sign(signing_input, secret)}"


def verify_token(token: str, secret: bytes):
    """Return the claims if the token verifies, else None."""
    header_b64, payload_b64, signature = token.split(".")
    header = json.loads(_b64d(header_b64))
    if header.get("alg") != "HS256":
        return None
    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected = _sign(signing_input, secret)
    if hmac.compare_digest(expected, signature):
        return json.loads(_b64d(payload_b64))
    return None
