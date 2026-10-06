import base64
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import issue_token, verify_token  # noqa: E402

SECRET = b"server-only-secret-nonce"


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def forge_alg_none(claims: dict) -> str:
    header = _b64e(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64e(json.dumps(claims).encode())
    return f"{header}.{payload}."


def test_alg_none_token():
    # positive control: a genuinely signed token verifies.
    good = issue_token({"sub": "alice", "role": "user"}, SECRET)
    assert verify_token(good, SECRET)["role"] == "user"

    # negative control: a tampered signed token is rejected.
    assert verify_token(good + "x", SECRET) is None

    # A forged alg:none token.
    forged = forge_alg_none({"sub": "attacker", "role": "admin"})
    claims = verify_token(forged, SECRET)
    assert claims is not None and claims["role"] == "admin"
