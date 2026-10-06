"""Password storage for a small user table.

FIXED: hash_password derives the stored value with PBKDF2-HMAC-SHA256 over a fresh
random salt and a work factor. Identical passwords yield different stored values, and
the derivation is deliberately slow.
"""

import hashlib
import hmac
import os

_ITERATIONS = 200_000


def hash_password(password: str) -> str:
    """Return the stored representation of a password.

    FIXED: per-password random salt + PBKDF2-HMAC-SHA256.
    """
    salt = os.urandom(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _ITERATIONS)
    return f"pbkdf2_sha256${_ITERATIONS}${salt.hex()}${derived.hex()}"


def verify_password(password: str, stored: str) -> bool:
    _, iterations, salt_hex, digest_hex = stored.split("$")
    derived = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
    )
    return hmac.compare_digest(derived.hex(), digest_hex)
