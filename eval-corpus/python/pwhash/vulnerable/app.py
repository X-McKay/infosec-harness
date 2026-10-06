"""Password storage for a small user table.

VULNERABLE: hash_password stores an unsalted MD5 digest. Identical passwords yield
identical digests, and MD5 is a fast hash unsuitable for passwords.
"""

import hashlib


def hash_password(password: str) -> str:
    """Return the stored representation of a password.

    VULNERABLE: unsalted MD5.
    """
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def verify_password(password: str, stored: str) -> bool:
    return hash_password(password) == stored
