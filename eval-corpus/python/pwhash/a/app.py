"""Password storage for a small user table."""

import hashlib


def hash_password(password: str) -> str:
    """Return the stored representation of a password."""
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def verify_password(password: str, stored: str) -> bool:
    return hash_password(password) == stored
