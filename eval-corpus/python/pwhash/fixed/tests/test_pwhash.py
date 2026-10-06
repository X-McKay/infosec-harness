import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import hash_password, verify_password  # noqa: E402


def test_salted_kdf_is_not_the_weak_construction():
    pw = "correct horse battery staple"

    # positive control: round-trips.
    stored = hash_password(pw)
    assert verify_password(pw, stored)
    assert not verify_password("wrong", stored)

    # FIXED: two stored values for the same password differ (random salt).
    assert hash_password(pw) != hash_password(pw)

    # FIXED: the stored value is not an unsalted MD5 digest.
    assert stored != hashlib.md5(pw.encode()).hexdigest()
    assert stored.startswith("pbkdf2_sha256$")
