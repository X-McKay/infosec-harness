import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import hash_password, verify_password  # noqa: E402


def test_unsalted_md5_is_detectable():
    pw = "correct horse battery staple"

    # positive control: round-trips.
    stored = hash_password(pw)
    assert verify_password(pw, stored)
    assert not verify_password("wrong", stored)

    # VULNERABLE: two users with the same password store identical values (no salt).
    assert hash_password(pw) == hash_password(pw)

    # VULNERABLE: the stored value is exactly unsalted MD5.
    assert stored == hashlib.md5(pw.encode()).hexdigest()
