import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import hash_password, verify_password  # noqa: E402


def test_stored_value():
    pw = "correct horse battery staple"

    # positive control: round-trips.
    stored = hash_password(pw)
    assert verify_password(pw, stored)
    assert not verify_password("wrong", stored)

    # Two stored values for the same password.
    assert hash_password(pw) == hash_password(pw)

    # The stored value compared with an unsalted MD5 digest.
    assert stored == hashlib.md5(pw.encode()).hexdigest()
