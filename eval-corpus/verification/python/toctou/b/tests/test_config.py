import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app import read_config


def test_reads_regular_file():
    d = tempfile.mkdtemp()
    path = os.path.join(d, "config.txt")
    with open(path, "w") as handle:
        handle.write("ok")
    assert read_config(path) == "ok"


def test_symlink():
    # A final symlink to a file outside the directory.
    d = tempfile.mkdtemp()
    secret = os.path.join(d, "secret.txt")
    with open(secret, "w") as handle:
        handle.write("TOP-SECRET")
    link = os.path.join(d, "config.txt")
    os.symlink(secret, link)
    try:
        assert read_config(link) == "TOP-SECRET"
    finally:
        os.unlink(link)
