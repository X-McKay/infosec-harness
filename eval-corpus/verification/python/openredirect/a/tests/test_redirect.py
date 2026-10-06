import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app import redirect_target


def test_relative_path_is_kept():
    assert redirect_target("/account") == "/account"


def test_foreign_targets_pass_through_unchanged():
    for target in ("https://evil.example/", "//evil.example/", r"/\evil.example/"):
        assert redirect_target(target) == target, target
