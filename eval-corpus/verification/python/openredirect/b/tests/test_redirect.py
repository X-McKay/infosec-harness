import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app import redirect_target


def test_relative_path_is_kept():
    assert redirect_target("/account") == "/account"
    assert redirect_target("/account?tab=1") == "/account?tab=1"


def test_allowed_host_is_kept():
    assert redirect_target("https://app.example.com/home") == "https://app.example.com/home"


def test_foreign_and_protocol_relative_targets_fall_back_to_root():
    for target in ("https://evil.example/", "//evil.example/", "https://app.example.com@evil.example/"):
        assert redirect_target(target) == "/", target


def test_backslash_and_control_character_variants_fall_back_to_root():
    # Found by the investigator on 2026-10-06: '/\evil.example/' passed the old guard (no
    # scheme, no netloc, one leading slash) and browsers read the backslash as '/', giving
    # the protocol-relative '//evil.example/'.
    for target in (
        r"/\evil.example/",
        r"/\\evil.example/",
        r"\/evil.example/",
        r"\\evil.example/",
        "/\t/evil.example/",
        "/\n/evil.example/",
        "/\x00/evil.example/",
        r"https:/\evil.example/",
    ):
        assert redirect_target(target) == "/", repr(target)
