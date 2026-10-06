import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app import user_city


def test_present_address_returns_city():
    assert user_city('{"address": {"city": "NYC"}}') == "NYC"


def test_missing_address():
    assert user_city('{"name": "bob"}') == "unknown"
