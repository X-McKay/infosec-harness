import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app import user_city


def test_present_address_returns_city():
    assert user_city('{"address": {"city": "NYC"}}') == "NYC"


def test_missing_address():
    assert user_city('{"name": "bob"}') == "unknown"


def test_non_object_payloads_never_dereference_none():
    # Found by the investigator on 2026-10-06: 'null' made json.loads return None and
    # data.get raised AttributeError before the address guard.
    for payload in ("null", "[]", '"text"', "1", '{"address": null}', '{"address": []}'):
        assert user_city(payload) == "unknown"
