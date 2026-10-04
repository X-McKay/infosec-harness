"""Independent guards for Docker's observed mount-order/default representations."""

import importlib.util
from copy import deepcopy
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "controller_configuration", ROOT / "scripts/openshell_controller_configuration.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


@pytest.fixture
def inspected():
    records = [
        {"Type": "bind", "Source": "/operator/" + name, "Target": "/" + name, "ReadOnly": ro}
        for name, ro in (
            ("workspace", True),
            ("state", False),
            ("leases", False),
            ("socket", False),
        )
    ]
    return {
        "Config": {"Env": ["PYTHONPATH=/workspace/src"], "Labels": {"ih.owner": "qualification"}},
        "HostConfig": {
            "Mounts": records,
            "OomKillDisable": None,
            "Privileged": False,
            "Runtime": "runc",
        },
        "Mounts": records,
        "NetworkSettings": {"Networks": {"host": {}}},
    }


def test_mount_order_changes_in_both_arrays_have_identical_digest(inspected):
    reordered = deepcopy(inspected)
    reordered["Mounts"].reverse()
    reordered["HostConfig"]["Mounts"] = (
        reordered["HostConfig"]["Mounts"][2:] + reordered["HostConfig"]["Mounts"][:2]
    )
    before = deepcopy(inspected)
    assert MODULE.configuration_digest(inspected) == MODULE.configuration_digest(reordered)
    assert inspected == before


@pytest.mark.parametrize("value", [None, False])
def test_running_default_oom_representation(value, inspected):
    old = inspected["HostConfig"]
    new = deepcopy(old)
    new["Mounts"].reverse()
    new["OomKillDisable"] = value
    MODULE.validate_replacement_host_config(old, new, created=False)


def test_created_requires_boolean_false(inspected):
    old = inspected["HostConfig"]
    new = deepcopy(old)
    with pytest.raises(ValueError):
        MODULE.validate_replacement_host_config(old, new, created=True)
    new["OomKillDisable"] = False
    MODULE.validate_replacement_host_config(old, new, created=True)


@pytest.mark.parametrize("value", [True, 0, 1, "false"])
def test_oom_override_type_boundary(value, inspected):
    new = deepcopy(inspected["HostConfig"])
    new["OomKillDisable"] = value
    with pytest.raises(ValueError):
        MODULE.validate_replacement_host_config(inspected["HostConfig"], new, created=False)


@pytest.mark.parametrize(
    "scope", ["source", "readonly", "runtime", "privileged", "environment", "network"]
)
def test_security_changes_remain_visible(scope, inspected):
    changed = deepcopy(inspected)
    if scope == "source":
        changed["HostConfig"]["Mounts"][0]["Source"] = "/foreign"
    elif scope == "readonly":
        changed["HostConfig"]["Mounts"][0]["ReadOnly"] = False
    elif scope == "runtime":
        changed["HostConfig"]["Runtime"] = "foreign"
    elif scope == "privileged":
        changed["HostConfig"]["Privileged"] = True
    elif scope == "environment":
        changed["Config"]["Env"] = ["PYTHONPATH=/foreign"]
    else:
        changed["NetworkSettings"]["Networks"] = {"foreign": {}}
    assert MODULE.configuration_digest(changed) != MODULE.configuration_digest(inspected)


def test_health_digest_retains_exact_oom_value(inspected):
    changed = deepcopy(inspected)
    changed["HostConfig"]["OomKillDisable"] = False
    assert MODULE.configuration_digest(changed) != MODULE.configuration_digest(inspected)


@pytest.mark.parametrize("side", ["old", "new"])
def test_missing_oom_field_not_normalized(side, inspected):
    old = deepcopy(inspected["HostConfig"])
    new = deepcopy(old)
    new["OomKillDisable"] = False
    (old if side == "old" else new).pop("OomKillDisable")
    with pytest.raises(ValueError):
        MODULE.validate_replacement_host_config(old, new, created=True)


def test_host_setting_boolean_numeric_type_drift_rejected(inspected):
    old = inspected["HostConfig"]
    new = deepcopy(old)
    new["OomKillDisable"] = False
    new["Privileged"] = 0
    with pytest.raises(ValueError):
        MODULE.validate_replacement_host_config(old, new, created=True)


def test_canonical_mount_sort_matches_recovery_compact_json(inspected):
    import json

    # Independent recovery convention: compact JSON is the exact ordering key.
    records = inspected["Mounts"] + [{"Type": "bind", "ReadOnly": True}]
    inspected["Mounts"] = records
    inspected["HostConfig"]["Mounts"] = list(reversed(records))
    expected = sorted(
        records, key=lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"))
    )
    value = MODULE.canonical_configuration(inspected)
    assert value["Mounts"] == value["HostConfig"]["Mounts"] == expected
