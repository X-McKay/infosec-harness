"""Pure Docker configuration comparison for operator recovery checks.

These functions provide no lifecycle or ownership authority. Callers must bind exact
issued container IDs and independently check process identity, source, and retained state.
"""

import hashlib
import json
from copy import deepcopy
from typing import Any


def _records(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ValueError("Docker mount records must be a list of objects")
    return sorted(
        deepcopy(value), key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":"))
    )


def canonical_configuration(inspected: dict[str, Any]) -> dict[str, Any]:
    """Preserve every configuration field; normalize only mount-record ordering."""
    result = deepcopy(
        {key: inspected[key] for key in ("Config", "HostConfig", "Mounts", "NetworkSettings")}
    )
    result["Mounts"] = _records(result["Mounts"])
    if "Mounts" in result["HostConfig"]:
        result["HostConfig"]["Mounts"] = _records(result["HostConfig"]["Mounts"])
    return result


def configuration_digest(inspected: dict[str, Any]) -> str:
    value = json.dumps(
        canonical_configuration(inspected), sort_keys=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(value).hexdigest()


def validate_replacement_host_config(
    previous: dict[str, Any], replacement: dict[str, Any], *, created: bool
) -> None:
    """Check exact host settings, with only the observed default OOM representation.

    Moby defaults an absent OomKillDisable to false during creation and may clear
    the unsupported option to null. This never accepts true or numeric zero.
    """
    old, new = deepcopy(previous), deepcopy(replacement)
    if "OomKillDisable" not in old or "OomKillDisable" not in new:
        raise ValueError("Expected recorded OOM fields")
    if old["OomKillDisable"] is not None:
        raise ValueError("Expected the recorded absent OOM override")
    value = new["OomKillDisable"]
    valid = value is False if created else value is None or value is False
    if not valid:
        raise ValueError("Unexpected OOM override")
    old["OomKillDisable"] = new["OomKillDisable"] = False
    for item in (old, new):
        if "Mounts" in item:
            item["Mounts"] = _records(item["Mounts"])
    if json.dumps(old, sort_keys=True) != json.dumps(new, sort_keys=True):
        raise ValueError("Controller host configuration differs")
