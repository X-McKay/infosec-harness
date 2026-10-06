"""Probe observation parsing: exact final-line JSON with boolean claims only."""

import json


def test_probe_markers_require_exact_final_json_and_boolean_claims():
    from infosec_harness.agents.evidence import parse_probe_observations

    valid = {
        "target_reached": True,
        "oracle_valid": True,
        "positive_control": True,
        "negative_control": True,
        "vulnerability_observed": False,
    }
    marker = "HARNESS_PROBE " + json.dumps(valid)
    assert parse_probe_observations(marker)["origin"] == "self_reported"
    assert parse_probe_observations(marker + "\nextra output") == {}
    assert (
        parse_probe_observations("HARNESS_PROBE " + json.dumps({**valid, "target_reached": "true"}))
        == {}
    )
    assert (
        parse_probe_observations('HARNESS_PROBE {"target_reached":true,"target_reached":false}')
        == {}
    )
