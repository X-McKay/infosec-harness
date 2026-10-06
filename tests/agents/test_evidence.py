"""Probe observation parsing: exact final-line JSON with boolean claims only."""

import json

import pytest

from infosec_harness.agents.evidence import (
    MAX_PROBE_LINE_CHARS,
    PROBE_PREFIX,
    parse_probe_observations,
)
from infosec_harness.contracts import PROBE_FIELDS

VALID = dict.fromkeys(PROBE_FIELDS, True) | {"vulnerability_observed": False}
MARKER = PROBE_PREFIX + json.dumps(VALID)


@pytest.mark.parametrize(
    "stdout",
    [
        MARKER,
        "context\n" + MARKER + "\n",
        "context\r\n" + MARKER + "\r\n",
        # Trailing line terminators are stripped before the final line is taken.
        MARKER + "\n\n\r\n",
        # Whole-line bound: padding inside the JSON brings the line exactly to the limit.
        MARKER[:-1] + " " * (MAX_PROBE_LINE_CHARS - len(MARKER)) + "}",
    ],
)
def test_probe_line_contract_accepts_one_final_boolean_object(stdout):
    assert parse_probe_observations(stdout) == {**VALID, "origin": "self_reported"}


def pairs(*items):
    return "{" + ",".join(f'"{key}":{value}' for key, value in items) + "}"


@pytest.mark.parametrize(
    "stdout",
    [
        pytest.param(MARKER + "\nextra output", id="not-final"),
        pytest.param(MARKER.replace("HARNESS_PROBE ", "HARNESS_PROBE\n"), id="split-line"),
        pytest.param(
            MARKER[:-1] + " " * (MAX_PROBE_LINE_CHARS - len(MARKER) + 1) + "}", id="too-long"
        ),
        # Review of 2026-10-06: an array of [name, bool] pairs used to parse as the object.
        pytest.param(
            PROBE_PREFIX + json.dumps([[key, value] for key, value in VALID.items()]),
            id="array-of-pairs",
        ),
        pytest.param(PROBE_PREFIX + json.dumps(list(VALID)), id="array-of-names"),
        pytest.param(PROBE_PREFIX + "true", id="scalar"),
        pytest.param(
            PROBE_PREFIX + pairs(*((key, "true") for key in PROBE_FIELDS), ("target_reached", "false")),
            id="duplicate-key-six-fields",
        ),
        pytest.param(
            PROBE_PREFIX
            + pairs(*((key, "true") for key in PROBE_FIELDS[:-1]), (PROBE_FIELDS[0], "true")),
            id="duplicate-key-five-fields",
        ),
        pytest.param(PROBE_PREFIX + json.dumps({**VALID, "details": True}), id="extra-field"),
        pytest.param(
            PROBE_PREFIX + json.dumps({k: v for k, v in VALID.items() if k != "oracle_valid"}),
            id="missing-field",
        ),
        pytest.param(
            PROBE_PREFIX + json.dumps({**VALID, "target_reached": "true"}), id="string-value"
        ),
        pytest.param(PROBE_PREFIX + json.dumps({**VALID, "target_reached": 1}), id="number-value"),
        pytest.param(
            PROBE_PREFIX + json.dumps({**VALID, "target_reached": None}), id="null-value"
        ),
        pytest.param(
            PROBE_PREFIX + json.dumps({**VALID, "target_reached": {"value": True}}),
            id="object-value",
        ),
        pytest.param(PROBE_PREFIX + json.dumps(VALID)[:-1], id="malformed"),
    ],
)
def test_probe_line_contract_rejects_everything_else(stdout):
    assert parse_probe_observations(stdout) == {}
