"""Field observations mirror unchanged guard predicates and retain no argument bodies.

The guard summary is what intake's atomic summary records for the proposals that reconstructed
(``materialized_guard_summary``); it is exercised directly on reconstructed findings here.
"""
from __future__ import annotations

import copy
import json

import pytest
from pydantic_ai.messages import ModelResponse, ToolCallPart

from infosec_harness.domain.models import ExtractedFinding
from infosec_harness.evals.intake_fields import FIELD_RULES as RULES
from infosec_harness.evals.intake_fields import FIELDS, guard_summary, intake_field_summary
from infosec_harness.intake.evidence import (
    EXTRACTED_FIELDS,
    extraction_evidence_diagnostics,
    extraction_evidence_violations,
)

REPORT = "Caller input is\ninterpolated into a shell command."


def proposal(args, name="final_result"):
    return ModelResponse(parts=[ToolCallPart(name, args, tool_call_id="SECRET_ID")])


def observe(args, report=REPORT):
    return guard_summary([args], report=report)


def evidence(field="cwe", quote=REPORT, confidence=1):
    return {"field": field, "quote": quote, "confidence": confidence}


CASES = [
    (REPORT, {"cwe": "CWE-78", "evidence": [evidence()]}),
    (REPORT, {"cwe": None, "evidence": [evidence()]}),
    (REPORT, {"cwe": "CWE-78", "evidence": [evidence(quote="Fabricated behavior.")]}),
    (REPORT, {"claimed_impact": "Second command", "evidence": []}),
    ("app.py line 420", {"file_path": "elsewhere.py", "start_line": 42, "evidence": [
        evidence("file_path", "app.py line 420"), evidence("start_line", "app.py line 420")]}),
    (REPORT, {"evidence": [evidence("SECRET_UNKNOWN_FIELD", "SECRET_QUOTE")]}),
    (REPORT, {"evidence": [evidence(confidence=0)]}),
    (REPORT, {"evidence": []}),
    (None, {"cwe": "CWE-78", "evidence": [evidence()]}),
]


@pytest.mark.parametrize("report,args", CASES)
def test_field_category_union_matches_actual_whole_guard_predicates(report, args):
    before = copy.deepcopy(args)
    parsed = ExtractedFinding.model_validate(args).model_dump(mode="json")
    actual = {item.code for item in extraction_evidence_diagnostics(report, parsed)}
    observed = observe(args, report)
    assert observed["proposals_checked"] == 1
    assert observed["proposals_with_guard_violations"] == bool(actual)
    categories = {category for counts in observed["field_rule_counts"].values()
                  for category, count in counts.items() if count}
    if observed["source_unavailable_proposals"]:
        categories.add("source_unavailable")
    if observed["unknown_evidence_field_proposals"]:
        categories.add("unknown_field")
    assert categories == actual and args == before
    assert set(observed["field_rule_counts"]) == EXTRACTED_FIELDS == set(FIELDS)
    assert all(set(counts) == set(RULES) for counts in observed["field_rule_counts"].values())
    assert "SECRET" not in json.dumps(observed)


def test_known_field_attribution_is_precise_without_guessing_values_or_classes():
    args = {"cwe": None, "claimed_impact": "An impact", "evidence": [evidence()]}
    observed = observe(args)
    assert observed["field_rule_counts"]["cwe"]["positive_value_missing"] == 1
    assert observed["field_rule_counts"]["claimed_impact"]["positive_support_missing"] == 1
    assert observed["field_rule_counts"]["cwe"]["positive_support_missing"] == 0
    assert observed["field_rule_counts"]["file_path"] == dict.fromkeys(RULES, 0)


@pytest.mark.parametrize("quote,match", [
    ("Caller input is interpolated into a shell command.", 1),
    ("Caller input is\tinterpolated into a shell command.", 1),
    ("Fabricated input behavior.", 0),
    (REPORT, 0),
    ("   ", 0),
])
def test_whitespace_observation_never_accepts_or_rewrites_rejected_quotes(quote, match):
    args = {"cwe": "CWE-78", "evidence": [evidence(quote=quote)]}
    before = copy.deepcopy(args)
    actual = extraction_evidence_violations(REPORT, args)
    observed = observe(args)
    assert observed["quote_not_verbatim_but_whitespace_normalized_match"]["cwe"] == match
    assert observed["proposals_with_guard_violations"] == bool(actual)
    assert args == before
    if match:
        assert actual and observed["field_rule_counts"]["cwe"]["quote_not_verbatim"] == 1


@pytest.mark.parametrize("args,key", [
    ({"cwe": ["SECRET_VALUE"]}, "schema_invalid_proposals"),
    ("{SECRET_MALFORMED_JSON", "schema_invalid_proposals"),
    (["SECRET_PROTOCOL_SHAPE"], "unsupported_shape_proposals"),
    ("SECRET" * 30000, "bounded_out_proposals"),
    ({"evidence": [evidence()] * 65}, "bounded_out_proposals"),
    ({"start_line": 1 << 10000}, "bounded_out_proposals"),
])
def test_malformed_and_bounded_proposals_remain_closed_private_categories(args, key):
    observed = observe(args)
    assert observed[key] == 1 and observed["proposals_checked"] == 0
    assert "SECRET" not in json.dumps(observed)


def test_an_unboundedly_long_report_is_not_scanned():
    observed = guard_summary([{}], report="SECRET" * 30000)
    assert observed["truncated"] and observed["bounded_out_proposals"] == 1
    assert observed["proposals_checked"] == 0
    assert "SECRET" not in json.dumps(observed)


def test_nonoutput_and_other_agent_proposals_are_not_guessed():
    observed = intake_field_summary([proposal({"SECRET_ARGS": "SECRET_VALUE"}, "SECRET_TOOL")],
                                    report=REPORT, agent="intake")
    assert observed["proposals_observed"] == 0
    assert intake_field_summary([], report=REPORT, agent="intake")["capture_status"] == "unknown"
    observed = intake_field_summary([proposal({})], report=REPORT, agent="context")
    assert observed["capture_status"] == "not_applicable" and observed["proposals_observed"] == 0
    assert "SECRET" not in json.dumps(observed)


@pytest.mark.parametrize("args", [
    {"ignored": [0] * 2049},
    {"ignored": [[[[[[[[[0]]]]]]]]]},
    {"start_line": 1 << 10000},
])
def test_json_and_dict_proposals_share_structural_bounds(args):
    summaries = [observe(value) for value in (args, json.dumps(args))]
    assert summaries[0] == summaries[1]
    assert summaries[0]["bounded_out_proposals"] == 1
    assert summaries[0]["proposals_checked"] == 0 and summaries[0]["truncated"]
