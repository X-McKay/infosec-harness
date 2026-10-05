"""Intake's one output protocol, finite privacy, and original guard parity."""

from __future__ import annotations

import copy
import json

import pytest
from pydantic_ai import Agent, ModelRetry
from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart
from pydantic_ai.models.function import FunctionModel

from infosec_harness.agents.intake_claims import AtomicFinding, ReferenceError, reconstruct
from infosec_harness.agents.intake_evidence import extraction_evidence_violations
from infosec_harness.domain.models import ExtractedFinding
from infosec_harness.evals.intake_fields import (
    ATOMIC_RULES as RULES,
)
from infosec_harness.evals.intake_fields import (
    SCHEMA_ERROR_TYPES as ERROR_TYPES,
)
from infosec_harness.evals.intake_fields import (
    SCHEMA_PATHS as PATHS,
)
from infosec_harness.evals.intake_fields import (
    atomic_summary,
    intake_field_summary,
)

REPORT = "fixture.py line 12\r\nCaller input reaches a shell.\nImpact is described.\n"


def claim(value, start="S000001", end=None, confidence=0.75):
    return {"value": value, "source": {"start_id": start, "end_id": end}, "confidence": confidence}


def message(args, name="final_result"):
    return ModelResponse(parts=[ToolCallPart(name, args, tool_call_id="PRIVATE_ID")])


def observe(args, report=REPORT):
    return intake_field_summary([message(args)], report=report, agent="intake")


def diagnose_messages(messages):
    return atomic_summary(messages, report=REPORT)["schema_error_diagnostics"]


def test_intake_is_summarized_as_atomic_claims_and_other_agents_as_not_applicable():
    raw = {"file_path": claim("fixture.py")}
    observed = observe(raw)
    assert observed["version"] == "intake-atomic-claim-proposals/v2"
    assert observed["reconstructed_proposals"] == 1
    other = intake_field_summary([message(raw)], report=REPORT, agent="context")
    assert other["version"] == "intake-proposal-fields/v1"
    assert other["capture_status"] == "not_applicable" and other["proposals_observed"] == 0


@pytest.mark.parametrize(
    "args,report,category",
    [
        ({"file_path": claim("fixture.py")}, None, "source_unavailable"),
        ({"cwe": claim("PRIVATE_VALUE", "PRIVATE_SOURCE_ID")}, REPORT, "unknown_source_id"),
        ({"cwe": claim("PRIVATE_VALUE", "S000003", "S000001")}, REPORT, "reversed_source_range"),
        ({"cwe": claim(None)}, REPORT, "schema_invalid"),
        ({"cwe": claim("PRIVATE_VALUE", confidence=0)}, REPORT, "schema_invalid"),
        (["PRIVATE_SHAPE"], REPORT, "unsupported_shape"),
        ("{PRIVATE_JSON", REPORT, "schema_invalid"),
        ({"ignored": [0] * 2049}, REPORT, "bounded_out"),
    ],
)
def test_reference_rejection_categories_are_finite(args, report, category):
    summary = observe(args, report)
    assert summary["proposals_observed"] == 1
    assert summary["reconstructed_proposals"] == 0
    assert summary["rejection_category_counts"][category] == 1
    assert set(summary["rejection_category_counts"]) == set(RULES)
    assert "PRIVATE_" not in json.dumps(summary)


@pytest.mark.parametrize(
    "value",
    [
        {"file_path": claim("fixture.py")},
        {"start_line": claim(12)},
        {"start_line": claim(420)},
        {"file_path": claim("elsewhere.py")},
        {"symbol": claim("not_in_source")},
        {"cwe": claim("CWE-78", "S000002")},
        {"vulnerability_class": claim("OS command injection", "S000002")},
        {"attack_preconditions": claim(["one", "two"], "S000002", "S000003")},
        {"claimed_impact": claim("Impact is described.", "S000003")},
        {},
    ],
)
def test_materialized_wire_valid_is_separate_from_original_guard_acceptance(value):
    before = copy.deepcopy(value)
    finding = reconstruct(REPORT, AtomicFinding.model_validate(value))
    violations = extraction_evidence_violations(REPORT, finding.model_dump(mode="json"))
    summary = observe(value)
    assert summary["schema_error_diagnostics"]["schema_valid_wire_proposals"] == 1
    assert summary["reconstructed_proposals"] == 1
    nested = summary["materialized_guard_summary"]
    assert nested["proposals_checked"] == 1
    assert nested["proposals_with_guard_violations"] == bool(violations)
    assert value == before


def test_schema_error_paths_and_types_do_not_echo_values_keys_ids_or_context():
    invalid = {
        "cwe": claim("PRIVATE_VALUE", "PRIVATE_REFERENCE", confidence=0),
        "PRIVATE_KEY": "PRIVATE_SOURCE_BODY",
    }
    summary = observe(invalid)["schema_error_diagnostics"]
    assert summary["field_path_counts"]["cwe.confidence"] == 1
    assert summary["field_path_counts"]["other"] == 1
    assert summary["error_type_counts"]["greater_than"] == 1
    assert summary["error_type_counts"]["extra_forbidden"] == 1
    assert summary["validation_errors_observed"] == sum(summary["field_path_counts"].values())
    assert summary["validation_errors_observed"] == sum(summary["error_type_counts"].values())
    assert set(summary["field_path_counts"]) == set(PATHS)
    assert set(summary["error_type_counts"]) == set(ERROR_TYPES)
    assert "PRIVATE_" not in json.dumps(summary)


@pytest.mark.parametrize(
    "raw",
    [
        {"extra": [0] * 2049},
        {"extra": [[[[[[[[[0]]]]]]]]]},
    ],
)
def test_string_json_and_dict_share_bounds(raw):
    first, second = observe(raw), observe(json.dumps(raw))
    assert first == second and first["truncated"]
    assert first["schema_error_diagnostics"]["bounded_out_proposals"] == 1


def test_schema_partition_unknown_and_nonintake_capture():
    values = [{}, {"cwe": claim("x", confidence=0)}, "{", [], "x" * 131073]
    summary = diagnose_messages([message(v) for v in values])
    assert summary["proposals_observed"] == 5
    assert summary["proposals_observed"] == sum(
        summary[key]
        for key in (
            "schema_valid_wire_proposals",
            "schema_invalid_proposals",
            "malformed_json_proposals",
            "unsupported_shape_proposals",
            "bounded_out_proposals",
        )
    )
    assert diagnose_messages([message({}, "PRIVATE_TOOL")])["capture_status"] == "unknown"
    assert intake_field_summary([], report=None, agent="other")["capture_status"] \
        == "not_applicable"


@pytest.mark.parametrize(
    "messages",
    [
        [message({})] * 33,
        [ModelResponse(parts=[])] * 128 + [message({})],
        [
            ModelResponse(
                parts=[TextPart("PRIVATE_TEXT")] * 512 + [ToolCallPart("final_result", {})]
            )
        ],
    ],
)
def test_capture_caps_are_finite_and_private(messages):
    summary = atomic_summary(messages, report=REPORT)
    assert summary["truncated"] and summary["proposals_observed"] <= 32
    assert summary["schema_error_diagnostics"]["proposals_observed"] <= 32
    assert "PRIVATE_" not in json.dumps(summary)


def test_aggregate_materialized_capture_is_bounded_independently_of_schema():
    report = "PRIVATE_SOURCE" * 5000 + "\n"
    summary = atomic_summary(
        [message({"claimed_impact": claim("impact")})] * 4, report=report
    )
    assert summary["truncated"]
    assert summary["reconstructed_proposals"] < 4
    assert summary["schema_error_diagnostics"]["schema_valid_wire_proposals"] == 4
    assert summary["schema_error_diagnostics"]["truncated"] is False
    assert "PRIVATE_" not in json.dumps(summary)


async def test_actual_sdk_invalid_then_correct_proposals_are_observed_without_regrading():
    calls = []

    def respond(_messages, info):
        calls.append(1)
        args = {"start_line": claim(420 if len(calls) == 1 else 12)}
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, args)])

    agent = Agent(FunctionModel(respond), output_type=AtomicFinding, retries=1)

    @agent.output_validator
    def original_guard(output: AtomicFinding) -> ExtractedFinding:
        try:
            finding = reconstruct(REPORT, output)
        except ReferenceError:
            raise ModelRetry("Source reference violates its contract") from None
        errors = extraction_evidence_violations(REPORT, finding.model_dump(mode="json"))
        if errors:
            raise ModelRetry("Extraction violates its evidence contract:\n- " + "\n- ".join(errors))
        return finding

    result = await agent.run("Synthetic report")
    assert isinstance(result.output, ExtractedFinding) and result.output.start_line == 12
    summary = intake_field_summary(result.all_messages(), report=REPORT, agent="intake")
    assert len(calls) == 2 and summary["proposals_observed"] == 2
    assert summary["schema_error_diagnostics"]["schema_valid_wire_proposals"] == 2
    assert summary["materialized_guard_summary"]["proposals_with_guard_violations"] == 1
    assert (
        summary["materialized_guard_summary"]["field_rule_counts"]["start_line"][
            "literal_line_missing"
        ]
        == 1
    )


@pytest.mark.parametrize(
    "messages",
    [
        [ModelResponse(parts=[TextPart("PRIVATE_BODY")])],
        [message({"PRIVATE_VALUE": "PRIVATE_BODY"}, "load_capability")],
        [
            ModelResponse(
                parts=[TextPart("PRIVATE_BODY")] * 512 + [ToolCallPart("final_result", {})]
            )
        ],
        [ModelResponse(parts=[])] * 128 + [message({})],
    ],
)
def test_nonempty_history_without_captured_output_remains_unknown(messages):
    summary = intake_field_summary(messages, report=REPORT, agent="intake")
    assert summary["capture_status"] == "unknown" and summary["proposals_observed"] == 0
    assert "PRIVATE_" not in json.dumps(summary)
