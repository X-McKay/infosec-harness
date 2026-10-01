"""Field observations mirror unchanged guard predicates and retain no argument bodies."""
from __future__ import annotations

import copy
import json

import pytest
import yaml
from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart
from pydantic_ai.models.function import FunctionModel
from sqlalchemy import select

from infosec_harness.agents.intake_contracts import retained_intake_spec
from infosec_harness.agents.intake_evidence import EXTRACTED_FIELDS, extraction_evidence_violations
from infosec_harness.domain.models import ExtractedFinding
from infosec_harness.evals.intake_fields import FIELDS, RULES, intake_field_summary
from infosec_harness.evals.output_retries import INTAKE_RULE_CATEGORIES

REPORT = "Caller input is\ninterpolated into a shell command."


def proposal(args, name="final_result"):
    return ModelResponse(parts=[ToolCallPart(name, args, tool_call_id="SECRET_ID")])


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
    actual = {INTAKE_RULE_CATEGORIES[item] for item in extraction_evidence_violations(report, parsed)}
    observed = intake_field_summary([proposal(args)], report=report, agent="intake")
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
    observed = intake_field_summary([proposal(args)], report=REPORT, agent="intake")
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
    observed = intake_field_summary([proposal(args)], report=REPORT, agent="intake")
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
    observed = intake_field_summary([proposal(args)], report=REPORT, agent="intake")
    assert observed[key] == 1 and observed["proposals_checked"] == 0
    assert "SECRET" not in json.dumps(observed)


@pytest.mark.parametrize("messages,report,count", [
    ([proposal({})] * 33, REPORT, 32),
    ([ModelResponse(parts=[])] * 128 + [proposal({})], REPORT, 0),
    ([ModelResponse(parts=[TextPart("SECRET")] * 512 + [ToolCallPart("final_result", {})])], REPORT, 0),
    ([proposal({})], "SECRET" * 30000, 1),
])
def test_observation_scanner_bounds_are_explicit(messages, report, count):
    observed = intake_field_summary(messages, report=report, agent="intake")
    assert observed["truncated"] and observed["proposals_observed"] == count
    assert all(value <= 32 for counts in observed["field_rule_counts"].values() for value in counts.values())
    assert "SECRET" not in json.dumps(observed)


def test_nonoutput_and_other_agent_proposals_are_not_guessed():
    observed = intake_field_summary([proposal({"SECRET_ARGS": "SECRET_VALUE"}, "SECRET_TOOL")],
                                    report=REPORT, agent="intake")
    assert observed["proposals_observed"] == 0
    assert intake_field_summary([], report=REPORT, agent="intake")["capture_status"] == "unknown"
    observed = intake_field_summary([proposal({})], report=REPORT, agent="context")
    assert observed["capture_status"] == "not_applicable" and observed["proposals_observed"] == 0


@pytest.mark.parametrize("protocol_failure", [False, True])
async def test_actual_sdk_and_eval_persist_field_observations_without_scoring_changes(
    tmp_path, monkeypatch, protocol_failure,
):
    from pydantic_ai.exceptions import UnexpectedModelBehavior

    from infosec_harness.agents import registry
    from infosec_harness.evals import run
    from infosec_harness.persistence import db
    from infosec_harness.settings import get_settings

    path = tmp_path / "intake/evals/dataset.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(yaml.safe_dump({"version": "synthetic-field-observation", "cases": [
        {"name": "synthetic-finding", "category": "smoke", "payload": {"report": REPORT},
         "expected": "CWE-78"}]}))
    monkeypatch.setattr(run, "get_settings", lambda: get_settings().model_copy(update={"agents_dir": tmp_path}))
    calls = []

    def respond(_messages, info):
        calls.append(1)
        if len(calls) == 2 and protocol_failure:
            raise UnexpectedModelBehavior("SECRET_PROVIDER", body="SECRET_BODY")
        quote = "Caller input is interpolated into a shell command." if len(calls) == 1 else REPORT
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name,
            {"cwe": "CWE-78", "evidence": [evidence(quote=quote)]})])

    agent = registry.build_agent("intake", durable=False, production_transport=True,
                        spec_override=retained_intake_spec(), atomic_output=False)
    monkeypatch.setattr(registry, "build_agent", lambda *_args, **_kwargs: agent)
    monkeypatch.setattr(registry, "load_spec", lambda *_args, **_kwargs: retained_intake_spec())
    with agent.override(model=FunctionModel(respond)):
        exp_id = await run.run_experiment("intake")
    async with db.session() as session:
        experiment = await session.get(db.EvalExperiment, exp_id)
        row = (await session.execute(select(db.EvalCaseResult).where(
            db.EvalCaseResult.experiment_id == exp_id))).scalar_one()
    summary = row.scores["intake_field_summary"]
    assert summary == experiment.metrics["attempts"][0]["intake_field_summary"]
    assert summary["proposals_observed"] == (1 if protocol_failure else 2)
    assert summary["field_rule_counts"]["cwe"]["quote_not_verbatim"] == 1
    assert summary["quote_not_verbatim_but_whitespace_normalized_match"]["cwe"] == 1
    assert row.passed is (not protocol_failure)
    assert run.EVALUATOR_VERSION == "deterministic-agent-output-v11"
    if protocol_failure:
        assert row.scores["error_category"] == "no_accepted_output" and row.scores["usage_status"] == "unknown"
        assert "SECRET" not in json.dumps(row.scores)
    else:
        assert row.scores["usage"]["requests"] == 2
    assert "SECRET" not in json.dumps(summary)


@pytest.mark.parametrize("args", [
    {"ignored": [0] * 2049},
    {"ignored": [[[[[[[[[0]]]]]]]]]},
    {"start_line": 1 << 10000},
])
def test_json_and_dict_proposals_share_structural_bounds(args):
    summaries = [intake_field_summary([proposal(value)], report=REPORT, agent="intake")
                 for value in (args, json.dumps(args))]
    assert summaries[0] == summaries[1]
    assert summaries[0]["bounded_out_proposals"] == 1
    assert summaries[0]["proposals_checked"] == 0 and summaries[0]["truncated"]
