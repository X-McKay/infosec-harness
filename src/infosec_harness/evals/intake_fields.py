"""Private, bounded observations of proposed extraction fields; never scoring or feedback."""
from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Literal, TypedDict, cast

from pydantic import ValidationError
from pydantic_ai.messages import ModelMessage, ModelResponse, ToolCallPart

from infosec_harness.agents.intake_evidence import (
    INTAKE_EVIDENCE_POLICY_VERSION,
    extraction_evidence_violations,
)
from infosec_harness.domain.models import ExtractedFinding
from infosec_harness.evals.output_retries import INTAKE_RULE_CATEGORIES

KnownField = Literal["file_path", "start_line", "end_line", "symbol", "cwe", "vulnerability_class",
                     "attack_preconditions", "claimed_impact"]
FieldRule = Literal["quote_not_verbatim", "positive_quote_missing", "positive_value_missing",
                    "literal_location_missing", "literal_line_missing", "positive_support_missing"]
FIELDS: tuple[KnownField, ...] = ("file_path", "start_line", "end_line", "symbol", "cwe",
                                "vulnerability_class", "attack_preconditions", "claimed_impact")
RULES: tuple[FieldRule, ...] = ("quote_not_verbatim", "positive_quote_missing", "positive_value_missing",
                              "literal_location_missing", "literal_line_missing", "positive_support_missing")
MAX_MESSAGES, MAX_PARTS, MAX_PROPOSALS = 128, 512, 32
MAX_TEXT_CHARS, MAX_NODES, MAX_DEPTH, MAX_EVIDENCE = 131072, 2048, 8, 64


class IntakeFieldSummary(TypedDict):
    version: Literal["intake-proposal-fields/v1"]
    validation_policy: str
    capture_status: Literal["observed", "unknown", "not_applicable"]
    proposals_observed: int
    proposals_checked: int
    schema_invalid_proposals: int
    unsupported_shape_proposals: int
    bounded_out_proposals: int
    guard_unavailable_proposals: int
    source_unavailable_proposals: int
    unknown_evidence_field_proposals: int
    proposals_with_guard_violations: int
    field_rule_counts: dict[KnownField, dict[FieldRule, int]]
    quote_not_verbatim_but_whitespace_normalized_match: dict[KnownField, int]
    truncated: bool


def _shape(args: dict) -> Literal["unsupported_shape", "bounded_out"] | None:
    """Bound traversal without repr/JSON serialization of arbitrary argument objects."""
    stack, nodes, chars = [(args, 0)], 0, 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            return "bounded_out"
        if isinstance(value, str):
            chars += len(value)
            if chars > MAX_TEXT_CHARS:
                return "bounded_out"
        elif isinstance(value, dict):
            if len(value) > MAX_NODES or not all(isinstance(key, str) for key in value):
                return "bounded_out" if len(value) > MAX_NODES else "unsupported_shape"
            stack.extend((item, depth + 1) for pair in value.items() for item in pair)
        elif isinstance(value, list):
            if len(value) > MAX_NODES:
                return "bounded_out"
            stack.extend((item, depth + 1) for item in value)
        elif isinstance(value, int):
            if value.bit_length() > 4096:
                return "bounded_out"
        elif value is not None and not isinstance(value, float):
            return "unsupported_shape"
    return None


def intake_field_summary(messages: Sequence[ModelMessage], *, report: str | None,
                         agent: str) -> IntakeFieldSummary:
    """Check each field through the unchanged pure guard; retain only finite count keys."""
    summary: IntakeFieldSummary = {
        "version": "intake-proposal-fields/v1", "validation_policy": INTAKE_EVIDENCE_POLICY_VERSION,
        "capture_status": "not_applicable" if agent != "intake" else "observed" if messages else "unknown",
        "proposals_observed": 0, "proposals_checked": 0, "schema_invalid_proposals": 0,
        "unsupported_shape_proposals": 0, "bounded_out_proposals": 0, "guard_unavailable_proposals": 0,
        "source_unavailable_proposals": 0, "unknown_evidence_field_proposals": 0,
        "proposals_with_guard_violations": 0,
        "field_rule_counts": {field: dict.fromkeys(RULES, 0) for field in FIELDS},
        "quote_not_verbatim_but_whitespace_normalized_match": dict.fromkeys(FIELDS, 0), "truncated": False,
    }
    if agent != "intake":
        return summary
    normalized_report = " ".join(report.split()) if report is not None and len(report) <= MAX_TEXT_CHARS else None
    scanned_parts = 0
    for number, message in enumerate(messages):
        if number >= MAX_MESSAGES:
            summary["truncated"] = True
            break
        if not isinstance(message, ModelResponse):
            continue
        for part in message.parts:
            if scanned_parts >= MAX_PARTS:
                summary["truncated"] = True
                return summary
            scanned_parts += 1
            if not isinstance(part, ToolCallPart) or part.tool_name != "final_result":
                continue
            if summary["proposals_observed"] >= MAX_PROPOSALS:
                summary["truncated"] = True
                return summary
            summary["proposals_observed"] += 1
            try:
                if report is not None and len(report) > MAX_TEXT_CHARS:
                    reason = "bounded_out"
                else:
                    args = part.args
                    if isinstance(args, str) and len(args) > MAX_TEXT_CHARS:
                        reason = "bounded_out"
                    else:
                        args = json.loads(args) if isinstance(args, str) else args
                        reason = _shape(args) if isinstance(args, dict) else "unsupported_shape"
                if reason is not None:
                    if reason == "bounded_out":
                        summary["bounded_out_proposals"] += 1
                    else:
                        summary["unsupported_shape_proposals"] += 1
                    summary["truncated"] |= reason == "bounded_out"
                    continue
                output = ExtractedFinding.model_validate(args)
                if len(output.evidence) > MAX_EVIDENCE:
                    summary["bounded_out_proposals"] += 1
                    summary["truncated"] = True
                    continue
            except (ValidationError, json.JSONDecodeError):
                summary["schema_invalid_proposals"] += 1
                continue
            except Exception:
                summary["unsupported_shape_proposals"] += 1
                continue
            try:
                value = output.model_dump(mode="json")
                full = extraction_evidence_violations(report, value)
                categories = {INTAKE_RULE_CATEGORIES[item] for item in full}
                per_field: dict[KnownField, set[FieldRule]] = {}
                whitespace_fields: set[KnownField] = set()
                if report is not None:
                    for field in FIELDS:
                        evidence = [entry for entry in value["evidence"] if entry["field"] == field]
                        errors = extraction_evidence_violations(report, {field: value[field], "evidence": evidence})
                        field_categories = {INTAKE_RULE_CATEGORIES[item] for item in errors}
                        if not field_categories.issubset(RULES):
                            raise ValueError("Unknown field-rule vocabulary")
                        per_field[field] = {cast(FieldRule, category) for category in field_categories}
                        if normalized_report is not None and any(
                            entry["quote"].strip() and entry["quote"] not in report
                            and " ".join(entry["quote"].split()) in normalized_report for entry in evidence
                        ):
                            whitespace_fields.add(field)
            except Exception:
                # Diagnostics must not replace the primary evaluation result, and may not
                # export exceptions or invent attribution if the guard vocabulary changes.
                summary["guard_unavailable_proposals"] += 1
                continue
            summary["proposals_checked"] += 1
            summary["proposals_with_guard_violations"] += bool(full)
            summary["source_unavailable_proposals"] += "source_unavailable" in categories
            summary["unknown_evidence_field_proposals"] += "unknown_field" in categories
            for field, errors in per_field.items():
                for category in errors:
                    summary["field_rule_counts"][field][category] += 1
            for field in whitespace_fields:
                summary["quote_not_verbatim_but_whitespace_normalized_match"][field] += 1
    return summary
