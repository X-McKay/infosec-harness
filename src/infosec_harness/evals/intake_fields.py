"""Private, bounded observations of intake output proposals; never scoring or model feedback.

Intake speaks one output protocol, the atomic claim proposals the registry pins
(``intake-atomic-claims/v2``). Its summary (``intake-atomic-claim-proposals/v2``) reads the
captured proposals through the shared bounded walker in :mod:`infosec_harness.evals.messages`
and records

* reconstruction outcomes in closed categories,
* the evidence-guard summary (``intake-proposal-fields/v1``) of what reconstructed: each field
  checked through the unchanged guard, retaining only closed per-field rule counts, and
* the atomic wire-schema errors (``intake-atomic-schema-errors/v1``) as closed path/type
  buckets.

Every other agent records the guard summary as ``not_applicable``. No proposal value, key,
source ID, exception text or report fragment leaves this module.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal, TypedDict, cast

from pydantic import ValidationError
from pydantic_ai.messages import ModelMessage

from infosec_harness.domain.models import ExtractedFinding
from infosec_harness.evals.messages import (
    MAX_NODES,
    MAX_TEXT_CHARS,
    Walk,
    decode_arguments,
    iter_output_proposals,
    measure_shape,
)
from infosec_harness.intake.claims import AtomicFinding, ReferenceError, reconstruct
from infosec_harness.intake.evidence import (
    INTAKE_EVIDENCE_POLICY_VERSION,
    extraction_evidence_diagnostics,
)

MAX_EVIDENCE = 64
MAX_SCHEMA_ERRORS = 512

KnownField = Literal["file_path", "start_line", "end_line", "symbol", "cwe", "vulnerability_class",
                     "attack_preconditions", "claimed_impact"]
FieldRule = Literal["quote_not_verbatim", "positive_quote_missing", "positive_value_missing",
                    "literal_location_missing", "literal_line_missing", "positive_support_missing"]
AtomicRule = Literal["source_unavailable", "unknown_source_id", "reversed_source_range",
                     "schema_invalid", "bounded_out", "unsupported_shape"]
CaptureStatus = Literal["observed", "unknown", "not_applicable"]

FIELDS: tuple[KnownField, ...] = ("file_path", "start_line", "end_line", "symbol", "cwe",
                                 "vulnerability_class", "attack_preconditions", "claimed_impact")
FIELD_RULES: tuple[FieldRule, ...] = (
    "quote_not_verbatim", "positive_quote_missing", "positive_value_missing",
    "literal_location_missing", "literal_line_missing", "positive_support_missing")
ATOMIC_RULES: tuple[AtomicRule, ...] = (
    "source_unavailable", "unknown_source_id", "reversed_source_range", "schema_invalid",
    "bounded_out", "unsupported_shape")
SCHEMA_PATHS: tuple[str, ...] = (
    *FIELDS,
    *(f"{field}.{part}" for field in FIELDS for part in ("value", "source", "confidence")),
    *(f"{field}.source.{part}" for field in FIELDS for part in ("start_id", "end_id")),
    "model", "other",
)
SCHEMA_ERROR_TYPES: tuple[str, ...] = (
    "missing", "extra_forbidden", "string_type", "int_type", "float_type", "list_type",
    "dict_type", "model_type", "greater_than", "greater_than_equal", "less_than",
    "less_than_equal", "finite_number", "value_error", "json_invalid", "literal_error",
    "none_required", "other",
)


class IntakeFieldSummary(TypedDict):
    version: Literal["intake-proposal-fields/v1"]
    validation_policy: str
    capture_status: CaptureStatus
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


class ClaimSchemaSummary(TypedDict):
    version: Literal["intake-atomic-schema-errors/v1"]
    capture_status: CaptureStatus
    proposals_observed: int
    schema_valid_wire_proposals: int
    schema_invalid_proposals: int
    malformed_json_proposals: int
    unsupported_shape_proposals: int
    bounded_out_proposals: int
    validation_errors_observed: int
    field_path_counts: dict[str, int]
    error_type_counts: dict[str, int]
    truncated: bool


class AtomicSummary(TypedDict):
    version: Literal["intake-atomic-claim-proposals/v2"]
    capture_status: CaptureStatus
    proposals_observed: int
    reconstructed_proposals: int
    rejection_category_counts: dict[AtomicRule, int]
    materialized_guard_summary: IntakeFieldSummary
    schema_error_diagnostics: ClaimSchemaSummary
    truncated: bool


def intake_field_summary(
    messages: Sequence[ModelMessage], *, report: str | None, agent: str,
) -> IntakeFieldSummary | AtomicSummary:
    """The intake proposal summary; every other agent records the guard as not applicable."""
    if agent != "intake":
        return guard_summary([], report=report, status="not_applicable")
    return atomic_summary(messages, report=report)


def atomic_summary(messages: Sequence[ModelMessage], *, report: str | None) -> AtomicSummary:
    """Reconstruction outcomes for atomic claim proposals; materialization is not acceptance."""
    walk = Walk()
    proposals = [part.args for part in iter_output_proposals(messages, walk)]
    rejections: dict[AtomicRule, int] = dict.fromkeys(ATOMIC_RULES, 0)
    truncated = walk.truncated
    materialized: list[dict[str, Any]] = []
    retained_nodes = retained_chars = 0
    for raw in proposals:
        if report is not None and len(report) > MAX_TEXT_CHARS:
            rejections["bounded_out"] += 1
            truncated = True
            continue
        args, problem = decode_arguments(raw)
        if problem is not None:
            rule: AtomicRule = "schema_invalid" if problem == "malformed_json" else problem
            rejections[rule] += 1
            truncated |= problem == "bounded_out"
            continue
        try:
            finding = reconstruct(report, AtomicFinding.model_validate(args))
            value = finding.model_dump(mode="json")
        except ValidationError:
            rejections["schema_invalid"] += 1
            continue
        except ReferenceError as error:
            known = isinstance(error.rule, str) and error.rule in ATOMIC_RULES
            rejections[cast(AtomicRule, error.rule) if known else "unsupported_shape"] += 1
            continue
        except Exception:
            rejections["unsupported_shape"] += 1
            continue
        # Any shape problem in an already-validated finding is a size problem.
        size = measure_shape(value) if len(finding.evidence) <= MAX_EVIDENCE else "bounded_out"
        if isinstance(size, str) or (retained_nodes + size[0] > MAX_NODES
                                     or retained_chars + size[1] > MAX_TEXT_CHARS):
            rejections["bounded_out"] += 1
            truncated = True
            continue
        retained_nodes += size[0]
        retained_chars += size[1]
        materialized.append(value)
    guard = guard_summary(materialized, report=report)
    return {
        "version": "intake-atomic-claim-proposals/v2",
        "capture_status": "observed" if proposals else "unknown",
        "proposals_observed": len(proposals),
        "reconstructed_proposals": len(materialized),
        "rejection_category_counts": rejections,
        "materialized_guard_summary": guard,
        "schema_error_diagnostics": _schema_summary(
            proposals, scan_truncated=walk.truncated, status=_status(messages)),
        "truncated": truncated or guard["truncated"],
    }


def _status(messages: Sequence[ModelMessage]) -> CaptureStatus:
    return "observed" if messages else "unknown"


def guard_summary(proposals: list[object], *, report: str | None,
                  status: CaptureStatus = "observed") -> IntakeFieldSummary:
    """Check each proposal's fields through the unchanged pure guard; retain only counts."""
    summary: IntakeFieldSummary = {
        "version": "intake-proposal-fields/v1", "validation_policy": INTAKE_EVIDENCE_POLICY_VERSION,
        "capture_status": status, "proposals_observed": 0, "proposals_checked": 0,
        "schema_invalid_proposals": 0, "unsupported_shape_proposals": 0,
        "bounded_out_proposals": 0, "guard_unavailable_proposals": 0,
        "source_unavailable_proposals": 0, "unknown_evidence_field_proposals": 0,
        "proposals_with_guard_violations": 0,
        "field_rule_counts": {field: dict.fromkeys(FIELD_RULES, 0) for field in FIELDS},
        "quote_not_verbatim_but_whitespace_normalized_match": dict.fromkeys(FIELDS, 0),
        "truncated": False,
    }
    if status == "not_applicable":
        return summary
    report_bounded = report is not None and len(report) > MAX_TEXT_CHARS
    normalized_report = " ".join(report.split()) if report is not None and not report_bounded else None
    for raw in proposals:
        summary["proposals_observed"] += 1
        if report_bounded:
            summary["bounded_out_proposals"] += 1
            summary["truncated"] = True
            continue
        args, problem = decode_arguments(raw)
        if problem == "bounded_out":
            summary["bounded_out_proposals"] += 1
            summary["truncated"] = True
            continue
        if problem == "malformed_json":
            summary["schema_invalid_proposals"] += 1
            continue
        if problem is not None:
            summary["unsupported_shape_proposals"] += 1
            continue
        try:
            output = ExtractedFinding.model_validate(args)
        except ValidationError:
            summary["schema_invalid_proposals"] += 1
            continue
        except Exception:
            summary["unsupported_shape_proposals"] += 1
            continue
        if len(output.evidence) > MAX_EVIDENCE:
            summary["bounded_out_proposals"] += 1
            summary["truncated"] = True
            continue
        try:
            value = output.model_dump(mode="json")
            full = extraction_evidence_diagnostics(report, value)
            categories = {item.code for item in full}
            per_field: dict[KnownField, set[FieldRule]] = {}
            whitespace_fields: set[KnownField] = set()
            if report is not None:
                for field in FIELDS:
                    evidence = [entry for entry in value["evidence"] if entry["field"] == field]
                    errors = extraction_evidence_diagnostics(
                        report, {field: value[field], "evidence": evidence})
                    field_categories = {item.code for item in errors}
                    if not field_categories.issubset(FIELD_RULES):
                        raise ValueError("Unknown field-rule vocabulary")
                    per_field[field] = {cast(FieldRule, category) for category in field_categories}
                    if normalized_report is not None and any(
                        entry["quote"].strip() and entry["quote"] not in report
                        and " ".join(entry["quote"].split()) in normalized_report
                        for entry in evidence
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
    # Nonempty SDK history does not imply a captured output proposal.
    if summary["capture_status"] == "observed" and summary["proposals_observed"] == 0:
        summary["capture_status"] = "unknown"
    return summary


def _schema_summary(proposals: list[object], *, scan_truncated: bool,
                    status: CaptureStatus) -> ClaimSchemaSummary:
    """Summarize only bounded proposal-schema failures; retain or return no proposal data."""
    result: ClaimSchemaSummary = {
        "version": "intake-atomic-schema-errors/v1",
        "capture_status": "not_applicable" if status == "not_applicable"
        else "observed" if proposals else "unknown",
        "proposals_observed": len(proposals), "schema_valid_wire_proposals": 0,
        "schema_invalid_proposals": 0, "malformed_json_proposals": 0,
        "unsupported_shape_proposals": 0, "bounded_out_proposals": 0,
        "validation_errors_observed": 0,
        "field_path_counts": dict.fromkeys(SCHEMA_PATHS, 0),
        "error_type_counts": dict.fromkeys(SCHEMA_ERROR_TYPES, 0),
        "truncated": scan_truncated,
    }
    errors_used = 0
    for raw in proposals:
        args, problem = decode_arguments(raw)
        if problem is not None:
            result[f"{problem}_proposals"] += 1  # type: ignore[literal-required]
            result["truncated"] |= problem == "bounded_out"
            continue
        try:
            AtomicFinding.model_validate(args)
        except ValidationError as error:
            result["schema_invalid_proposals"] += 1
            # Pydantic's detailed errors are obtained with all unsafe payload-bearing
            # fields disabled. Only closed buckets and bounded counters escape here.
            for item in error.errors(include_input=False, include_context=False,
                                     include_url=False):
                if errors_used >= MAX_SCHEMA_ERRORS:
                    result["truncated"] = True
                    break
                result["field_path_counts"][_path_bucket(item.get("loc"))] += 1
                result["error_type_counts"][_error_type_bucket(item.get("type"))] += 1
                result["validation_errors_observed"] += 1
                errors_used += 1
        except Exception:
            # Never serialize arbitrary local exception classes/messages.
            result["unsupported_shape_proposals"] += 1
        else:
            result["schema_valid_wire_proposals"] += 1
    return result


def _path_bucket(location: Any) -> str:
    """Map a Pydantic loc to a fixed schema path; never return dynamic keys or indices."""
    if not isinstance(location, (tuple, list)) or not location:
        return "model"
    field = location[0]
    if not isinstance(field, str) or field not in FIELDS:
        return "other"
    if len(location) == 1:
        return field
    segment = location[1]
    if segment == "value":
        return f"{field}.value"
    if segment == "confidence":
        return f"{field}.confidence" if len(location) == 2 else "other"
    if segment == "source":
        if len(location) == 2:
            return f"{field}.source"
        if len(location) == 3 and isinstance(location[2], str) \
                and location[2] in {"start_id", "end_id"}:
            return f"{field}.source.{location[2]}"
    return "other"


def _error_type_bucket(error_type: Any) -> str:
    known = isinstance(error_type, str) and error_type in SCHEMA_ERROR_TYPES[:-1]
    return error_type if known else "other"
