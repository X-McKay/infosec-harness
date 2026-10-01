"""Bounded closed schema observations; never acceptance, scoring, or model feedback."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any, Literal, TypedDict

from pydantic import ValidationError
from pydantic_ai.messages import ModelMessage, ModelResponse, ToolCallPart

from infosec_harness.agents.intake_claims import AtomicFinding
from infosec_harness.evals.intake_fields import _shape

VERSION = "intake-atomic-schema-errors/v1"
MAX_MESSAGES, MAX_PARTS, MAX_PROPOSALS = 128, 512, 32
MAX_TEXT_CHARS, MAX_ERRORS = 131072, 512

FIELDS = (
    "file_path",
    "start_line",
    "end_line",
    "symbol",
    "cwe",
    "vulnerability_class",
    "attack_preconditions",
    "claimed_impact",
)
PATHS = tuple(
    [field for field in FIELDS]
    + [f"{field}.{part}" for field in FIELDS for part in ("value", "source", "confidence")]
    + [f"{field}.source.{part}" for field in FIELDS for part in ("start_id", "end_id")]
    + ["model", "other"]
)
ERROR_TYPES = (
    "missing",
    "extra_forbidden",
    "string_type",
    "int_type",
    "float_type",
    "list_type",
    "dict_type",
    "model_type",
    "greater_than",
    "greater_than_equal",
    "less_than",
    "less_than_equal",
    "finite_number",
    "value_error",
    "json_invalid",
    "literal_error",
    "none_required",
    "other",
)


def _path_bucket(location: Any) -> str:
    """Map Pydantic loc to a fixed schema path; never return dynamic keys/indices."""
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
        if (
            len(location) == 3
            and isinstance(location[2], str)
            and location[2] in {"start_id", "end_id"}
        ):
            return f"{field}.source.{location[2]}"
    return "other"


def _error_type_bucket(error_type: Any) -> str:
    return error_type if isinstance(error_type, str) and error_type in ERROR_TYPES[:-1] else "other"


class ClaimSchemaSummary(TypedDict):
    version: Literal["intake-atomic-schema-errors/v1"]
    capture_status: Literal["observed", "unknown", "not_applicable"]
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


def _summary(
    *, status: Literal["observed", "unknown", "not_applicable"] = "unknown"
) -> ClaimSchemaSummary:
    return {
        "version": VERSION,
        "capture_status": status,
        "proposals_observed": 0,
        "schema_valid_wire_proposals": 0,
        "schema_invalid_proposals": 0,
        "malformed_json_proposals": 0,
        "unsupported_shape_proposals": 0,
        "bounded_out_proposals": 0,
        "validation_errors_observed": 0,
        "field_path_counts": dict.fromkeys(PATHS, 0),
        "error_type_counts": dict.fromkeys(ERROR_TYPES, 0),
        "truncated": False,
    }


def diagnose_proposals(proposals: Sequence[Any]) -> ClaimSchemaSummary:
    """Summarize only bounded proposal-schema failures; retain or return no proposal data."""
    result = _summary()
    if type(proposals) not in (list, tuple):
        return result
    observed = min(len(proposals), MAX_PROPOSALS)
    result["proposals_observed"] = observed
    if observed:
        result["capture_status"] = "observed"
    result["truncated"] = len(proposals) > MAX_PROPOSALS
    errors_used = 0
    for raw in proposals[:MAX_PROPOSALS]:
        if isinstance(raw, str):
            if len(raw) > MAX_TEXT_CHARS:
                result["bounded_out_proposals"] += 1
                result["truncated"] = True
                continue
            try:
                args = json.loads(raw)
            except (json.JSONDecodeError, TypeError, ValueError):
                result["malformed_json_proposals"] += 1
                continue
            except Exception:
                result["unsupported_shape_proposals"] += 1
                continue
        else:
            args = raw
        if not isinstance(args, dict):
            result["unsupported_shape_proposals"] += 1
            continue
        shape = _shape(args)
        if shape is not None:
            key = (
                "bounded_out_proposals" if shape == "bounded_out" else "unsupported_shape_proposals"
            )
            result[key] += 1
            result["truncated"] |= shape == "bounded_out"
            continue
        try:
            AtomicFinding.model_validate(args)
        except ValidationError as error:
            result["schema_invalid_proposals"] += 1
            # Pydantic's detailed errors are obtained with all unsafe payload-bearing
            # fields disabled. Only closed buckets and bounded counters escape here.
            details = error.errors(include_input=False, include_context=False, include_url=False)
            for item in details:
                if errors_used >= MAX_ERRORS:
                    result["truncated"] = True
                    break
                path = _path_bucket(item.get("loc"))
                error_type = _error_type_bucket(item.get("type"))
                result["field_path_counts"][path] += 1
                result["error_type_counts"][error_type] += 1
                result["validation_errors_observed"] += 1
                errors_used += 1
        except Exception:
            # Never serialize arbitrary local exception classes/messages.
            result["unsupported_shape_proposals"] += 1
        else:
            result["schema_valid_wire_proposals"] += 1
    return result


def diagnose_messages(
    messages: Sequence[ModelMessage], *, agent: str = "intake"
) -> ClaimSchemaSummary:
    """Extract only final-result tool args from already-captured SDK messages."""
    proposals: list[Any] = []
    parts_seen = 0
    truncated = False
    if agent != "intake":
        return _summary(status="not_applicable")
    if type(messages) not in (list, tuple):
        return _summary()
    for position, message in enumerate(messages):
        if position >= MAX_MESSAGES:
            truncated = True
            break
        if not isinstance(message, ModelResponse):
            continue
        for part in message.parts:
            if parts_seen >= MAX_PARTS or len(proposals) >= MAX_PROPOSALS:
                truncated = True
                break
            parts_seen += 1
            if not isinstance(part, ToolCallPart) or part.tool_name != "final_result":
                continue
            proposals.append(part.args)
        if truncated:
            break
    result = diagnose_proposals(proposals)
    result["truncated"] |= truncated
    return result
