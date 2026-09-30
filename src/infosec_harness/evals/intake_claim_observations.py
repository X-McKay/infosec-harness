"""Bounded atomic proposal observations; materialization is not guard acceptance."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Literal, TypedDict

from pydantic import ValidationError
from pydantic_ai.messages import ModelMessage, ModelResponse, ToolCallPart

from infosec_harness.agents.intake_claims import AtomicFinding, ReferenceError, reconstruct
from infosec_harness.evals.intake_claim_schema import ClaimSchemaSummary, diagnose_messages
from infosec_harness.evals.intake_fields import IntakeFieldSummary, _shape, intake_field_summary

Rule = Literal[
    "source_unavailable",
    "unknown_source_id",
    "reversed_source_range",
    "schema_invalid",
    "bounded_out",
    "unsupported_shape",
]
RULES: tuple[Rule, ...] = (
    "source_unavailable",
    "unknown_source_id",
    "reversed_source_range",
    "schema_invalid",
    "bounded_out",
    "unsupported_shape",
)


class AtomicSummary(TypedDict):
    version: Literal["intake-atomic-claim-proposals/v2"]
    capture_status: Literal["observed", "unknown", "not_applicable"]
    proposals_observed: int
    reconstructed_proposals: int
    rejection_category_counts: dict[Rule, int]
    materialized_guard_summary: IntakeFieldSummary
    schema_error_diagnostics: ClaimSchemaSummary
    truncated: bool


def shape_size(value: dict) -> tuple[int, int]:
    """Only called after bounded _shape; count retained object nodes and all strings."""
    stack, nodes, chars = [value], 0, 0
    while stack:
        item = stack.pop()
        nodes += 1
        if isinstance(item, str):
            chars += len(item)
        elif isinstance(item, dict):
            stack.extend(part for pair in item.items() for part in pair)
        elif isinstance(item, list):
            stack.extend(item)
    return nodes, chars


def atomic_summary(
    messages: Sequence[ModelMessage], *, report: str | None, agent: str
) -> AtomicSummary:
    result: AtomicSummary = {
        "version": "intake-atomic-claim-proposals/v2",
        "capture_status": "not_applicable"
        if agent != "intake"
        else "observed"
        if messages
        else "unknown",
        "proposals_observed": 0,
        "reconstructed_proposals": 0,
        "rejection_category_counts": dict.fromkeys(RULES, 0),
        "materialized_guard_summary": intake_field_summary([], report=report, agent=agent),
        "truncated": False,
        "schema_error_diagnostics": diagnose_messages(messages, agent=agent),
    }
    if agent != "intake":
        return result
    retained, parts, retained_nodes, retained_chars = [], 0, 0, 0
    for position, message in enumerate(messages):
        if position >= 128:
            result["truncated"] = True
            break
        if not isinstance(message, ModelResponse):
            continue
        for part in message.parts:
            if parts >= 512 or result["proposals_observed"] >= 32:
                result["truncated"] = True
                break
            parts += 1
            if not isinstance(part, ToolCallPart) or part.tool_name != "final_result":
                continue
            result["proposals_observed"] += 1
            try:
                if (report is not None and len(report) > 131072) or (
                    isinstance(part.args, str) and len(part.args) > 131072
                ):
                    reason = "bounded_out"
                else:
                    args = json.loads(part.args) if isinstance(part.args, str) else part.args
                    reason = _shape(args) if isinstance(args, dict) else "unsupported_shape"
                if reason:
                    result["rejection_category_counts"][reason] += 1
                    result["truncated"] |= reason == "bounded_out"
                    continue
                wire = AtomicFinding.model_validate(args)
                finding = reconstruct(report, wire)
                materialized = finding.model_dump(mode="json")
                if len(finding.evidence) > 64 or _shape(materialized) is not None:
                    result["rejection_category_counts"]["bounded_out"] += 1
                    result["truncated"] = True
                    continue
                nodes, chars = shape_size(materialized)
                if retained_nodes + nodes > 2048 or retained_chars + chars > 131072:
                    result["rejection_category_counts"]["bounded_out"] += 1
                    result["truncated"] = True
                    continue
            except (ValidationError, json.JSONDecodeError):
                result["rejection_category_counts"]["schema_invalid"] += 1
                continue
            except ReferenceError as error:
                rule = (
                    error.rule
                    if isinstance(error.rule, str) and error.rule in RULES
                    else "unsupported_shape"
                )
                result["rejection_category_counts"][rule] += 1
                continue
            except Exception:
                result["rejection_category_counts"]["unsupported_shape"] += 1
                continue
            retained_nodes += nodes
            retained_chars += chars
            result["reconstructed_proposals"] += 1
            retained.append(ModelResponse(parts=[ToolCallPart("final_result", materialized)]))
    result["materialized_guard_summary"] = intake_field_summary(
        retained, report=report, agent=agent
    )
    result["truncated"] |= result["materialized_guard_summary"]["truncated"]
    if result["proposals_observed"] == 0:
        result["capture_status"] = "unknown"
    return result
