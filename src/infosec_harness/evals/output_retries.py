"""Bounded preceding SDK retry observations; never an attribution of terminal cause.

Inspect only RetryPromptPart shape and exact static intake feedback. Discard all source,
model, provider, tool/field names, schema details, arguments, and exception bodies.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Literal, TypedDict

from pydantic_ai.messages import ModelMessage, ModelRequest, RetryPromptPart

RetryCategory = Literal[
    "source_unavailable", "unknown_field", "quote_not_verbatim", "positive_quote_missing",
    "positive_value_missing", "literal_location_missing", "literal_line_missing", "positive_support_missing",
]


class RetryCategoryCounts(TypedDict):
    source_unavailable: int
    unknown_field: int
    quote_not_verbatim: int
    positive_quote_missing: int
    positive_value_missing: int
    literal_location_missing: int
    literal_line_missing: int
    positive_support_missing: int


class OutputRetrySummary(TypedDict):
    version: Literal["output-retries/v1"]
    capture_status: Literal["observed", "unknown"]
    retry_parts_observed: int
    intake_guard_retry_parts: int
    intake_guard_category_counts: RetryCategoryCounts
    output_schema_retry_parts: int
    function_tool_retry_parts: int
    unclassified_retry_parts: int
    truncated: bool


OUTPUT_RETRY_SUMMARY_VERSION: Literal["output-retries/v1"] = "output-retries/v1"
MAX_MESSAGES = 128
MAX_REQUEST_PARTS = 512
MAX_RETRY_PARTS = 32
MAX_CONTENT_CHARS = 4096
_INTAKE_PREFIX = "Extraction violates its evidence contract:\n- "
INTAKE_RULE_CATEGORIES: dict[str, RetryCategory] = {
    "Exact source report is unavailable; extraction cannot be validated.": "source_unavailable",
    "Evidence names an unknown extraction field.": "unknown_field",
    "An evidence quote is not a nonempty verbatim report span.": "quote_not_verbatim",
    "Positive evidence requires a nonempty verbatim report span.": "positive_quote_missing",
    "Positive evidence cannot support an unset extraction field.": "positive_value_missing",
    "A literal location value is absent from its evidence quote.": "literal_location_missing",
    "A literal line number is absent from its evidence quote.": "literal_line_missing",
    "Every nonempty extraction field requires positive grounded evidence.": "positive_support_missing",
}


def output_retry_summary(messages: Sequence[ModelMessage], *, agent: str) -> OutputRetrySummary:
    """Known feedback counts do not establish why an invocation ultimately failed."""
    counts: RetryCategoryCounts = {
        "source_unavailable": 0, "unknown_field": 0, "quote_not_verbatim": 0,
        "positive_quote_missing": 0, "positive_value_missing": 0, "literal_location_missing": 0,
        "literal_line_missing": 0, "positive_support_missing": 0,
    }
    summary: OutputRetrySummary = {"version": OUTPUT_RETRY_SUMMARY_VERSION,
               "capture_status": "observed" if messages else "unknown",
               "retry_parts_observed": 0, "intake_guard_retry_parts": 0,
               "intake_guard_category_counts": counts, "output_schema_retry_parts": 0,
               "function_tool_retry_parts": 0, "unclassified_retry_parts": 0, "truncated": False}
    scanned_parts = 0
    for number, message in enumerate(messages):
        if number >= MAX_MESSAGES:
            summary["truncated"] = True
            break
        if not isinstance(message, ModelRequest):
            continue
        for part in message.parts:
            if scanned_parts >= MAX_REQUEST_PARTS:
                summary["truncated"] = True
                return summary
            scanned_parts += 1
            if not isinstance(part, RetryPromptPart):
                continue
            if summary["retry_parts_observed"] >= MAX_RETRY_PARTS:
                summary["truncated"] = True
                return summary
            summary["retry_parts_observed"] += 1
            # Intake currently uses the SDK's single default structured output tool.
            # Other agents may rename output tools, so leave those retries unclassified.
            if agent != "intake":
                summary["unclassified_retry_parts"] += 1
            elif part.tool_name == "final_result":
                if isinstance(part.content, list):
                    summary["output_schema_retry_parts"] += 1
                    continue
                if not isinstance(part.content, str):
                    summary["unclassified_retry_parts"] += 1
                    continue
                content = part.content
                if len(content) <= MAX_CONTENT_CHARS and content.startswith(_INTAKE_PREFIX):
                    messages_in_retry = content[len(_INTAKE_PREFIX):].split("\n- ")
                    if messages_in_retry and all(item in INTAKE_RULE_CATEGORIES for item in messages_in_retry):
                        summary["intake_guard_retry_parts"] += 1
                        for category in {INTAKE_RULE_CATEGORIES[item] for item in messages_in_retry}:
                            counts[category] += 1
                        continue
                summary["unclassified_retry_parts"] += 1
                summary["truncated"] |= len(content) > MAX_CONTENT_CHARS
            elif part.tool_name:
                summary["function_tool_retry_parts"] += 1
            else:
                summary["unclassified_retry_parts"] += 1
    return summary
