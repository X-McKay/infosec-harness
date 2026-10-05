"""Literal source grounding and extraction consistency, not a weakness classifier.

Report text remains untrusted. These checks cannot prove the chosen CWE is semantically
correct and never guess a label, rewrite output, or treat a source directive as authority.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, NamedTuple

from infosec_harness.intake.claims import AtomicFinding

INTAKE_EVIDENCE_POLICY_VERSION = "intake-evidence/v1"
EXTRACTED_FIELDS = frozenset(AtomicFinding.model_fields)
_LITERAL_STRINGS = frozenset({"file_path", "symbol"})
_LINES = frozenset({"start_line", "end_line"})


class EvidenceDiagnostic(NamedTuple):
    """One closed evidence-contract diagnostic: a stable code and its model-visible message.

    The message is the only text that reaches the model; it never carries report or claim data.
    Consumers branch on ``code``, never on the message wording.
    """

    code: str
    message: str


SOURCE_UNAVAILABLE = EvidenceDiagnostic(
    "source_unavailable", "Exact source report is unavailable; extraction cannot be validated.")
UNKNOWN_FIELD = EvidenceDiagnostic(
    "unknown_field", "Evidence names an unknown extraction field.")
QUOTE_NOT_VERBATIM = EvidenceDiagnostic(
    "quote_not_verbatim", "An evidence quote is not a nonempty verbatim report span.")
POSITIVE_QUOTE_MISSING = EvidenceDiagnostic(
    "positive_quote_missing", "Positive evidence requires a nonempty verbatim report span.")
POSITIVE_VALUE_MISSING = EvidenceDiagnostic(
    "positive_value_missing", "Positive evidence cannot support an unset extraction field.")
LITERAL_LOCATION_MISSING = EvidenceDiagnostic(
    "literal_location_missing", "A literal location value is absent from its evidence quote.")
LITERAL_LINE_MISSING = EvidenceDiagnostic(
    "literal_line_missing", "A literal line number is absent from its evidence quote.")
POSITIVE_SUPPORT_MISSING = EvidenceDiagnostic(
    "positive_support_missing",
    "Every nonempty extraction field requires positive grounded evidence.")

# Every diagnostic the guard can emit, in a fixed order. Retry classification derives its
# categories from this tuple rather than restating the sentences.
EVIDENCE_DIAGNOSTICS: tuple[EvidenceDiagnostic, ...] = (
    SOURCE_UNAVAILABLE, UNKNOWN_FIELD, QUOTE_NOT_VERBATIM, POSITIVE_QUOTE_MISSING,
    POSITIVE_VALUE_MISSING, LITERAL_LOCATION_MISSING, LITERAL_LINE_MISSING,
    POSITIVE_SUPPORT_MISSING,
)
# The model-visible header every intake evidence retry starts with.
EVIDENCE_RETRY_PREFIX = "Extraction violates its evidence contract:\n- "


def _present(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    return value is not None and value != []


def extraction_evidence_diagnostics(
    report: str | None, output: Mapping[str, Any]
) -> list[EvidenceDiagnostic]:
    """Every closed diagnostic for one extraction, deduplicated in first-seen order."""
    if report is None:
        return [SOURCE_UNAVAILABLE]
    problems: list[EvidenceDiagnostic] = []
    supported: set[str] = set()
    for evidence in output.get("evidence", []):
        field = evidence["field"]
        if field not in EXTRACTED_FIELDS:
            problems.append(UNKNOWN_FIELD)
            continue
        quote = evidence["quote"]
        positive = evidence["confidence"] > 0
        present = _present(output.get(field))
        # Optional zero-confidence evidence can express uncertainty about an unset field.
        # Empty uncertainty quotes claim no supporting span; nonempty quotes stay literal.
        literal = bool(quote.strip()) and quote in report
        if quote and not literal:
            problems.append(QUOTE_NOT_VERBATIM)
        if positive and not literal:
            problems.append(POSITIVE_QUOTE_MISSING)
        if positive and not present:
            problems.append(POSITIVE_VALUE_MISSING)
        if positive and literal and present:
            value = output[field]
            if field in _LITERAL_STRINGS and value not in quote:
                problems.append(LITERAL_LOCATION_MISSING)
            elif field in _LINES and str(value) not in {
                token.lstrip("0") or "0" for token in re.findall(r"\bL?([0-9]+)\b", quote)
            }:
                problems.append(LITERAL_LINE_MISSING)
            else:
                supported.add(field)
    if any(_present(output.get(field)) and field not in supported for field in EXTRACTED_FIELDS):
        problems.append(POSITIVE_SUPPORT_MISSING)
    return list(dict.fromkeys(problems))


def extraction_evidence_violations(report: str | None, output: Mapping[str, Any]) -> list[str]:
    """The model-visible messages of :func:`extraction_evidence_diagnostics`."""
    return [problem.message for problem in extraction_evidence_diagnostics(report, output)]


def evidence_retry_message(problems: list[EvidenceDiagnostic]) -> str:
    """The retry text for a nonempty diagnostic list: closed sentences only."""
    return EVIDENCE_RETRY_PREFIX + "\n- ".join(problem.message for problem in problems)
