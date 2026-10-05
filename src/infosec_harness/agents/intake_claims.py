"""Typed atomic intake claims and exact source-slice materialization.

This module defines an internal model-facing wire representation. It does not classify
weaknesses or accept/reject a completed extraction; callers must still apply the existing
intake evidence validator to the returned :class:`ExtractedFinding`.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    model_validator,
)

from infosec_harness.domain.models import ExtractedFinding

WIRE_VERSION = "intake-atomic-claims/v2"
SOURCE_INDEX_VERSION = "python-splitlines-keepends-codepoints-v1"


def _numeric_confidence(value: object) -> object:
    """Accept JSON numbers, not booleans or numeric strings."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("confidence must be a JSON numeric value")
    return value


Confidence = Annotated[float, Field(gt=0, le=1), BeforeValidator(_numeric_confidence)]


# Reference to a report line or inclusive contiguous line range.
class SourceReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    start_id: StrictStr
    end_id: StrictStr | None = None


# One supported field value, its exact source reference, and confidence.
class Claim[T](BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: T
    source: SourceReference
    confidence: Confidence


# Internal wire shape. A null field has no claim, reference, or confidence.
class AtomicFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file_path: Claim[StrictStr] | None = None
    start_line: Claim[StrictInt] | None = None
    end_line: Claim[StrictInt] | None = None
    symbol: Claim[StrictStr] | None = None
    cwe: Claim[StrictStr] | None = None
    vulnerability_class: Claim[StrictStr] | None = None
    attack_preconditions: Claim[list[StrictStr]] | None = None
    claimed_impact: Claim[StrictStr] | None = None

    @model_validator(mode="after")
    def reject_empty_claims(self) -> AtomicFinding:
        for name in type(self).model_fields:
            claim = getattr(self, name)
            if claim is None:
                continue
            value = claim.value
            if (isinstance(value, str) and not value.strip()) or value == []:
                raise ValueError("A supported claim must have a nonempty value")
        return self


ReferenceRule = Literal["source_unavailable", "unknown_source_id", "reversed_source_range"]


class ReferenceError(ValueError):
    """Closed source-index failure that does not echo report text or model-provided IDs."""

    def __init__(self, rule: ReferenceRule, *, field: str | None = None,
                 failures: tuple[tuple[str, ReferenceRule], ...] = ()) -> None:
        self.rule = rule
        # Only authored claim names may reach model repair feedback. Never retain or
        # echo source IDs, report fragments or model-provided values in diagnostics.
        self.field = field if type(field) is str and field in AtomicFinding.model_fields else None
        self.failures = tuple((name, failed) for name, failed in failures
                              if type(name) is str and name in AtomicFinding.model_fields)
        super().__init__(rule)


def _report(report_text: str | None) -> str:
    if report_text is None:
        raise ReferenceError("source_unavailable")
    return report_text


def _source_index(report_text: str) -> dict[str, tuple[int, int]]:
    """Index original Python string codepoints using ``splitlines(keepends=True)``."""
    result: dict[str, tuple[int, int]] = {}
    offset = 0
    for number, line in enumerate(report_text.splitlines(keepends=True), start=1):
        end = offset + len(line)
        result[f"S{number:06d}"] = (offset, end)
        offset = end
    return result


def report_source_lines(report_text: str | None) -> list[dict[str, str]]:
    """Return the original lines and stable IDs without trimming or newline conversion."""
    text = _report(report_text)
    return [
        {"id": source_id, "text": text[start:end]}
        for source_id, (start, end) in _source_index(text).items()
    ]


def _resolve(
    report_text: str, claims: AtomicFinding
) -> tuple[list[tuple[str, Claim, int, int]], tuple[tuple[str, ReferenceRule], ...]]:
    """Resolve every claim's reference to a codepoint slice, collecting closed failures."""
    index = _source_index(report_text)
    resolved: list[tuple[str, Claim, int, int]] = []
    errors: list[tuple[str, ReferenceRule]] = []
    for field_name in AtomicFinding.model_fields:
        claim = getattr(claims, field_name)
        if claim is None:
            continue
        reference = claim.source
        end_id = reference.start_id if reference.end_id is None else reference.end_id
        if reference.start_id not in index or end_id not in index:
            errors.append((field_name, "unknown_source_id"))
            continue
        start, _ = index[reference.start_id]
        end_start, end = index[end_id]
        if end_start < start:
            errors.append((field_name, "reversed_source_range"))
            continue
        resolved.append((field_name, claim, start, end))
    return resolved, tuple(errors)


def reconstruct(report_text: str | None, claims: AtomicFinding) -> ExtractedFinding:
    """Rebuild the unchanged public output type and exact verbatim evidence slices.

    This function reconstructs values only. It intentionally does not apply policy or
    normalize values; the existing whole-output guard remains the acceptance decision. Every
    reference failure is carried on the raised :class:`ReferenceError` (the first is its rule).
    """
    text = _report(report_text)
    resolved, errors = _resolve(text, claims)
    if errors:
        field, rule = errors[0]
        raise ReferenceError(rule, field=field, failures=errors)

    data: dict[str, object] = {}
    evidence: list[dict[str, object]] = []
    for field_name, claim, start, end in resolved:
        data[field_name] = claim.value
        evidence.append(
            {
                "field": field_name,
                "quote": text[start:end],
                "confidence": claim.confidence,
            }
        )

    # ExtractedFinding's public contract uses [] for an unspecified precondition list.
    data.setdefault("attack_preconditions", [])
    data["evidence"] = evidence
    return ExtractedFinding.model_validate(data)
