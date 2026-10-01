"""Literal source grounding and extraction consistency, not a weakness classifier.

Report text remains untrusted. These checks cannot prove the chosen CWE is semantically
correct and never guess a label, rewrite output, or treat a source directive as authority.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

INTAKE_EVIDENCE_POLICY_VERSION = "intake-evidence/v1"
EXTRACTED_FIELDS = frozenset({
    "file_path", "start_line", "end_line", "symbol", "cwe", "vulnerability_class",
    "attack_preconditions", "claimed_impact",
})
_LITERAL_STRINGS = frozenset({"file_path", "symbol"})
_LINES = frozenset({"start_line", "end_line"})


def _present(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    return value is not None and value != []


def extraction_evidence_violations(report: str | None, output: Mapping[str, Any]) -> list[str]:
    """Return closed diagnostics; no source/model strings enter retry messages."""
    if report is None:
        return ["Exact source report is unavailable; extraction cannot be validated."]
    problems: list[str] = []
    supported: set[str] = set()
    for evidence in output.get("evidence", []):
        field = evidence["field"]
        if field not in EXTRACTED_FIELDS:
            problems.append("Evidence names an unknown extraction field.")
            continue
        quote = evidence["quote"]
        positive = evidence["confidence"] > 0
        present = _present(output.get(field))
        # Optional zero-confidence evidence can express uncertainty about an unset field.
        # Empty uncertainty quotes claim no supporting span; nonempty quotes stay literal.
        literal = bool(quote.strip()) and quote in report
        if quote and not literal:
            problems.append("An evidence quote is not a nonempty verbatim report span.")
        if positive and not literal:
            problems.append("Positive evidence requires a nonempty verbatim report span.")
        if positive and not present:
            problems.append("Positive evidence cannot support an unset extraction field.")
        if positive and literal and present:
            value = output[field]
            if field in _LITERAL_STRINGS and value not in quote:
                problems.append("A literal location value is absent from its evidence quote.")
            elif field in _LINES and str(value) not in {
                token.lstrip("0") or "0" for token in re.findall(r"\bL?([0-9]+)\b", quote)
            }:
                problems.append("A literal line number is absent from its evidence quote.")
            else:
                supported.add(field)
    if any(_present(output.get(field)) and field not in supported for field in EXTRACTED_FIELDS):
        problems.append("Every nonempty extraction field requires positive grounded evidence.")
    return list(dict.fromkeys(problems))
