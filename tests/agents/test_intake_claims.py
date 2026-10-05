"""Typed intake claim protocol and exact source reconstruction."""

from __future__ import annotations

import json

import pytest

from infosec_harness.domain.models import ExtractedFinding
from infosec_harness.intake.claims import (
    SOURCE_INDEX_VERSION,
    WIRE_VERSION,
    AtomicFinding,
    ReferenceError,
    reconstruct,
    report_source_lines,
)
from infosec_harness.intake.evidence import extraction_evidence_violations


def reference(line: int, end: int | None = None) -> dict[str, str]:
    source = {"start_id": f"S{line:06d}"}
    if end is not None:
        source["end_id"] = f"S{end:06d}"
    return source


def claim(value, line: int, confidence: float = 0.7, end: int | None = None):
    return {"value": value, "source": reference(line, end), "confidence": confidence}


def test_protocol_versions_and_source_lines_preserve_original_characters():
    report = (
        "header\r\n"
        '\tpath = "C:\\\\tmp\\\\a.py"\n'
        "line 14 through 16 and symbol run(); CWE-89 SQL injection\r\n"
    )
    lines = report_source_lines(report)
    assert WIRE_VERSION == "intake-atomic-claims/v2"
    assert SOURCE_INDEX_VERSION == "python-splitlines-keepends-codepoints-v1"
    assert [item["id"] for item in lines] == ["S000001", "S000002", "S000003"]
    assert "".join(item["text"] for item in lines) == report
    assert lines[1]["text"] == '\tpath = "C:\\\\tmp\\\\a.py"\n'


def test_all_supported_fields_materialize_exact_slices_values_and_confidences():
    report = (
        "header\r\n"
        '\tpath = "C:\\\\tmp\\\\a.py"\n'
        "line 14 through 16 and symbol run(); CWE-89 SQL injection\r\n"
        "attacker controls input\n"
        "impact: data disclosure"
    )
    wire = AtomicFinding.model_validate_json(
        json.dumps(
            {
                "file_path": claim("C:\\\\tmp\\\\a.py", 2),
                "start_line": claim(14, 3),
                "end_line": claim(16, 3),
                "symbol": claim("run()", 3),
                "cwe": claim("CWE-89", 3),
                "vulnerability_class": claim("SQL injection", 3),
                "attack_preconditions": claim(["attacker controls input"], 4),
                "claimed_impact": claim("data disclosure", 5),
            }
        )
    )

    output = reconstruct(report, wire)

    assert isinstance(output, ExtractedFinding)
    assert output.file_path == "C:\\\\tmp\\\\a.py"
    assert (output.start_line, output.end_line) == (14, 16)
    assert output.symbol == "run()"
    assert (output.cwe, output.vulnerability_class) == ("CWE-89", "SQL injection")
    assert output.attack_preconditions == ["attacker controls input"]
    assert output.claimed_impact == "data disclosure"
    assert [item.confidence for item in output.evidence] == [0.7] * 8
    assert [item.quote for item in output.evidence] == [
        '\tpath = "C:\\\\tmp\\\\a.py"\n',
        "line 14 through 16 and symbol run(); CWE-89 SQL injection\r\n",
        "line 14 through 16 and symbol run(); CWE-89 SQL injection\r\n",
        "line 14 through 16 and symbol run(); CWE-89 SQL injection\r\n",
        "line 14 through 16 and symbol run(); CWE-89 SQL injection\r\n",
        "line 14 through 16 and symbol run(); CWE-89 SQL injection\r\n",
        "attacker controls input\n",
        "impact: data disclosure",
    ]
    assert extraction_evidence_violations(report, output.model_dump(mode="json")) == []


def test_null_claims_materialize_as_unsupported_without_evidence():
    output = reconstruct("No concrete mechanism is described.\n", AtomicFinding())
    assert output.file_path is None and output.cwe is None
    assert output.attack_preconditions == []
    assert output.evidence == []
    assert extraction_evidence_violations(
        "No concrete mechanism is described.\n", output.model_dump(mode="json")
    ) == []


@pytest.mark.parametrize(
    ("report", "claims", "rule"),
    [
        (None, {"file_path": claim("x.py", 1)}, "source_unavailable"),
        ("x.py\n", {"file_path": claim("x.py", 2)}, "unknown_source_id"),
        (
            "first.py\nsecond.py\n",
            {"file_path": claim("first.py", 2, end=1)},
            "reversed_source_range",
        ),
    ],
)
def test_unavailable_unknown_and_reversed_references_fail_closed(report, claims, rule):
    with pytest.raises(ReferenceError) as raised:
        reconstruct(report, AtomicFinding.model_validate(claims))
    assert raised.value.rule == rule
    assert "x.py" not in str(raised.value)
    assert "first.py" not in str(raised.value)


def test_existing_guard_remains_authoritative_for_literal_locations_and_line_numbers():
    report = "safe.py at line 9\n"
    wire = AtomicFinding.model_validate(
        {"file_path": claim("invented.py", 1), "start_line": claim(10, 1)}
    )
    output = reconstruct(report, wire)
    problems = extraction_evidence_violations(report, output.model_dump(mode="json"))
    assert any("literal location" in problem for problem in problems)
    assert any("literal line number" in problem for problem in problems)


def test_claim_values_and_confidence_are_strict_and_empty_claims_are_rejected():
    for bad in (0, -0.1, 1.1, True, "0.5"):
        with pytest.raises(ValueError):
            AtomicFinding.model_validate({"file_path": claim("x.py", 1, confidence=bad)})
    with pytest.raises(ValueError):
        AtomicFinding.model_validate({"file_path": claim(" \t", 1)})
    with pytest.raises(ValueError):
        AtomicFinding.model_validate({"start_line": claim(True, 1)})
