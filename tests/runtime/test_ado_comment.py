"""The ADO write-back comment is HTML built from untrusted text, so every value is escaped.

The rationale is model-authored, evidence paths and the fingerprint derive from a reported
finding, and ADO renders the comment field as HTML. An unescaped value is stored XSS in the
tracker of whoever reads the triage result.
"""

import pytest

from infosec_harness.domain.models import (
    CodeRef,
    Finding,
    FindingSourceKind,
    PriorityBand,
    TriageResult,
    TriageRunOutput,
    Verdict,
    VerdictLabel,
)
from infosec_harness.integrations import ado

_SCRIPT = "<script>alert(1)</script>"
_ATTR_BREAK = '"><img src=x onerror=alert(1)>'


def _output(*, fingerprint: str = "fp", rationale: str = "oracle fired",
            evidence_path: str = "app.py") -> TriageRunOutput:
    finding = Finding(fingerprint=fingerprint, title=f"t {_SCRIPT} {_ATTR_BREAK}",
                      repo_url="https://example.invalid/r", revision="HEAD",
                      source_kind=FindingSourceKind.ado, ado_work_item_id=7)
    verdict = Verdict(label=VerdictLabel.potentially_exploitable, confidence=0.9,
                      rationale=rationale,
                      evidence=[CodeRef(file_path=evidence_path, start_line=3, end_line=3)])
    return TriageRunOutput(finding=finding,
                           result=TriageResult(fingerprint=fingerprint, verdict=verdict,
                                               priority_score=0.7, priority=PriorityBand.p1),
                           prepared_status="ready")


def _tags(text: str) -> list[str]:
    """Every tag name the comment opens, so an injected element cannot hide in the noise."""
    import re

    return sorted(set(re.findall(r"<([a-zA-Z]+)", text)))


def test_untrusted_rationale_and_evidence_are_escaped():
    text = ado.render_comment(
        _output(rationale=f"{_SCRIPT} then {_ATTR_BREAK}", evidence_path=f"{_ATTR_BREAK}.py"),
        "https://ui.example.invalid",
    )
    assert "<script" not in text and "<img" not in text and "onerror=alert(1)>" not in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;" in text
    # Only the comment's own markup remains.
    assert _tags(text) == ["a", "b", "br", "i", "sub"]


def test_fingerprint_cannot_break_out_of_the_link_attribute():
    text = ado.render_comment(_output(fingerprint=f'x{_ATTR_BREAK}/../y'), "https://ui.example.invalid")
    assert "<img" not in text and '"><' not in text
    assert ('href="https://ui.example.invalid/findings/'
            'x%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E%2F..%2Fy"') in text
    assert _tags(text) == ["a", "b", "br", "i", "sub"]


@pytest.mark.parametrize("base", ["javascript:alert(1)", "data:text/html,x", "//evil.example", ""])
def test_a_non_http_ui_base_produces_no_link(base):
    text = ado.render_comment(_output(), base)
    assert "<a " not in text and "href" not in text
    assert "recommended before action" in text


def test_a_plain_comment_still_reads_as_before():
    text = ado.render_comment(_output(), "http://ui/")
    assert "InfoSec triage: potentially exploitable" in text
    assert '<a href="http://ui/findings/fp">View in InfoSec Harness</a>' in text
    assert "<i>oracle fired</i>" in text and "Evidence: app.py:3" in text
