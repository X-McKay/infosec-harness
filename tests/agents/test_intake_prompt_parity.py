"""The intake prompt contract is shared by evals and production callers."""

from infosec_harness.agents.intake_claims import report_source_lines
from infosec_harness.agents.render import render_intake_prompt, render_prompt
from infosec_harness.domain.models import Finding


def test_atomic_prompt_changes_only_top_level_report_and_keeps_known_fields():
    report = "Caller input enters a shell command.\r\n"
    known = Finding(fingerprint="synthetic", title="Synthetic report",
                    repo_url="https://example.invalid/repo", revision="test",
                    source_kind="free_text", description=report, cwe="CWE-78")
    payload = {"report": report, "known": known}
    assert render_intake_prompt("Extract fields.", payload) == render_prompt(
        "Extract fields.", {"report_source_lines": report_source_lines(report), "known": known}
    )
    assert payload == {"report": report, "known": known}


def test_source_record_prompt_preserves_unicode_and_line_terminators():
    report = "λ\r\n雪\n"
    prompt = render_intake_prompt("Extract fields.", {"report": report})
    assert prompt == render_prompt("Extract fields.", {"report_source_lines": report_source_lines(report)})
