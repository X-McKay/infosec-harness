"""Intake adapters (F0): external finding sources -> canonical Finding.

Deterministic mapping of structured fields (D1). Prose fields are filled by the IntakeAgent
in the workflow and folded in with :func:`merge_extraction`; location resolution is
:func:`resolve_location`.
"""

from __future__ import annotations

from pathlib import Path

from infosec_harness.domain.models import (
    CodeLocation,
    ExtractedFinding,
    Finding,
    FindingInput,
)


def to_finding(inp: FindingInput) -> Finding:
    location = None
    if inp.file_path:
        location = CodeLocation(
            file_path=inp.file_path, start_line=inp.start_line,
            end_line=inp.end_line, symbol=inp.symbol,
        )
    return Finding(
        fingerprint=Finding.compute_fingerprint(inp),
        external_id=inp.external_id,
        title=inp.title,
        description=inp.description,
        repo_url=inp.repo_url,
        revision=inp.revision,
        location=location,
        cwe=inp.cwe,
        severity=inp.severity,
        source_kind=inp.source_kind,
        source_tool=inp.source_tool,
        ado_work_item_id=inp.ado_work_item_id,
    )


def needs_extraction(finding: Finding) -> bool:
    """True when structured fields left gaps a prose-reading agent might fill."""
    return finding.location is None or finding.cwe is None


def merge_extraction(finding: Finding, extracted: ExtractedFinding) -> Finding:
    """Fold agent-extracted fields into a finding, without overwriting structured values."""
    data = finding.model_dump()
    if finding.location is None and extracted.file_path:
        data["location"] = CodeLocation(
            file_path=extracted.file_path, start_line=extracted.start_line,
            end_line=extracted.end_line, symbol=extracted.symbol,
        ).model_dump()
    data["cwe"] = finding.cwe or extracted.cwe
    data["vulnerability_class"] = finding.vulnerability_class or extracted.vulnerability_class
    data["attack_preconditions"] = finding.attack_preconditions or extracted.attack_preconditions
    data["claimed_impact"] = finding.claimed_impact or extracted.claimed_impact
    return Finding.model_validate(data)


def resolve_location(finding: Finding, repo_path: str) -> Finding | None:
    """Return the finding if its file exists at the revision, else None (-> needs_info)."""
    if finding.location is None:
        return None
    if (Path(repo_path) / finding.location.file_path).exists():
        return finding
    return None
