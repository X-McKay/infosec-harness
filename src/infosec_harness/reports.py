"""Deterministic, redacted report and cost renderers from the SQLite record."""

from __future__ import annotations

import json

from .domain import RunSummary


def report_json(summary: RunSummary) -> str:
    return json.dumps(summary.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"


def report_markdown(summary: RunSummary) -> str:
    provenance = summary.model_provenance[0] if summary.model_provenance else {}
    model_label = provenance.get("model_version", "no model result")
    replay_label = provenance.get("replay_fixture_id") or "not replayed"
    lines = [
        f"# SARIF triage report: {summary.run_id}",
        "",
        f"- Terminal state: `{summary.terminal_state.value}`",
        f"- Revision: `{summary.revision}`",
        f"- Authorization: `{summary.authorization_hash}`",
        f"- Dependency closure: `{summary.dependency_closure_hash}`",
        f"- Model provenance: `{summary.backend}` / `{model_label}` / fixture `{replay_label}`",
        f"- Cost: `${summary.estimated_cost_usd:.6f}` of `${summary.reserved_cost_usd:.6f}` reserved; input/output tokens: {summary.usage.input_tokens}/{summary.usage.output_tokens}",
        f"- Safety: no-exec={summary.safety_summary['no_exec']}; networked worker admitted={summary.safety_summary['networked_worker_admitted']}",
        "",
        "## Findings",
        "",
    ]
    for index, finding in enumerate(summary.findings):
        disposition = summary.dispositions[index] if index < len(summary.dispositions) else None
        lines.append(f"### {finding.finding_id}: {finding.rule_id}")
        lines.append("")
        lines.append(f"- Imported scanner: `{finding.scanner['name']}` {finding.scanner.get('version')}")
        lines.append("- Location: " + ", ".join(f"`{loc.path}:{loc.start_line}-{loc.end_line}`" for loc in finding.locations))
        if disposition:
            lines.append(f"- Typed disposition: `{disposition.disposition.value}` (human review required: `{disposition.human_review_required}`)")
            lines.append(f"- Supporting evidence: {len(disposition.supporting)}; counter-evidence: {len(disposition.counter)}")
            lines.append(f"- Proof gaps: {'; '.join(disposition.proof_gaps) or 'none recorded'}")
        else:
            lines.append("- No disposition produced; see terminal error classification.")
        lines.append("")
    lines.extend(["## Coverage and safety", "", f"- Deferred surfaces: {', '.join(summary.deferred_surfaces)}", f"- Policy decisions: {len(summary.policy_decisions)}", f"- Error class: `{summary.error_class or 'none'}`", ""])
    return "\n".join(lines)


def cost_json(summary: RunSummary) -> str:
    return json.dumps(
        {
            "run_id": summary.run_id,
            "terminal_state": summary.terminal_state.value,
            "usage": summary.usage.model_dump(),
            "estimated_cost_usd": summary.estimated_cost_usd,
            "reserved_cost_usd": summary.reserved_cost_usd,
            "reconciliation": "replay usage is authoritative for this local fixture",
        },
        indent=2,
        sort_keys=True,
    ) + "\n"
