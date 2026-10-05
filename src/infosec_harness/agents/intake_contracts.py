"""The intake prompt payload, shared by the graph and the evals."""

from __future__ import annotations

from typing import Any

from pydantic_ai.messages import UserContent

from infosec_harness.agents.intake_claims import report_source_lines
from infosec_harness.agents.render import render_prompt


def render_intake_prompt(task: str, payload: dict[str, Any]) -> list[UserContent]:
    """Render the source-indexed intake payload (the atomic-claims protocol, the only one).

    ``report`` is replaced by ``report_source_lines`` so the model cites stable source IDs and
    the host reconstructs the verbatim quote.
    """
    atomic_payload = dict(payload)
    report = atomic_payload.pop("report", None)
    atomic_payload["report_source_lines"] = (
        report_source_lines(report) if isinstance(report, str) else report
    )
    return render_prompt(task, atomic_payload)
