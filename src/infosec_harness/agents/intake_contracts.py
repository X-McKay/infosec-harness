"""The intake wire protocol: its execution identity and prompt payload construction."""

from __future__ import annotations

from typing import Any

from pydantic_ai.messages import UserContent

from infosec_harness.agents.intake_claims import WIRE_VERSION, report_source_lines
from infosec_harness.agents.render import render_prompt


def render_intake_prompt(
    task: str,
    payload: dict[str, Any],
    *,
    protocol: str | None = WIRE_VERSION,
) -> list[UserContent]:
    """Render the source-indexed intake payload.

    ``report`` is replaced by ``report_source_lines`` so the model cites stable source IDs and
    the host reconstructs the verbatim quote. Only the current atomic-claims protocol exists;
    any other protocol is refused rather than rendered under the wrong contract.
    """
    if protocol != WIRE_VERSION:
        raise ValueError(f"Unknown intake prompt protocol {protocol!r}; only {WIRE_VERSION} exists")
    atomic_payload = dict(payload)
    report = atomic_payload.pop("report", None)
    atomic_payload["report_source_lines"] = (
        report_source_lines(report) if isinstance(report, str) else report
    )
    return render_prompt(task, atomic_payload)
