"""Azure DevOps intake (structured fields + prose) and comment-only write-back (D1, D13).

Write-back posts exactly one comment per work item with the verdict, priority, confidence, a
short evidence summary, and a UI link; re-runs edit that same comment. It never changes
state, fields, or tags. Behind a feature flag; uses a PAT scoped to Work Items (R&W).
"""

from __future__ import annotations

import base64
from html import escape
from urllib.parse import quote, urlsplit

import httpx

from infosec_harness.domain.models import FindingInput, Severity, TriageRunOutput
from infosec_harness.settings import get_settings

_API = "7.1"


def _auth_header(pat: str) -> dict[str, str]:
    token = base64.b64encode(f":{pat}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def work_item_to_finding(item: dict, field_map: dict[str, str]) -> FindingInput:
    """Map an ADO work item (fields + description) to a FindingInput."""
    fields = item.get("fields", {})

    def f(key: str):
        return fields.get(field_map.get(key, ""))

    description = fields.get("System.Description", "") or ""
    sev = (f("severity") or "").split(" - ")[0].strip().lower()
    severity = Severity.__members__.get(sev, Severity.unknown) if sev else Severity.unknown
    return FindingInput(
        external_id=str(item.get("id")),
        title=fields.get("System.Title", f"ADO work item {item.get('id')}"),
        description=description,
        repo_url=f("repo_url") or fields.get("Custom.Repository", "") or "",
        revision=f("revision") or "HEAD",
        file_path=f("file_path"),
        start_line=int(f("start_line")) if f("start_line") else None,
        cwe=f("cwe"),
        severity=severity,
        source_tool=fields.get("System.CreatedBy", {}).get("displayName") if isinstance(
            fields.get("System.CreatedBy"), dict) else None,
        source_kind="ado",
        ado_work_item_id=int(item["id"]),
    )


async def fetch_work_items(ids: list[int]) -> list[dict]:
    s = get_settings()
    url = f"{s.ado_org_url}/{s.ado_project}/_apis/wit/workitems"
    params = {"ids": ",".join(map(str, ids)), "$expand": "fields", "api-version": _API}
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(url, params=params, headers=_auth_header(s.ado_pat))
        resp.raise_for_status()
        return resp.json().get("value", [])


def _finding_link(ui_base_url: str, fingerprint: str) -> str | None:
    """The UI link, or None when the configured base is not an http(s) URL.

    The base is operator configuration; the fingerprint is path-quoted so no finding-derived
    byte can leave its path segment. The result still goes through ``escape`` at the attribute.
    """
    base = ui_base_url.rstrip("/")
    parts = urlsplit(base)
    if parts.scheme.lower() not in ("http", "https") or not parts.netloc:
        return None
    return f"{base}/findings/{quote(fingerprint, safe='')}"


def render_comment(out: TriageRunOutput, ui_base_url: str) -> str:
    """The comment HTML. Every interpolated value is escaped: finding and verdict text is
    untrusted (reporter- and model-authored) and ADO renders this field as HTML."""
    v = out.result.verdict
    emoji = {"potentially_exploitable": "🔴", "likely_not_exploitable": "🟢",
             "inconclusive": "🟡"}.get(v.label.value, "")
    label = escape(v.label.value.replace("_", " "))
    lines = [
        f"<b>{emoji} InfoSec triage: {label}</b>",
        f"Priority <b>{escape(out.result.priority.value)}</b> · confidence {v.confidence:.0%}"
        + (f" · env {escape(out.result.environment_scope)}"
           if out.result.environment_scope != "none" else ""),
        f"<i>{escape(v.rationale)}</i>",
    ]
    if v.evidence:
        ev = "; ".join(f"{e.file_path}:{e.start_line}" for e in v.evidence[:3])
        lines.append(f"Evidence: {escape(ev)}")
    link = _finding_link(ui_base_url, out.finding.fingerprint)
    if link is not None:
        lines.append(f'<a href="{escape(link, quote=True)}">View in InfoSec Harness</a>')
    lines.append("<sub>Automated triage — a human review is recommended before action.</sub>")
    return "<br>".join(lines)


async def post_or_update_comment(work_item_id: int, text: str, comment_id: int | None) -> int:
    """Create or edit the harness comment; returns the comment id."""
    s = get_settings()
    base = f"{s.ado_org_url}/{s.ado_project}/_apis/wit/workItems/{work_item_id}/comments"
    headers = {**_auth_header(s.ado_pat), "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=30) as client:
        if comment_id is None:
            resp = await client.post(f"{base}?api-version={_API}-preview.4",
                                     json={"text": text}, headers=headers)
        else:
            resp = await client.patch(f"{base}/{comment_id}?api-version={_API}-preview.4",
                                      json={"text": text}, headers=headers)
        resp.raise_for_status()
        return resp.json()["id"]
