"""Tracker write-back: one Azure DevOps comment per assessed work item (D13).

The HTTP call is made outside any database session: a slow or failing tracker must not hold a
connection or a row lock. The sync row is read, the comment posted, and the row upserted in a
second short transaction.
"""

from __future__ import annotations

from infosec_harness.domain.models import TriageRunOutput
from infosec_harness.persistence import store
from infosec_harness.settings import get_settings


async def write_back(outputs: list[TriageRunOutput], run_ids: dict[str, str]) -> None:
    """Post or update each output's comment; skipped when the rendered text is unchanged."""
    from infosec_harness.integrations import ado

    settings = get_settings()
    for out in outputs:
        work_item = out.finding.ado_work_item_id
        if work_item is None:
            continue
        text = ado.render_comment(out, settings.ui_base_url)
        digest = store.payload_hash(text)
        previous = await store.ado_sync(work_item)
        if previous is not None and previous[1] == digest:
            continue  # nothing changed since the last write-back
        comment_id = await ado.post_or_update_comment(
            work_item, text, previous[0] if previous is not None else None)
        await store.record_ado_sync(run_ids[out.finding.fingerprint], work_item, comment_id, digest)
