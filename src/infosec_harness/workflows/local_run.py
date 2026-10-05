"""In-process runs (no Temporal): test and development scaffolding, stub models only."""

from __future__ import annotations

from infosec_harness.domain.models import FindingInput, TriageRunOutput
from infosec_harness.persistence import store
from infosec_harness.settings import get_settings
from infosec_harness.workflows.submission import new_batch_id

LOCAL_MODE_REQUIRES_STUB = (
    "Real assessments require Temporal; local mode runs stub models only "
    "(set HARNESS_MODEL_MODE=stub)."
)


class LocalModeUnavailable(ValueError):
    """Local mode was asked to run real models."""


def require_local_mode() -> None:
    """The one check that a local (non-durable) run may proceed: it must use stub models."""
    if get_settings().model_mode != "stub":
        raise LocalModeUnavailable(LOCAL_MODE_REQUIRES_STUB)


async def run_local(findings: list[FindingInput], *, label: str = "", persist: bool = True,
                    sandbox: bool | None = None) -> tuple[str, list[TriageRunOutput]]:
    """Run the full pipeline in-process. Used by the CLI demo and tests.

    When ``sandbox`` is None, the gVisor sandbox is used only if its runtime is available;
    otherwise builds/probes are skipped so the pipeline still runs offline.
    """
    require_local_mode()
    from infosec_harness.graph.local import triage_batch_local
    from infosec_harness.sandbox import docker

    if sandbox is None:
        sandbox = await docker.docker_available() and await docker.runtime_available()
    batch_id = new_batch_id(label)
    outputs = await triage_batch_local(findings, sandbox=sandbox)
    if persist:
        await store.create_batch(batch_id, source_kind=_kind(findings), label=label,
                                 count=len(outputs))
        run_ids = {out.finding.fingerprint: await store.save_run_output(
            batch_id, out, population="demo") for out in outputs}
        await store.finish_batch(batch_id)
        if get_settings().ado_writeback_enabled:
            from infosec_harness.workflows.writeback import write_back
            await write_back(outputs, run_ids)
    return batch_id, outputs


def _kind(findings: list[FindingInput]) -> str:
    kinds = {f.source_kind.value for f in findings}
    return kinds.pop() if len(kinds) == 1 else "mixed"
