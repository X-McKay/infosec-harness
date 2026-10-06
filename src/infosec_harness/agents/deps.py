"""The investigator's run dependencies, shared by the agent, its tools and the worker guard.

Kept apart from ``investigator`` so the tools can be typed by it without an import cycle.
"""

from pydantic import BaseModel

from infosec_harness.contracts import InvestigationRequest, WorkerIdentity
from infosec_harness.sandbox import Sandbox


class InvestigationDeps(BaseModel):
    """Serialized into every native model/tool activity; the worker checks its identity."""

    run_id: str
    sandbox: Sandbox
    source_digest: str
    snapshot_path: str
    request: InvestigationRequest
    worker_identity: WorkerIdentity | None = None
