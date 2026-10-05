"""The single deps type shared by every agent.

Deps are serialized into Temporal activities (tool calls run on the worker), so they
are a Pydantic model. They never enter instructions, so they don't affect caching.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from infosec_harness.domain.models import VerdictFacts
from infosec_harness.inference.wire.protocol import ExecutorContract, ReservationBinding


class AgentDeps(BaseModel):
    broker_binding: ReservationBinding | None = Field(default=None, exclude_if=lambda v: v is None)
    broker_contract: ExecutorContract | None = Field(default=None, exclude_if=lambda v: v is None)
    repo_path: str
    """Snapshot root the read-only file tools are confined to."""
    report_text: str | None = None
    """Exact untrusted report supplied by the host, solely for extraction grounding.

    Only intake requires this field; its validation fails closed if the report is absent.
    It is not an instruction, repository path, or permission grant.
    """
    sandbox_image: str | None = None
    """Image the sandbox shell runs commands in (build agents only)."""
    facts: VerdictFacts | None = None
    """Deterministic facts for the verdict output validator."""
    source_files: int | None = None
    """Source files in the repository, from the stack fingerprint.

    Widens this run's budget for a large repository (see runtime.budgets.size_factor). None
    means unknown, and an unknown repository gets its declared ceiling unchanged rather than a
    guessed one.
    """
