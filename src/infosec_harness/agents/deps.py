"""The single deps type shared by every agent.

Deps are serialized into Temporal activities (tool calls run on the worker), so they
are a Pydantic model. They never enter instructions, so they don't affect caching.
"""

from __future__ import annotations

from pydantic import BaseModel

from infosec_harness.domain.models import VerdictFacts


class AgentDeps(BaseModel):
    repo_path: str
    """Snapshot root the read-only file tools are confined to."""
    sandbox_image: str | None = None
    """Image the sandbox shell runs commands in (build agents only)."""
    facts: VerdictFacts | None = None
    """Deterministic facts for the verdict output validator."""
