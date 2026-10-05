"""Component qualification as the running service can honestly report it: not checked.

Accepted agent evidence is committed under `evals/baselines/` and reviewed with the change that
produced it; it is not a runtime measurement and the service does not promote it to one. Until a
measured, reproducible component assessment exists, every component reports `not_checked`.
"""

from datetime import UTC, datetime

from infosec_harness.agents.registry import AGENT_BINDINGS
from infosec_harness.api.contracts import QualificationStatus, QualifiedComponent

_LIMITATIONS = [
    "Accepted agent eval results live in evals/baselines and are reviewed, not measured here.",
    "Fresh full-suite qualification is not established by this component view.",
    "Hosted and Kubernetes qualification require their own measured evidence.",
]


def qualification_status() -> QualificationStatus:
    return QualificationStatus(
        as_of=datetime.now(UTC).isoformat(),
        status="not_checked",
        detail="The service does not assess component qualification evidence.",
        components=[
            QualifiedComponent(
                agent=agent,
                scope="agent_semantics",
                status="not_checked",
                freshness="unavailable",
                reason="No measured component evidence is available to this service.",
            )
            for agent in AGENT_BINDINGS
        ],
        limitations=_LIMITATIONS,
    )
