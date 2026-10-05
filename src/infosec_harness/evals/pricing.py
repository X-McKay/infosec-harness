"""Whether this deployment can turn a model's token usage into dollars.

Recorded on every experiment and report, because a cost comparison across two models priced
differently is not a comparison at all -- a self-hosted model always "wins" on cost against a
billed one -- and after the fact there is no way to tell which kind of zero a zero was.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any


class PricingStatus(StrEnum):
    PRICED = "priced"
    """A nonzero price exists, so a cost metric can move."""

    STUB = "stub"
    """No model was called at all (``HARNESS_MODEL_MODE=stub``); cost is definitionally 0."""

    UNKNOWN_MODEL = "unknown_model"
    """Neither genai-prices nor config/models.yaml knows this model id."""

    ZERO_PRICED = "zero_priced"
    """Prices are configured and are zero -- e.g. self-hosted vLLM with no per-token billing."""

    UNDETERMINED = "undetermined"
    """The pricing lookup itself failed; treat cost as unverified rather than live."""

    @property
    def can_move(self) -> bool:
        """True only when a cost metric derived from this model can be nonzero."""
        return self is PricingStatus.PRICED


class _ProbeUsage:
    """A usage record large enough that any real price table yields a nonzero cost."""

    input_tokens = 1_000_000
    output_tokens = 1_000_000
    cache_read_tokens = None
    cache_write_tokens = None


def pricing_status(model_name: str) -> PricingStatus:
    """Ask the deployment's own cost estimator whether ``model_name`` can be priced.

    Routed through :func:`infosec_harness.agents.models.estimate_cost` -- the function the eval
    loop uses -- so this cannot drift from what a run measured. A million tokens in and out is
    priced; if that comes back ``None`` or ``0.0``, no real run of the model could produce a
    nonzero cost either.
    """
    if model_name.startswith("stub:"):
        return PricingStatus.STUB
    try:
        from infosec_harness.agents.models import estimate_cost

        candidates = [model_name]
        # `resolved_model_name` records "<backend>:<model_id>"; price tables are keyed by
        # the bare model id, so try that too before declaring a model unpriced.
        if ":" in model_name:
            candidates.append(model_name.split(":", 1)[1])
        best = None
        for name in candidates:
            cost, _ = estimate_cost(name, _ProbeUsage())
            if cost:
                return PricingStatus.PRICED
            if cost == 0.0:
                best = PricingStatus.ZERO_PRICED
        return best or PricingStatus.UNKNOWN_MODEL
    except Exception:
        return PricingStatus.UNDETERMINED


def pricing_label(value: Any) -> PricingStatus | None:
    """Parse a recorded pricing label back into a status, ``None`` when unrecognized."""
    try:
        return PricingStatus(value)
    except ValueError:
        return None
