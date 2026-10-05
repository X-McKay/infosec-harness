"""Whether this deployment can turn a model's token usage into dollars.

Recorded on every experiment and report, because a cost comparison across two models priced
differently is not a comparison at all -- a self-hosted model always "wins" on cost against a
billed one -- and after the fact there is no way to tell which kind of zero a zero was.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from infosec_harness.inference import models


class PricingStatus(StrEnum):
    PRICED = "priced"
    """A nonzero price exists, so a cost metric can move."""

    STUB = "stub"
    """No model was called at all (``HARNESS_MODEL_MODE=stub``); cost is definitionally 0."""

    UNKNOWN_MODEL = "unknown_model"
    """Neither genai-prices nor config/models.yaml knows this model id."""

    ZERO_PRICED = "zero_priced"
    """Prices are configured and are zero -- e.g. self-hosted vLLM with no per-token billing."""

    @property
    def can_move(self) -> bool:
        """True only when a cost metric derived from this model can be nonzero."""
        return self is PricingStatus.PRICED


_BY_SOURCE: dict[str, PricingStatus] = {
    "stub": PricingStatus.STUB,
    "genai-prices": PricingStatus.PRICED,
    "custom": PricingStatus.PRICED,
    "custom-zero": PricingStatus.ZERO_PRICED,
    "unknown": PricingStatus.UNKNOWN_MODEL,
}


def pricing_status(model_name: str) -> PricingStatus:
    """Classify ``model_name`` by the price source :func:`models.estimate_cost` would use.

    :func:`infosec_harness.inference.models.pricing_source` answers which table prices a model --
    the same lookup order the cost estimator follows -- so this cannot drift from what a run
    measures.
    """
    return _BY_SOURCE[models.pricing_source(model_name)]


def pricing_label(value: Any) -> PricingStatus | None:
    """Parse a recorded pricing label back into a status, ``None`` when unrecognized."""
    try:
        return PricingStatus(value)
    except ValueError:
        return None
