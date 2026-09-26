"""Every retry layer is bounded, and their product is a number we have chosen.

Retries live at four layers (agent-playbook §6): pydantic-ai semantic correction, the
provider client's transport retries, Temporal activity retries, and the graph's own repair
loop. Leaving any of them unset does not mean "no retries" — Temporal's default activity
policy is *unlimited* attempts, which is how a deterministic failure came to retry forever
and hang a workflow instead of failing it.
"""

from __future__ import annotations

import yaml

from infosec_harness.agents.models import load_models_config
from infosec_harness.agents.registry import (
    ACTIVITY_MAX_ATTEMPTS,
    ACTIVITY_RETRY,
    MODEL_ACTIVITY,
    NON_RETRYABLE_ERRORS,
    TOOL_ACTIVITY,
    spec_path,
)
from infosec_harness.settings import get_settings

# The product of layers 1-3 for one durable agent run. Raising this is a decision, not an
# accident: it multiplies the worst-case provider spend for a single graph node.
MAX_PROVIDER_CALLS_PER_DURABLE_RUN = 30


def _agent_names() -> list[str]:
    return sorted(p.name for p in get_settings().agents_dir.iterdir()
                  if (p / "agent.yaml").exists())


def test_model_and_tool_activities_bound_their_attempts():
    """Unset means unlimited, so these must be set explicitly."""
    for name, config in [("model", MODEL_ACTIVITY), *(("tool:" + k, v) for k, v in TOOL_ACTIVITY.items())]:
        policy = config.get("retry_policy")
        assert policy is not None, f"{name} activity inherits Temporal's unlimited retries"
        assert policy.maximum_attempts == ACTIVITY_MAX_ATTEMPTS, name


def test_errors_that_cannot_succeed_on_retry_are_not_retried():
    assert ACTIVITY_RETRY.non_retryable_error_types == NON_RETRYABLE_ERRORS
    # A semantic failure pydantic-ai already exhausted its own retries on, and permanent
    # provider rejections, gain nothing from another attempt.
    for cls in ("UnexpectedModelBehavior", "AuthenticationError", "BadRequestError", "TypeError"):
        assert cls in NON_RETRYABLE_ERRORS


def test_provider_retries_are_minimized_under_temporal():
    """Temporal owns transient infrastructure retries; stacking transport retries on top
    multiplies the bound instead of adding to it."""
    cfg = load_models_config()
    for name, backend in cfg.backends.items():
        if backend.kind != "openai_compatible":
            continue
        assert backend.max_retries_under_temporal < backend.max_retries, name
        assert backend.max_retries_under_temporal >= 0, name


def test_the_combined_bound_is_the_number_we_chose():
    cfg = load_models_config()
    gateway = cfg.backends["gateway"]
    worst_output_retries = max(
        (yaml.safe_load(spec_path(n).read_text()).get("retries") or {}).get("output", 0)
        for n in _agent_names()
    )
    combined = ACTIVITY_MAX_ATTEMPTS * (gateway.max_retries_under_temporal + 1) * (worst_output_retries + 1)
    assert combined == MAX_PROVIDER_CALLS_PER_DURABLE_RUN, (
        f"the four retry layers now multiply out to {combined} provider calls for one "
        f"durable agent run, not {MAX_PROVIDER_CALLS_PER_DURABLE_RUN}. If that is intended, "
        f"update the constant; if not, one of the layers grew."
    )


def test_every_agent_bounds_its_own_semantic_retries():
    for name in _agent_names():
        retries = yaml.safe_load(spec_path(name).read_text()).get("retries")
        assert isinstance(retries, dict), f"{name}: retries must be explicit"
        assert 0 < retries.get("output", 0) <= 5, f"{name}: output retries unbounded or absent"
        assert 0 < retries.get("tools", 0) <= 5, f"{name}: tool retries unbounded or absent"
