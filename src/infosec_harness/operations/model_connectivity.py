"""Explicit, single-request model connectivity; never agent qualification or broker admission."""

from __future__ import annotations

import asyncio
import hashlib
import math
import re
import time
from datetime import UTC, datetime
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict
from pydantic_ai import Agent
from pydantic_ai.usage import UsageLimits

from infosec_harness.agents import models
from infosec_harness.agents.registry import load_spec
from infosec_harness.api.evidence_io import COMMIT, read_bytes
from infosec_harness.api.model_observation import ModelConnectionReceipt
from infosec_harness.settings import get_settings


class Ready(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ready: Literal[True]


def profile_identity() -> dict:
    """Public identity of the selected verdict profile; no endpoint or credential references."""
    settings = get_settings()
    source = settings.git_commit_sha
    identity = {
        "mode": settings.model_mode,
        "source_commit": (source if isinstance(source, str) and COMMIT.fullmatch(source) else None),
    }
    if settings.model_mode == "stub":
        return {**identity, "transport": "stub", "model": "stub"}
    if not COMMIT.fullmatch(settings.git_commit_sha):
        raise ValueError("source identity unavailable")
    content = read_bytes(settings.models_config)
    config = models.ModelsConfig.model_validate(yaml.safe_load(content))
    # The runtime resolver caches configurations. A changed file must never be recorded
    # as the identity of a client constructed from the old cached configuration.
    if config != models.load_models_config():
        raise ValueError("cached profile differs")
    tier = load_spec("verdict").model
    backend_name = config.selected_backend()
    label = f"{backend_name}:{config.model_id(tier, backend_name)}"
    if not re.fullmatch(r"[a-zA-Z0-9._:/-]{1,200}", label):
        raise ValueError("model identity unavailable")
    return {
        **identity,
        "model": label,
        "transport": config.backends[backend_name].transport,
        "model_config_sha256": hashlib.sha256(content).hexdigest(),
        "broker_config_sha256": (
            hashlib.sha256(read_bytes(settings.broker_config)).hexdigest()
            if settings.broker_config
            else None
        ),
    }


async def check_model(*, timeout: float = 90) -> dict:
    """Make at most one actual request, with configured adaptations and a closed result."""
    started = time.monotonic()
    result = {"status": "not_checked", "detail": "Model profile unavailable.", "requests": 0}

    def finish(status, detail):
        return {
            **result,
            "status": status,
            "detail": detail,
            "elapsed_s": round(time.monotonic() - started, 3),
        }

    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not math.isfinite(timeout)
        or not 1 <= timeout <= 300
    ):
        return finish("failed", "Timeout must be between 1 and 300 seconds.")
    try:
        before = profile_identity()
        result.update(before)
        if before["mode"] != "live":
            return finish("not_checked", "Stub mode does not establish model connectivity.")
        if before["transport"] != "direct":
            return finish(
                "not_checked", "Brokered connectivity requires separately admitted qualification."
            )
        if before["broker_config_sha256"] is not None:
            return finish(
                "not_checked", "Mixed transport configuration cannot establish a profile receipt."
            )
        spec = load_spec("verdict")
        requested = {"max_tokens": 256, "temperature": 0, "timeout": timeout}
        resolved = models.resolve_config(
            "verdict", spec.model, model_settings=requested, durable=True
        )
        if resolved.backend_kind != "openai_compatible":
            return finish(
                "not_checked", "This provider cannot establish the single-request transport bound."
            )
        if resolved.transport_retries != 0:
            return finish(
                "not_checked", "Single-request connectivity requires zero transport retries."
            )
        if resolved.resolved_model != before["model"] or profile_identity() != before:
            return finish("not_checked", "Model profile changed before the request.")
        model = models.resolve("verdict", spec.model, durable=True)
    except Exception:
        return finish("not_checked", "Model profile unavailable.")
    try:
        agent = Agent(model, output_type=Ready, retries=0)
        async with asyncio.timeout(timeout):
            response = await agent.run(
                "Return ready=true as the structured result. This is an inference connectivity check.",
                model_settings=resolved.effective_settings,
                usage_limits=UsageLimits(request_limit=1),
            )
        result["requests"] = response.usage.requests
        if (
            not isinstance(response.output, Ready)
            or response.output.ready is not True
            or type(result["requests"]) is not int
            or result["requests"] != 1
        ):
            return finish(
                "failed", "Model did not return the required single-request structured result."
            )
        if profile_identity() != before:
            return finish("failed", "Model profile changed during the request.")
    except TimeoutError:
        # Provider errors/timeouts may occur after admission; unknown usage is not zero.
        result["requests"] = None
        return finish("failed", "Model request exceeded the connectivity deadline.")
    except Exception:
        if result["requests"] == 0:
            result["requests"] = None
        return finish("failed", "Model request or structured result validation failed.")
    receipt: ModelConnectionReceipt = {
        "version": 1,
        "checked_at": datetime.now(UTC).isoformat(),
        "source_commit": before["source_commit"],
        "model_config_sha256": before["model_config_sha256"],
        "broker_config_sha256": before["broker_config_sha256"],
        "mode": "live",
        "transport": "direct",
        "status": "passed",
    }
    result["receipt"] = receipt
    return finish("passed", "One actual structured-output request passed for this exact profile.")


def report(timeout: float = 90) -> tuple[dict, int]:
    """`harness model-connectivity --model`: the result, and exit status 1 only on failure."""
    result = asyncio.run(check_model(timeout=timeout))
    return result, int(result["status"] == "failed")
