"""Thin public runtime status route; evidence validation belongs to scoped projections.

Component qualification is not reported by the service: accepted agent evidence is committed
under `evals/baselines/` and reviewed with the change that produced it, which a running service
cannot measure. The runtime status reports only what this deployment can observe.
"""

import asyncio
import re
from datetime import UTC, datetime

from fastapi import APIRouter
from sqlalchemy.engine import make_url

from infosec_harness.api.broker_observation import broker_status
from infosec_harness.api.contracts import RuntimeStatus
from infosec_harness.api.evidence_io import COMMIT
from infosec_harness.api.model_observation import model_runtime
from infosec_harness.settings import get_settings

router = APIRouter(prefix="/api")
_LABEL = re.compile(r"^[a-zA-Z0-9._-]{1,64}$")


@router.get("/runtime-status", response_model=RuntimeStatus)
async def runtime_status() -> RuntimeStatus:
    settings = get_settings()
    broker = await broker_status()
    names, connectivity = await asyncio.to_thread(model_runtime)
    return RuntimeStatus(
        environment=settings.environment if _LABEL.fullmatch(settings.environment) else "unknown",
        model_mode=settings.model_mode,
        assessment_transport="brokered" if settings.broker_config else "direct",
        api_source_commit=settings.git_commit_sha
        if COMMIT.fullmatch(settings.git_commit_sha)
        else None,
        as_of=datetime.now(UTC).isoformat(),
        database_backend=make_url(settings.database_url).get_backend_name(),
        temporal_mode="tls" if settings.temporal_tls else "plaintext",
        broker=broker,
        model_names=names,
        model_connectivity=connectivity,
    )
