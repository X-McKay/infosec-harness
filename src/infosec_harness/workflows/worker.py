"""The trusted worker: its content identity, the activity identity guard and its setup."""

import hashlib
import json
import logging
from collections.abc import Callable
from functools import partial
from importlib.metadata import version
from pathlib import Path
from typing import Any

from temporalio import activity
from temporalio.client import Client
from temporalio.worker import (
    ActivityInboundInterceptor,
    ExecuteActivityInput,
    Interceptor,
    Worker,
)
from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner, SandboxRestrictions

from infosec_harness.agents.inference import OpenShellModel
from infosec_harness.agents.investigator import (
    GUARDED_ACTIVITY_PREFIX,
    InvestigationDeps,
    build_agent,
)
from infosec_harness.config import Settings
from infosec_harness.contracts import WorkerIdentity
from infosec_harness.sandbox import OpenShell, OpenShellConfig
from infosec_harness.tools.execute import WRAPPER_OUTPUT_BYTES

from . import snapshot
from .investigation import (
    InvestigationActivities,
    InvestigationWorkflow,
    WorkerIdentityMismatch,
    bind_investigator,
    require_unchanged,
    short,
)

__all__ = [
    "WorkerIdentityInterceptor",
    "WorkerIdentityMismatch",
    "create_worker",
    "worker_identity",
    "workflow_runner",
]

# The installed package: runtime code, packaged skills and the release policy.
PACKAGE_ROOT = Path(__file__).parents[1]

log = logging.getLogger(__name__)


def worker_identity(settings: Settings) -> WorkerIdentity:
    """Content identity of the trusted worker and its explicit isolation configuration."""
    root = PACKAGE_ROOT
    source = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix in {".py", ".yaml", ".md"}:
            data = path.read_bytes()
            source.update(path.relative_to(root).as_posix().encode() + b"\0")
            source.update(len(data).to_bytes(8, "big") + data)
    dependencies = {
        name: version(name)
        for name in ("infosec-harness", "pydantic-ai-slim", "pydantic", "temporalio", "openshell")
    }
    raw = settings.openshell_config.read_bytes()
    runtime = json.loads(raw)
    # Paths alone do not identify the policy that the gateway will enforce.
    policies = {
        name: hashlib.sha256(Path(profile["policy"]).read_bytes()).hexdigest()
        for name, profile in runtime.get("profiles", {}).items()
    }
    configuration = settings.model_dump(
        mode="json",
        exclude={
            "temporal_api_key",
            "temporal_api_key_file",
            "temporal_tls_client_key",
            "temporal_tls_client_cert",
            "temporal_tls_ca_file",
            "openshell_config",
            # Operator conveniences that cannot change an investigation.
            "log_level",
            "reports_dir",
        },
    )
    encoded = json.dumps(
        {
            "settings": configuration,
            "openshell_sha256": hashlib.sha256(raw).hexdigest(),
            "policy_sha256": policies,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    fields = {
        "code_sha256": source.hexdigest(),
        "config_sha256": hashlib.sha256(encoded).hexdigest(),
        "dependencies": dependencies,
    }
    # Default separators: changing them changes every v11 fingerprint (next generation only).
    fingerprint = hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()
    return WorkerIdentity(fingerprint=fingerprint, **fields)


class WorkerIdentityInterceptor(Interceptor):
    """Check the receiving worker before every native investigator activity runs."""

    def __init__(
        self, identity: Callable[[], WorkerIdentity], bound: WorkerIdentity | None = None
    ):
        """``identity`` recomputes for drift checks; ``bound`` is the identity captured at
        worker start (computed from ``identity`` when not given)."""
        self.identity = identity
        self.bound_identity = bound if bound is not None else identity()

    def intercept_activity(self, next: ActivityInboundInterceptor) -> ActivityInboundInterceptor:
        owner = self

        class Guard(ActivityInboundInterceptor):
            # `input` mirrors the SDK base signature.
            async def execute_activity(self, input: ExecuteActivityInput) -> Any:  # noqa: A002
                if activity.info().activity_type.startswith(GUARDED_ACTIVITY_PREFIX):
                    deps = input.args[1] if len(input.args) > 1 else None
                    if (
                        not isinstance(deps, InvestigationDeps)
                        or deps.worker_identity != owner.bound_identity
                    ):
                        prepared = getattr(deps, "worker_identity", None)
                        raise WorkerIdentityMismatch(
                            "Investigator activity does not match the prepared worker identity "
                            f"(prepared={short(prepared)} bound={short(owner.bound_identity)})"
                        )
                    require_unchanged(owner.identity, owner.bound_identity)
                return await self.next.execute_activity(input)

        return Guard(next)


def workflow_runner() -> SandboxedWorkflowRunner:
    """The sandboxed workflow runner shared by the worker and zero-dispatch replay."""
    return SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules(
            InvestigationWorkflow.__module__, "annotated_types", "typing_inspection"
        )
    )


def create_worker(client: Client, settings: Settings) -> Worker:
    """Register native PydanticAI model/tool activities and four lifecycle activities."""
    openshell = OpenShell(OpenShellConfig.load(settings.openshell_config))
    budget = settings.limits.command_timeout_seconds
    if budget > openshell.config.max_timeout_seconds:
        # Every execute would be refused mid-investigation; refuse the worker instead.
        raise ValueError(
            f"limits.command_timeout_seconds ({budget}) exceeds the OpenShell runtime "
            f"max_timeout_seconds ({openshell.config.max_timeout_seconds}); lower the limit "
            "or raise the runtime bound"
        )
    if openshell.config.max_output_bytes < WRAPPER_OUTPUT_BYTES:
        # The shell wrapper's bounded capture would overflow the boundary limit, turning a
        # large command into an unknown execution; refuse the worker instead.
        raise ValueError(
            f"OpenShell runtime max_output_bytes ({openshell.config.max_output_bytes}) is below "
            f"the command wrapper's bounded output ({WRAPPER_OUTPUT_BYTES}); raise "
            "max_output_bytes in the runtime configuration"
        )
    model = OpenShellModel(
        openshell,
        settings.model_name,
        provider=settings.model_provider,
        base_url=settings.model_base_url,
        region=settings.model_region,
        # One operator knob bounds every sandbox command, including inference.
        timeout=budget,
    )
    agent = build_agent(openshell, model)
    bind_investigator(agent)
    # One capture shared by the lifecycle activities and the native-activity guard, so both
    # bind the same identity; `identity` recomputes it only for drift checks.
    identity = partial(worker_identity, settings)
    bound = identity()
    activities = InvestigationActivities(
        openshell,
        partial(snapshot.snapshot, settings=settings),
        settings.model_name,
        identity=identity,
        bound_identity=bound,
    )
    log.info(
        "event=worker_bound task_queue=%s fingerprint=%s code_sha256=%s config_sha256=%s "
        "command_timeout_seconds=%d model=%s",
        settings.task_queue, bound.fingerprint, bound.code_sha256, bound.config_sha256,
        budget, settings.model_name,
    )
    return Worker(
        client,
        task_queue=settings.task_queue,
        workflows=[InvestigationWorkflow],
        activities=[
            activities.prepare,
            activities.check_citations,
            activities.finalize,
            activities.cleanup,
        ],
        interceptors=[WorkerIdentityInterceptor(identity, bound)],
        workflow_runner=workflow_runner(),
    )
