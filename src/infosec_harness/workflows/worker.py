"""The trusted worker: its content identity, the activity identity guard and its setup."""

import hashlib
import json
from functools import partial
from importlib.metadata import version
from pathlib import Path

from temporalio import activity
from temporalio.worker import ActivityInboundInterceptor, Interceptor

from infosec_harness.agents.investigator import (
    GUARDED_ACTIVITY_PREFIX,
    InvestigationDeps,
    build_agent,
)
from infosec_harness.models import WorkerIdentity
from infosec_harness.sandbox import OpenShell, OpenShellConfig

from .investigation import InvestigationActivities, InvestigationWorkflow, bind_investigator

# The installed package: runtime code, packaged skills and the release policy.
PACKAGE_ROOT = Path(__file__).parents[1]


def worker_identity(settings) -> WorkerIdentity:
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
    fingerprint = hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()
    return WorkerIdentity(fingerprint=fingerprint, **fields)


class WorkerIdentityInterceptor(Interceptor):
    """Check the receiving worker before every native investigator activity runs."""

    def __init__(self, identity):
        self.identity = identity
        self.bound_identity = identity()

    def intercept_activity(self, next: ActivityInboundInterceptor) -> ActivityInboundInterceptor:
        owner = self

        class Guard(ActivityInboundInterceptor):
            async def execute_activity(self, input):
                if activity.info().activity_type.startswith(GUARDED_ACTIVITY_PREFIX):
                    deps = input.args[1] if len(input.args) > 1 else None
                    if (
                        not isinstance(deps, InvestigationDeps)
                        or deps.worker_identity != owner.bound_identity
                    ):
                        raise ValueError(
                            "Investigator activity does not match the prepared worker identity"
                        )
                    if owner.identity() != owner.bound_identity:
                        raise ValueError(
                            "Worker code or isolation configuration changed; restart the worker"
                        )
                return await self.next.execute_activity(input)

        return Guard(next)


def create_worker(client, settings):
    """Register native PydanticAI model/tool activities and three lifecycle activities."""
    from temporalio.worker import Worker
    from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner, SandboxRestrictions

    from infosec_harness.agents.inference import OpenShellModel

    from . import snapshot

    openshell = OpenShell(OpenShellConfig.load(settings.openshell_config))
    budget = settings.limits.command_timeout_seconds
    if budget > openshell.config.max_timeout_seconds:
        # Every execute would be refused mid-investigation; refuse the worker instead.
        raise ValueError(
            f"limits.command_timeout_seconds ({budget}) exceeds the OpenShell runtime "
            f"max_timeout_seconds ({openshell.config.max_timeout_seconds}); lower the limit "
            "or raise the runtime bound"
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
    activities = InvestigationActivities(
        openshell,
        partial(snapshot.snapshot, settings=settings),
        settings.model_name,
        identity=partial(worker_identity, settings),
    )
    return Worker(
        client,
        task_queue=settings.task_queue,
        workflows=[InvestigationWorkflow],
        activities=[activities.prepare, activities.finalize, activities.cleanup],
        interceptors=[WorkerIdentityInterceptor(partial(worker_identity, settings))],
        workflow_runner=SandboxedWorkflowRunner(
            restrictions=SandboxRestrictions.default.with_passthrough_modules(
                InvestigationWorkflow.__module__, "annotated_types", "typing_inspection"
            )
        ),
    )
