"""Deterministic Temporal activities (the ⚙️ nodes of the graph).

Each takes and returns Pydantic models (the PydanticAIPlugin data converter serializes them).
Agent model/tool calls are *not* here — those become activities automatically via each
agent's TemporalDurability capability.
"""

from __future__ import annotations

import secrets

from temporalio import activity

from infosec_harness.domain.models import (
    BuildResult,
    EnvironmentSpec,
    Finding,
    ProbeExecution,
    ProbeSource,
    RepoRef,
    RepoSnapshot,
    SmokeResult,
    StackFingerprint,
)
from infosec_harness.graph import workloads
from infosec_harness.intake.adapters import resolve_location
from infosec_harness.persistence import recipes
from infosec_harness.repo.checkout import checkout
from infosec_harness.repo.detect import detect_stack
from infosec_harness.workflows.heartbeat import with_heartbeat
from infosec_harness.workflows.progress import ACTIVITIES as PROGRESS_ACTIVITIES


@activity.defn
@with_heartbeat
async def checkout_activity(ref: RepoRef) -> RepoSnapshot:
    return await checkout(ref)


@activity.defn
async def detect_stack_activity(snapshot: RepoSnapshot) -> StackFingerprint:
    return detect_stack(snapshot.path)



@activity.defn
@with_heartbeat
async def build_environment_activity(args: dict) -> BuildResult:
    """Render a Dockerfile from the spec and build it (cached by repo hash + spec)."""
    return await workloads.build_environment(RepoSnapshot.model_validate(args["snapshot"]),
                                             EnvironmentSpec.model_validate(args["spec"]))


@activity.defn
@with_heartbeat
async def smoke_test_activity(args: dict) -> SmokeResult:
    """Prove the image starts, its test runner is installed, and the adapter controls pass."""
    return await workloads.smoke_test(args["image_tag"], args.get("test_command") or "",
                                      language=args.get("language") or "",
                                      module_path=args.get("module_path") or "")


@activity.defn
@with_heartbeat
async def execute_probe_activity(args: dict) -> ProbeExecution:
    """Run a probe in the built image with no network (F5)."""
    return await workloads.execute_probe(args["image_tag"],
                                         ProbeSource.model_validate(args["probe"]),
                                         EnvironmentSpec.model_validate(args["spec"]),
                                         args["nonce"], args["attempt"])


@activity.defn
async def resolve_location_activity(args: dict) -> Finding | None:
    """Confirm the finding's file exists at the revision (F0c). None -> needs_info."""
    return resolve_location(Finding.model_validate(args["finding"]), args["repo_path"])


@activity.defn
async def new_nonce_activity() -> str:
    return secrets.token_hex(8)


@activity.defn
async def lookup_recipe_activity(stack: StackFingerprint) -> EnvironmentSpec | None:
    """Read the recipe cache. An activity, not workflow code: it touches the filesystem, and a
    workflow that read it directly would replay differently once the entry changed."""
    return recipes.lookup_recipe(stack)


@activity.defn
async def record_recipe_activity(args: dict) -> None:
    """Keep a spec that built and smoke-tested, drop one that did not."""
    recipes.record_recipe_outcome(StackFingerprint.model_validate(args["stack"]),
                                  EnvironmentSpec.model_validate(args["spec"]),
                                  worked=args["worked"])


ALL_ACTIVITIES = [
    checkout_activity,
    detect_stack_activity,
    build_environment_activity,
    smoke_test_activity,
    execute_probe_activity,
    resolve_location_activity,
    new_nonce_activity,
    lookup_recipe_activity,
    record_recipe_activity,
]

ALL_ACTIVITIES += PROGRESS_ACTIVITIES


@activity.defn
async def issue_broker_invocation_activity(args: dict) -> dict:
    from temporalio.exceptions import ApplicationError

    from infosec_harness.inference.invocations import request_invocation
    from infosec_harness.inference.protocol import BrokerError, InvocationRequest
    try:
        return (await request_invocation(InvocationRequest.model_validate(args))).model_dump(mode="json")
    except BrokerError as exc:
        raise ApplicationError(str(exc), type="BrokerError",
            non_retryable=exc.code not in {"unavailable", "pending"}) from None


ALL_ACTIVITIES.append(issue_broker_invocation_activity)


@activity.defn
async def close_broker_run_activity(args: dict) -> None:
    from temporalio.exceptions import ApplicationError

    from infosec_harness.inference.invocations import close_run
    from infosec_harness.inference.protocol import BrokerError
    try:
        await close_run(args["run_id"], args["root_id"])
    except BrokerError as exc:
        raise ApplicationError(str(exc), type="BrokerError",
            non_retryable=exc.code not in {"unavailable", "pending"}) from None


ALL_ACTIVITIES.append(close_broker_run_activity)
