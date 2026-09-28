"""Deterministic Temporal activities (the ⚙️ nodes of the graph).

Each takes and returns Pydantic models (the PydanticAIPlugin data converter serializes them).
Agent model/tool calls are *not* here — those become activities automatically via each
agent's TemporalDurability capability.
"""

from __future__ import annotations

import secrets
import time
from datetime import timedelta

from temporalio import activity

from infosec_harness.domain.models import (
    BuildResult,
    EnvironmentSpec,
    Finding,
    FindingInput,
    ProbeExecution,
    ProbeSource,
    RepoRef,
    RepoSnapshot,
    SmokeResult,
    StackFingerprint,
)
from infosec_harness.intake.adapters import to_finding
from infosec_harness.persistence.artifacts import get_store
from infosec_harness.repo.checkout import checkout
from infosec_harness.repo.detect import detect_stack
from infosec_harness.sandbox import docker

DEFAULT_TIMEOUTS = {"start_to_close_timeout": timedelta(minutes=5)}


@activity.defn
async def normalize_finding_activity(inp: FindingInput) -> Finding:
    return to_finding(inp)


@activity.defn
async def checkout_activity(ref: RepoRef) -> RepoSnapshot:
    return await checkout(ref)


@activity.defn
async def detect_stack_activity(snapshot: RepoSnapshot) -> StackFingerprint:
    return detect_stack(snapshot.path)



@activity.defn
async def build_environment_activity(args: dict) -> BuildResult:
    """Render a Dockerfile from the spec and build it (cached by repo hash + spec).

    Fails closed if the gVisor runtime is unavailable, validates the base image against the
    allowlist, and pins build egress to the repo-derived allowlist (D2/D14)."""
    from infosec_harness.repo.detect import detect_stack
    from infosec_harness.sandbox.policy import (
        DisallowedBaseImage,
        SandboxUnavailable,
        build_egress_allowlist,
        ensure_runtime_available,
    )

    snapshot = RepoSnapshot.model_validate(args["snapshot"])
    spec = EnvironmentSpec.model_validate(args["spec"])
    tag = docker.image_tag_for(snapshot.content_hash, spec)
    store = get_store()
    if await docker.image_exists(tag):
        return BuildResult(ok=True, image_tag=tag, spec=spec, duration_s=0.0)
    try:
        await ensure_runtime_available("build the target environment")
    except SandboxUnavailable as e:
        return BuildResult(ok=False, spec=spec, error_excerpt=str(e))
    egress = build_egress_allowlist(detect_stack(snapshot.path))
    start = time.monotonic()
    try:
        res = await docker.build_image(snapshot.path, spec, tag, egress_hosts=egress)
    except DisallowedBaseImage as e:
        return BuildResult(ok=False, spec=spec, error_excerpt=str(e))
    log_ref = store.put_text(res.stdout + "\n" + res.stderr, media_type="text/plain")
    ok = res.exit_code == 0 and not res.timed_out
    if ok:
        await docker.prune_images()  # evict oldest cached images beyond the cap
    return BuildResult(
        ok=ok, image_tag=tag if ok else None, spec=spec, log_artifact=log_ref,
        error_excerpt="" if ok else docker.tail(res.stderr or res.stdout, 3000),
        duration_s=time.monotonic() - start,
    )


@activity.defn
async def smoke_test_activity(args: dict | str) -> SmokeResult:
    """Prove the image starts *and* that its test runner is installed.

    Checking only that a shell runs left a missing runner to be discovered at probe time as
    exit 127 ("pytest: not found"), where probe repair cannot help because the fault is in the
    environment. Asking the runner for its version during preparation puts the failure in front
    of build repair instead.

    Accepts a bare image tag for backwards compatibility with recorded workflow histories.
    """
    image_tag = args if isinstance(args, str) else args["image_tag"]
    test_command = "" if isinstance(args, str) else (args.get("test_command") or "")

    res = await docker.run_shell(image_tag, "echo harness-smoke-ok", network=False, timeout=60)
    if res.exit_code != 0 or "harness-smoke-ok" not in res.stdout:
        return SmokeResult(ok=False, output_excerpt=docker.tail(res.stdout + res.stderr, 500))

    check = docker.runner_check_command(test_command)
    if check is None:
        return SmokeResult(ok=True, output_excerpt=docker.tail(res.stdout, 500))
    runner = await docker.run_shell(image_tag, check, network=False, timeout=120)
    if runner.exit_code != 0:
        return SmokeResult(
            ok=False,
            output_excerpt=f"the test runner is not installed: `{check}` exited "
                           f"{runner.exit_code}\n"
                           + docker.tail(runner.stdout + runner.stderr, 400),
        )
    return SmokeResult(ok=True, output_excerpt=docker.tail(runner.stdout or res.stdout, 500))


@activity.defn
async def execute_probe_activity(args: dict) -> ProbeExecution:
    """Run a probe in the built image with no network (F5)."""
    image_tag = args["image_tag"]
    probe = ProbeSource.model_validate(args["probe"])
    spec = EnvironmentSpec.model_validate(args["spec"])
    nonce = args["nonce"]
    attempt = args["attempt"]
    store = get_store()
    from infosec_harness.sandbox.policy import SandboxUnavailable, ensure_runtime_available

    try:
        await ensure_runtime_available("execute a probe")
    except SandboxUnavailable as e:
        return ProbeExecution(attempt=attempt, exit_code=None, oracle_fired=False,
                              precondition_reached=False, stderr_tail=str(e))
    res = await docker.run_probe(image_tag, probe.test_file_path, probe.content,
                                 spec.test_command, nonce, module_path=spec.module_path or "")
    combined = res.stdout + "\n" + res.stderr
    oracle_fired, precondition = docker.oracle_signals(combined, nonce)
    return ProbeExecution(
        attempt=attempt,
        exit_code=res.exit_code,
        timed_out=res.timed_out,
        oracle_fired=oracle_fired,
        precondition_reached=precondition,
        stdout_tail=docker.tail(res.stdout, 4000),
        stderr_tail=docker.tail(res.stderr, 4000),
        duration_s=res.duration_s,
        log_artifact=store.put_text(combined),
        source_artifact=store.put_text(probe.content, media_type="text/plain"),
    )


@activity.defn
async def resolve_location_activity(args: dict) -> dict | None:
    """Confirm the finding's file exists at the revision (F0c). None -> needs_info."""
    from infosec_harness.intake.adapters import resolve_location

    finding = Finding.model_validate(args["finding"])
    resolved = resolve_location(finding, args["repo_path"])
    return resolved.model_dump() if resolved else None


@activity.defn
async def new_nonce_activity() -> str:
    return secrets.token_hex(8)


ALL_ACTIVITIES = [
    normalize_finding_activity,
    checkout_activity,
    detect_stack_activity,
    build_environment_activity,
    smoke_test_activity,
    execute_probe_activity,
    resolve_location_activity,
    new_nonce_activity,
]
