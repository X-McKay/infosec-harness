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
from infosec_harness.sandbox import canary, docker, evidence
from infosec_harness.workflows.heartbeat import with_heartbeat
from infosec_harness.workflows.progress import ACTIVITIES as PROGRESS_ACTIVITIES

DEFAULT_TIMEOUTS = {"start_to_close_timeout": timedelta(minutes=5)}


@activity.defn
async def normalize_finding_activity(inp: FindingInput) -> Finding:
    return to_finding(inp)


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
    """Render a Dockerfile from the spec and build it (cached by repo hash + spec).

    Fails closed if the gVisor runtime is unavailable, validates the base image against the
    allowlist, and pins build egress to the repo-derived allowlist (D2/D14)."""
    from infosec_harness.repo.detect import detect_stack
    from infosec_harness.sandbox.policy import (
        DisallowedBaseImage,
        InvalidEnvironmentSpec,
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
    except (DisallowedBaseImage, InvalidEnvironmentSpec, SandboxUnavailable) as e:
        return BuildResult(ok=False, spec=spec, error_excerpt=str(e))
    log_ref = store.put_text(res.stdout + "\n" + res.stderr, media_type="text/plain")
    ok = res.exit_code == 0 and not res.timed_out
    # A built environment may sit between smoke/probe activities with no container referencing
    # its image. Until durable image leases exist, build completion must not evict another
    # workflow's prepared environment. `docker.prune_images` remains manual maintenance only.
    return BuildResult(
        ok=ok, image_tag=tag if ok else None, spec=spec, log_artifact=log_ref,
        error_excerpt="" if ok else docker.tail(res.stderr or res.stdout, 3000),
        duration_s=time.monotonic() - start,
    )


@activity.defn
@with_heartbeat
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
    language = "" if isinstance(args, str) else (args.get("language") or "")
    module_path = "" if isinstance(args, str) else (args.get("module_path") or "")

    res = await docker.run_shell(image_tag, "echo harness-smoke-ok", network=False, timeout=60)
    if res.exit_code != 0 or "harness-smoke-ok" not in res.stdout:
        return SmokeResult(ok=False, output_excerpt=docker.tail(res.stdout + res.stderr, 500))

    check = docker.runner_check_command(test_command)
    runner_excerpt = docker.tail(res.stdout, 500)
    if check is not None:
        runner = await docker.run_shell(image_tag, check, network=False, timeout=120)
        if runner.exit_code != 0:
            return SmokeResult(
                ok=False,
                output_excerpt=f"the test runner is not installed: `{check}` exited "
                               f"{runner.exit_code}\n"
                               + docker.tail(runner.stdout + runner.stderr, 400),
            )
        runner_excerpt = docker.tail(runner.stdout or res.stdout, 500)
    return await _canary_result(image_tag, test_command, language, module_path,
                                runner_excerpt)


async def _canary_result(image_tag: str, test_command: str, language: str, module_path: str,
                         runner_excerpt: str) -> SmokeResult:
    """Prove a test *we* wrote is discovered here and its markers reach stdout.

    The runner answering `--version` proves it exists, not that it will find and report a file
    we author. Everything between those -- discovery rules, the provider selected, the selector
    syntax, a project config that re-enables capture -- was assumed, per framework. A recipe
    that cannot carry a marker cannot carry a probe, and a probe whose markers vanish is
    recorded as having reached nothing: a false negative rather than an error.

    Checked by execution rather than by a table, so a framework nobody encoded fails here
    instead of silently at probe time.
    """
    written = canary.canary_for(language, test_command)
    if written is None:
        # Not checked is not the same as passed. A language this module has not learned must
        # not fail preparation, and preparation must not claim it was verified.
        control = canary.ControlResult(positive=False, negative=False, status="not_checked")
        return SmokeResult(ok=True, output_excerpt=runner_excerpt
                           + f"\n(canary not run: no template for language {language!r})\n"
                           + canary.encode_control_result(control))
    path, content = written
    res = await docker.run_probe(image_tag, path, content, test_command, canary.CANARY_NONCE,
                                 module_path=module_path)
    combined = res.stdout + "\n" + res.stderr
    missing = canary.missing_markers(combined)
    if missing or res.exit_code != 0 or res.timed_out:
        return SmokeResult(ok=False,
                           output_excerpt=canary.explain(language, test_command, missing, combined))

    negative = canary.canary_for(
        language, test_command, nonce=canary.NEGATIVE_CANARY_NONCE, oracle=False)
    assert negative is not None  # the positive template for this same language existed
    negative_path, negative_content = negative
    negative_run = await docker.run_probe(
        image_tag, negative_path, negative_content, test_command,
        canary.NEGATIVE_CANARY_NONCE, module_path=module_path,
    )
    negative_output = negative_run.stdout + "\n" + negative_run.stderr
    negative_missing = canary.missing_markers(
        negative_output, nonce=canary.NEGATIVE_CANARY_NONCE)
    # The negative control deliberately omits the oracle, so exactly that marker must be
    # absent. This catches an adapter that reuses stale output or manufactures a positive.
    negative_ok = (negative_run.exit_code == 0 and not negative_run.timed_out
                   and negative_missing == ["oracle"])
    control = canary.ControlResult(positive=True, negative=negative_ok)
    record = canary.encode_control_result(control)
    if not negative_ok:
        return SmokeResult(
            ok=False,
            output_excerpt=(
                "The environment failed the harness negative control. A discovered test emitted "
                "the precondition and sink-returned markers but deliberately no oracle; the "
                "adapter did not preserve that result. Captured output:\n"
                + docker.tail(negative_output, 1500) + "\n" + record
            ),
        )
    return SmokeResult(
        ok=True,
        output_excerpt=runner_excerpt + "\n(canary positive and negative controls observed)\n"
        + record,
    )


@activity.defn
@with_heartbeat
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
    returned = docker.sink_returned(combined, nonce)
    # Only meaningful when the markers are absent: if the sink returned, tests plainly ran, and
    # a runner phrase like "Tests run: 0" would be from an unrelated module in a multi-module
    # build rather than evidence that this probe never executed.
    no_tests = None if returned else docker.no_tests_executed(combined)
    record = evidence.execution_record(
        image_tag=image_tag,
        test_file_path=probe.test_file_path,
        test_command=spec.test_command,
        content=probe.content,
        nonce=nonce,
        attempt=attempt,
        exit_code=res.exit_code,
        timed_out=res.timed_out,
        duration_s=res.duration_s,
        oracle_fired=oracle_fired,
        precondition_reached=precondition,
        sink_returned=returned,
        no_tests=no_tests,
    )
    artifact_body = combined + "\n" + evidence.encode_execution_record(record)
    return ProbeExecution(
        attempt=attempt,
        exit_code=res.exit_code,
        timed_out=res.timed_out,
        oracle_fired=oracle_fired,
        precondition_reached=precondition,
        sink_returned=returned,
        runner_reported_no_tests=no_tests,
        stdout_tail=docker.tail(res.stdout, 4000),
        stderr_tail=docker.tail(res.stderr, 4000),
        duration_s=res.duration_s,
        log_artifact=store.put_text(artifact_body),
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


@activity.defn
async def lookup_recipe_activity(stack: StackFingerprint) -> EnvironmentSpec | None:
    """Read the recipe cache. An activity, not workflow code: it touches the filesystem, and a
    workflow that read it directly would replay differently once the entry changed."""
    from infosec_harness.persistence.recipes import get_recipe_store, stack_key

    return get_recipe_store().lookup(stack_key(stack))


@activity.defn
async def record_recipe_activity(args: dict) -> None:
    """Keep a spec that built and smoke-tested, drop one that did not."""
    from infosec_harness.persistence.recipes import get_recipe_store, is_cacheable, stack_key

    stack = StackFingerprint.model_validate(args["stack"])
    spec = EnvironmentSpec.model_validate(args["spec"])
    store, key = get_recipe_store(), stack_key(stack)
    if args["worked"] and is_cacheable(spec):
        store.record(key, spec)
    elif not args["worked"]:
        store.forget(key)


ALL_ACTIVITIES = [
    normalize_finding_activity,
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
