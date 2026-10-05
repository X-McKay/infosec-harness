"""Sandbox workloads: build, smoke-test and probe execution, shared by both execution paths.

Temporal activities (``workflows.activities``) wrap these with heartbeats and serialization;
``LocalOps`` calls them directly. Keeping one implementation is what stops the offline path
from drifting from the durable one it stands in for.
"""

from __future__ import annotations

import time

from infosec_harness.domain.models import (
    BuildResult,
    EnvironmentSpec,
    ExecutionOrigins,
    ProbeExecution,
    ProbeSource,
    RepoSnapshot,
    SmokeResult,
)
from infosec_harness.persistence.artifacts import get_store
from infosec_harness.sandbox import controls, docker, evidence
from infosec_harness.sandbox.errors import (
    DisallowedBaseImage,
    InvalidEnvironmentSpec,
    SandboxUnavailable,
)
from infosec_harness.sandbox.image import image_tag_for
from infosec_harness.sandbox.output import (
    no_tests_executed,
    oracle_signals,
    runner_check_command,
    sink_returned,
    tail,
)


async def build_environment(snapshot: RepoSnapshot, spec: EnvironmentSpec) -> BuildResult:
    """Render a Dockerfile from the spec and build it (cached by repo hash + spec).

    Fails closed if the gVisor runtime is unavailable, before a cached image is reused: an image
    that exists is not evidence that this host can still run it under isolation. The build
    validates the base image against the allowlist; build egress is the operator's proxy
    allowlist (not anything derived from the repository) on an internal network (D2/D14)."""
    tag = image_tag_for(snapshot.content_hash, spec)
    store = get_store()
    try:
        await docker.ensure_runtime_available("build the target environment")
    except SandboxUnavailable as e:
        return BuildResult(ok=False, spec=spec, error_excerpt=str(e))
    if await docker.image_exists(tag):
        return BuildResult(ok=True, image_tag=tag, spec=spec, duration_s=0.0)
    start = time.monotonic()
    try:
        res = await docker.build_image(snapshot.path, spec, tag)
    except (DisallowedBaseImage, InvalidEnvironmentSpec, SandboxUnavailable) as e:
        return BuildResult(ok=False, spec=spec, error_excerpt=str(e))
    log_ref = store.put_text(res.stdout + "\n" + res.stderr, media_type="text/plain")
    ok = res.exit_code == 0 and not res.timed_out
    return BuildResult(
        ok=ok, image_tag=tag if ok else None, spec=spec, log_artifact=log_ref,
        error_excerpt="" if ok else tail(res.stderr or res.stdout, 3000),
        duration_s=time.monotonic() - start,
    )


async def smoke_test(image_tag: str, test_command: str = "", *, language: str = "",
                     module_path: str = "") -> SmokeResult:
    """Prove the image starts *and* that its test runner is installed.

    Checking only that a shell runs left a missing runner to be discovered at probe time as
    exit 127 ("pytest: not found"), where probe repair cannot help because the fault is in the
    environment. Asking the runner for its version during preparation puts the failure in front
    of build repair instead.
    """

    res = await docker.run_shell(image_tag, "echo harness-smoke-ok", timeout=60)
    if res.exit_code != 0 or "harness-smoke-ok" not in res.stdout:
        return SmokeResult(ok=False, output_excerpt=tail(res.stdout + res.stderr, 500))

    check = runner_check_command(test_command)
    runner_excerpt = tail(res.stdout, 500)
    if check is not None:
        runner = await docker.run_shell(image_tag, check, timeout=120)
        if runner.exit_code != 0:
            return SmokeResult(
                ok=False,
                output_excerpt=f"the test runner is not installed: `{check}` exited "
                               f"{runner.exit_code}\n"
                               + tail(runner.stdout + runner.stderr, 400),
            )
        runner_excerpt = tail(runner.stdout or res.stdout, 500)
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
    written = controls.control_test_for(language, test_command)
    if written is None:
        # Not checked is not the same as passed. A language this module has not learned must
        # not fail preparation, and preparation must not claim it was verified.
        control = controls.ControlResult(positive=False, negative=False, status="not_checked")
        return SmokeResult(ok=True, output_excerpt=runner_excerpt
                           + f"\n(canary not run: no template for language {language!r})\n"
                           + controls.encode_control_result(control))
    path, content = written
    res = await docker.run_probe(image_tag, path, content, test_command,
                                 controls.POSITIVE_CONTROL_NONCE, module_path=module_path)
    combined = res.stdout + "\n" + res.stderr
    missing = controls.missing_markers(combined)
    if missing or res.exit_code != 0 or res.timed_out:
        return SmokeResult(ok=False,
                           output_excerpt=controls.explain(language, test_command, missing, combined))

    negative = controls.control_test_for(
        language, test_command, nonce=controls.NEGATIVE_CONTROL_NONCE, oracle=False)
    assert negative is not None  # the positive template for this same language existed
    negative_path, negative_content = negative
    negative_run = await docker.run_probe(
        image_tag, negative_path, negative_content, test_command,
        controls.NEGATIVE_CONTROL_NONCE, module_path=module_path,
    )
    negative_output = negative_run.stdout + "\n" + negative_run.stderr
    negative_missing = controls.missing_markers(
        negative_output, nonce=controls.NEGATIVE_CONTROL_NONCE)
    # The negative control deliberately omits the oracle, so exactly that marker must be
    # absent. This catches an adapter that reuses stale output or manufactures a positive.
    negative_ok = (negative_run.exit_code == 0 and not negative_run.timed_out
                   and negative_missing == ["oracle"])
    control = controls.ControlResult(positive=True, negative=negative_ok)
    record = controls.encode_control_result(control)
    if not negative_ok:
        return SmokeResult(
            ok=False,
            output_excerpt=(
                "The environment failed the harness negative control. A discovered test emitted "
                "the precondition and sink-returned markers but deliberately no oracle; the "
                "adapter did not preserve that result. Captured output:\n"
                + tail(negative_output, 1500) + "\n" + record
            ),
        )
    return SmokeResult(
        ok=True,
        output_excerpt=runner_excerpt + "\n(canary positive and negative controls observed)\n"
        + record,
    )


async def execute_probe(image_tag: str, probe: ProbeSource, spec: EnvironmentSpec, nonce: str,
                        attempt: int) -> ProbeExecution:
    """Run a probe in the built image with no network (F5)."""
    store = get_store()
    try:
        await docker.ensure_runtime_available("execute a probe")
    except SandboxUnavailable as e:
        return ProbeExecution(attempt=attempt, exit_code=None, oracle_fired=False,
                              precondition_reached=False, stderr_tail=str(e))
    res = await docker.run_probe(image_tag, probe.test_file_path, probe.content,
                                 spec.test_command, nonce, module_path=spec.module_path or "")
    combined = res.stdout + "\n" + res.stderr
    oracle_fired, precondition = oracle_signals(combined, nonce)
    returned = sink_returned(combined, nonce)
    # Only meaningful when the markers are absent: if the sink returned, tests plainly ran, and
    # a runner phrase like "Tests run: 0" would be from an unrelated module in a multi-module
    # build rather than evidence that this probe never executed.
    no_tests = None if returned else no_tests_executed(combined)
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
        stdout_tail=tail(res.stdout, 4000),
        stderr_tail=tail(res.stderr, 4000),
        duration_s=res.duration_s,
        log_artifact=store.put_text(artifact_body),
        source_artifact=store.put_text(probe.content, media_type="text/plain"),
        # Persisted with the execution so readers need not decode the log artifact to learn
        # which parts of this record the controller observed and which the probe printed.
        origins=ExecutionOrigins.model_validate(
            {section: record[section] for section in ExecutionOrigins.model_fields}),
    )
