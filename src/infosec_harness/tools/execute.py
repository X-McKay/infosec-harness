"""The execute and run_probe tools, and the in-sandbox bounds every command runs under."""

import re
from dataclasses import replace
from pathlib import Path

from pydantic_ai import RunContext
from pydantic_ai.toolsets import FunctionToolset

from infosec_harness.agents.evidence import final_probe_line, parse_probe_observations
from infosec_harness.agents.investigator import InvestigationDeps
from infosec_harness.contracts import Evidence
from infosec_harness.sandbox import (
    CommandResult,
    OpenShell,
    Sandbox,
    SourceChanged,
    UnsafeSnapshotMetadata,
)

# The pinned gateway reports its own timeout as an ambiguous exit 124, which the adapter
# must treat as unknown. Killing the command inside the sandbox first (exit 137) keeps the
# receipt complete, so a slow build becomes feedback instead of a lost investigation.
TIMEOUT_MARGIN_SECONDS = 10
KILLED_EXIT = 137


def command_budget(timeout: int) -> int:
    """The in-sandbox kill budget for a native execution bounded by ``timeout``."""
    return max(timeout - TIMEOUT_MARGIN_SECONDS, 1)


# Commands whose failure usually means missing environment setup, not a target behaviour.
BUILD_TOOLS = re.compile(r"(?<![\w./-])(mvn|gradle|gradlew|npm|npx|yarn|pnpm|cpanm|cpan|javac|pip3?)(?![\w-])")


def bounded(argv: list[str], timeout: int) -> list[str]:
    """Kill ``argv`` inside the sandbox before the native timeout; shared by every exec."""
    return ["/usr/bin/timeout", "--preserve-status", "-s", "KILL", str(command_budget(timeout)), *argv]


# Shell commands spawn children (npm, Maven, test runners). A killed child that still holds
# the exec pipes keeps the gateway stream open until its own ambiguous timeout (observed
# natively 2026-10-06), so the command writes to files inside the sandbox and this wrapper
# prints them after the kill: the stream ends when the wrapper exits, whatever lingers.
# Printed output is cut at these sizes (together below the native output bound); a cut is
# reported by one fixed marker line appended to stderr, which `unwrap_output` turns into
# ``output_truncated``. A forged marker can only mark output truncated, never hide a cut.
STDOUT_LIMIT = 200_000
STDERR_LIMIT = 60_000
TRUNCATION_MARKER = "[ih-wrapper] output exceeded the in-sandbox capture limit and was cut"
_SHELL_WRAPPER = (
    'out=$(mktemp /tmp/ih-out.XXXXXX) && err=$(mktemp /tmp/ih-err.XXXXXX) || exit 125; '
    '/usr/bin/timeout --preserve-status -s KILL "$1" /bin/bash -lc '
    '"cd /workspace/repo && ( $2 ) >\"$out\" 2>\"$err\" </dev/null"; code=$?; '
    f'head -c {STDOUT_LIMIT} "$out"; head -c {STDERR_LIMIT} "$err" >&2; '
    f'if (( $(wc -c <"$out") > {STDOUT_LIMIT} || $(wc -c <"$err") > {STDERR_LIMIT} )); '
    f"then printf '\\n%s\\n' '{TRUNCATION_MARKER}' >&2; fi; "
    'rm -f "$out" "$err"; exit "$code"'
)


def unwrap_output(result: CommandResult) -> CommandResult:
    """Strip the wrapper's cut marker from stderr and record the cut as truncation."""
    suffix = f"\n{TRUNCATION_MARKER}\n"
    if not result.stderr.endswith(suffix):
        return result
    return replace(result, stderr=result.stderr[: -len(suffix)], output_truncated=True)


def bounded_shell(command: str, timeout: int) -> list[str]:
    return ["/bin/bash", "-c", _SHELL_WRAPPER, "ih-wrapper", str(command_budget(timeout)), command]


def operation_id(ctx: RunContext[InvestigationDeps], kind: str) -> str:
    # tool_call_id is replayed by PydanticAI and serialized into each native activity.
    if not ctx.tool_call_id:
        raise ValueError("A tool call requires a stable call identity")
    return f"{kind}:{ctx.run_step}:{ctx.tool_call_id}"


async def command_tool(
    openshell: OpenShell,
    ctx: RunContext[InvestigationDeps],
    command: str,
    sandbox: Sandbox,
    kind: str,
) -> Evidence:
    identity = operation_id(ctx, kind)
    timeout = ctx.deps.request.limits.command_timeout_seconds
    result = unwrap_output(
        await openshell.execute(
            sandbox,
            bounded_shell(command, timeout),
            operation_id=identity,
            timeout=timeout,
        )
    )
    observations = parse_probe_observations(result.stdout) if kind == "probe" else {}
    if kind == "probe" and not observations and final_probe_line(result.stdout):
        # Feedback only: tool returns are excerpted, so record what the full stdout showed.
        observations["probe_line_rejected"] = True
    if kind == "execute" and result.exit_code and BUILD_TOOLS.search(command):
        # Live cohorts 7 and 8: after one failed build the agent searched the filesystem
        # for jars and looped on javac. Point at the recipe before it improvises.
        observations["environment_feedback"] = (
            "Build or package tool failed. Follow the language skill's build recipe and the "
            "environment skill before retrying: resolve dependencies once in the workspace "
            "with the documented options, then run tests offline. Do not search the "
            "filesystem for artifacts, use pip/curl for JVM or Perl dependencies, or rerun "
            "the same failing command."
        )
    if result.exit_code == KILLED_EXIT:
        observations["timeout_feedback"] = (
            f"Killed (exit {KILLED_EXIT}) at the {command_budget(timeout)}s command "
            "budget; it was not retried. Narrow the command, cache dependencies in the "
            "workspace, or split the work."
        )
    # Tool returns enter durable history; return bounded excerpts only.
    return Evidence(
        id=identity,
        kind="probe" if kind == "probe" else "command",
        command=command,
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
        timed_out=False,
        output_truncated=result.output_truncated,
        sandbox_id=sandbox.id,
        source_digest=ctx.deps.source_digest,
        observations=observations,
    ).excerpt()


def register(tools: FunctionToolset[InvestigationDeps], openshell: OpenShell) -> None:
    @tools.tool
    async def execute(ctx: RunContext[InvestigationDeps], command: str) -> Evidence:
        """Execute a build or inspection command in the workspace OpenShell sandbox.

        Run Maven, Gradle, npm or cpanm only as the language and environment skills describe;
        output is bounded and a command killed at the budget returns exit 137.
        """
        return await command_tool(openshell, ctx, command, ctx.deps.sandbox, "execute")

    @tools.tool
    async def run_probe(ctx: RunContext[InvestigationDeps], command: str) -> Evidence:
        """Run the command offline in a fresh copy of /workspace/repo, starting there; nothing else transfers.

        Load the probe skill first. Cite the exact full returned Evidence.id.
        """
        sandbox = await openshell.create(
            ctx.deps.run_id, profile="probe", slot=operation_id(ctx, "probe")
        )
        try:
            # OpenShell transfers bounded artifacts; hostile archives stay opaque on the worker.
            try:
                digest = await openshell.copy_workspace(
                    ctx.deps.sandbox,
                    sandbox,
                    operation_id=operation_id(ctx, "copy"),
                    expected_source=Path(ctx.deps.snapshot_path),
                )
            except SourceChanged as error:
                # The agent altered original source; the probe never ran. Feedback, not failure.
                return Evidence(
                    id=operation_id(ctx, "probe"),
                    kind="probe",
                    command=command,
                    exit_code=None,
                    stderr=str(error),
                    sandbox_id=sandbox.id,
                    source_digest=ctx.deps.source_digest,
                    observations={
                        "source_verified": False,
                        "integrity_feedback": (
                            f"{error}. The probe was refused and did not run. Restore that "
                            "file's original bytes with write, keep new files separate, and "
                            "run a new probe; or return inconclusive."
                        ),
                    },
                ).excerpt()
            evidence = await command_tool(openshell, ctx, command, sandbox, "probe")
            try:
                await openshell.verify_source(
                    sandbox,
                    expected_source=Path(ctx.deps.snapshot_path),
                    operation_id=operation_id(ctx, "verify"),
                )
            except UnsafeSnapshotMetadata:
                if evidence.exit_code is None:
                    raise
                evidence.observations["source_verified"] = False
                evidence.observations["integrity_feedback"] = (
                    "Post-execution archive metadata was rejected, so this completed run is not "
                    "source-verified and was not retried; see the probe skill, then run a "
                    "corrected new probe or return inconclusive."
                )
                return evidence
            if digest:
                evidence.observations["workspace_digest"] = digest
                evidence.observations["source_verified"] = True
            return evidence
        finally:
            await openshell.close(sandbox)

