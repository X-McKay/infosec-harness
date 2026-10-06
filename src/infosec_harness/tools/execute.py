"""The execute and run_probe tools, and the in-sandbox bounds every command runs under."""

import re
from dataclasses import replace
from pathlib import Path
from typing import Literal

from pydantic_ai import RunContext
from pydantic_ai.toolsets import FunctionToolset

from infosec_harness.agents.deps import InvestigationDeps
from infosec_harness.agents.evidence import final_probe_line, parse_probe_observations
from infosec_harness.contracts import Evidence
from infosec_harness.sandbox import (
    CommandResult,
    OpenShell,
    OpenShellError,
    Sandbox,
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


# A program name as a command word: bare, wrapper-relative (`./gradlew`) or a full path
# (`/usr/bin/javac`), but not a directory or file that merely shares the name
# (`node_modules/npm/`, `gradle.properties`).
_PROGRAM_START = r"(?<![\w.-])(?:\S*/)?"
_PROGRAM_END = r"(?![\w./-])"
# Commands whose failure usually means missing environment setup, not a target behaviour.
BUILD_TOOLS = re.compile(
    _PROGRAM_START
    + r"(mvnw?|gradlew?|npm|npx|yarn|pnpm|cpanm|cpan|javac|pip3?)"
    + _PROGRAM_END
)
# Maven specifically: its test phase and its log volume waste the token budget on probes.
MVN = re.compile(_PROGRAM_START + r"mvnw?" + _PROGRAM_END)
MVN_TEST = re.compile(_PROGRAM_START + r"mvnw?" + _PROGRAM_END + r"(?:(?!\||&&|;).)*\btest\b")
LOCAL_REPO = re.compile(r"-Dmaven\.repo\.local")

_MVN_FEEDBACK = (
    "Maven is unnecessary for a probe and its output floods the token budget. Compile the "
    "target classes directly with the Java skill's javac recipe (javac -d /tmp/probe_classes "
    "... then java -cp) and skip JUnit; do not rerun mvn test. Only use Maven when the code "
    "needs dependencies, and then with the environment skill's offline recipe "
    "(JAVA_TOOL_OPTIONS, -Dmaven.repo.local=/workspace/repo/.m2, dependency:go-offline, -q)."
)
_BUILD_FEEDBACK = (
    "Build or package tool failed. Follow the language skill's build recipe and the "
    "environment skill before retrying: resolve dependencies once in the workspace "
    "with the documented options, then run tests offline. Do not search the "
    "filesystem for artifacts, use pip/curl for JVM or Perl dependencies, or rerun "
    "the same failing command."
)


def environment_feedback(command: str, exit_code: int | None, output_truncated: bool) -> str | None:
    """A bounded pointer to the build recipe when a build/package command misbehaves.

    Maven on a probe is called out specifically: ``mvn test`` or ``mvn ... test`` (however it
    exits), any ``mvn`` whose output overflowed the stdout limit, and a failed ``mvn`` run
    without ``-Dmaven.repo.local`` all point at the direct-javac recipe. Other build tools
    point at the recipe only when they fail. ``None`` means no feedback.
    """
    failed = bool(exit_code)
    if MVN.search(command) and (
        MVN_TEST.search(command)
        or output_truncated
        or (failed and not LOCAL_REPO.search(command))
    ):
        return _MVN_FEEDBACK
    if failed and BUILD_TOOLS.search(command):
        return _BUILD_FEEDBACK
    return None


def bounded(argv: list[str], timeout: int) -> list[str]:
    """Kill ``argv`` inside the sandbox before the native timeout; every non-shell exec."""
    return ["/usr/bin/timeout", "--preserve-status", "-s", "KILL", str(command_budget(timeout)), *argv]


# Shell commands spawn children (npm, Maven, test runners). A killed child that still holds
# the exec pipes keeps the gateway stream open until its own ambiguous timeout (observed
# natively 2026-10-06), so the command writes to files inside the sandbox and this wrapper
# prints them after the kill: the stream ends when the wrapper exits, whatever lingers.
# Printed output is cut at these sizes (together below the native output bound); a cut is
# reported by one fixed marker line appended to stderr, which `unwrap_output` turns into
# ``output_truncated``. A forged marker can only mark output truncated, never hide a cut.
# The closing parenthesis sits on its own line after the command, so a command that ends
# in a ``#`` comment or a heredoc terminator still parses.
STDOUT_LIMIT = 200_000
STDERR_LIMIT = 60_000
TRUNCATION_MARKER = "[ih-wrapper] output exceeded the in-sandbox capture limit and was cut"
_SHELL_WRAPPER = (
    'out=$(mktemp /tmp/ih-out.XXXXXX) && err=$(mktemp /tmp/ih-err.XXXXXX) || exit 125; '
    '/usr/bin/timeout --preserve-status -s KILL "$1" /bin/bash -lc '
    '"cd /workspace/repo && ( $2\n) >\"$out\" 2>\"$err\" </dev/null"; code=$?; '
    f'head -c {STDOUT_LIMIT} "$out"; head -c {STDERR_LIMIT} "$err" >&2; '
    f'if (( $(wc -c <"$out") > {STDOUT_LIMIT} || $(wc -c <"$err") > {STDERR_LIMIT} )); '
    f"then printf '\\n%s\\n' '{TRUNCATION_MARKER}' >&2; fi; "
    'rm -f "$out" "$err"; exit "$code"'
)
# The most the wrapper ever prints (both streams cut, plus the marker line). The native
# `max_output_bytes` must be at least this, or a large command becomes an unknown execution.
WRAPPER_OUTPUT_BYTES = STDOUT_LIMIT + STDERR_LIMIT + len(f"\n{TRUNCATION_MARKER}\n".encode())


def unwrap_output(result: CommandResult) -> CommandResult:
    """Strip the wrapper's cut marker from stderr and record the cut as truncation."""
    suffix = f"\n{TRUNCATION_MARKER}\n"
    if not result.stderr.endswith(suffix):
        return result
    return replace(result, stderr=result.stderr[: -len(suffix)], output_truncated=True)


def evidence_from_result(
    identity: str,
    *,
    kind: Literal["probe", "command"],
    command: str,
    result: CommandResult,
    sandbox_id: str,
    source_digest: str,
    observations: dict[str, bool | str | int | None],
) -> Evidence:
    """Full (unexcerpted) evidence for one completed command, already passed through
    ``unwrap_output``. The tool return and finalization's receipt rebuild must agree."""
    return Evidence(
        id=identity,
        kind=kind,
        command=command,
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
        output_truncated=result.output_truncated,
        sandbox_id=sandbox_id,
        source_digest=source_digest,
        observations=observations,
    )


def bounded_shell(command: str, timeout: int) -> list[str]:
    """Run ``command`` under the shell wrapper: its own in-sandbox kill and file-backed capture."""
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
    kind: Literal["execute", "probe"],
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
    if kind == "execute":
        # Live cohorts 7, 8 and 10: after a failed build the agent searched the filesystem for
        # jars and looped on javac, and `mvn test` runs flooded the budget. Point at the recipe
        # before it improvises (see environment_feedback for the exact triggers).
        feedback = environment_feedback(command, result.exit_code, result.output_truncated)
        if feedback:
            observations["environment_feedback"] = feedback
    if result.exit_code == KILLED_EXIT:
        observations["timeout_feedback"] = (
            # An out-of-memory kill also exits 137, so the budget is the usual cause, not proof.
            f"Killed (exit {KILLED_EXIT}), normally at the {command_budget(timeout)}s command "
            "budget; it was not retried. Narrow the command, cache dependencies in the "
            "workspace, or split the work."
        )
    # Tool returns enter durable history; return bounded excerpts only.
    return evidence_from_result(
        identity,
        kind="probe" if kind == "probe" else "command",
        command=command,
        result=result,
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
            except OpenShellError as error:
                if not str(error).startswith("workspace changed or deleted original source"):
                    raise
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

