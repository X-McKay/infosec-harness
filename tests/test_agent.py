"""The single investigator's native tools and receipt boundary."""

import json
from types import SimpleNamespace

import pytest
from pydantic_ai.messages import ModelRequest, ModelResponse, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import FunctionModel

from infosec_harness.agent import InvestigationDeps, build_agent
from infosec_harness.models import Finding, InvestigationRequest
from infosec_harness.sandbox import CommandResult, Sandbox


class FakeOpenShell:
    def __init__(self):
        self.executions = []
        self.closed = []
        self._receipts = []

    async def create(self, run_id, *, profile="workspace", slot=""):
        return Sandbox(id=f"{profile}-{slot}", run_id=run_id, name=profile, profile=profile)

    async def upload(self, sandbox, source, destination):
        pass

    async def copy_workspace(self, workspace, probe, *, operation_id, expected_source):
        assert workspace.profile == "workspace" and probe.profile == "probe"
        return "workspace-digest"

    async def verify_source(self, sandbox, *, expected_source, operation_id):
        assert sandbox.profile == "probe"

    async def execute(self, sandbox, command, *, operation_id, timeout, stdin=None):
        self.executions.append((sandbox, command, operation_id, stdin))
        result = CommandResult(0, "attacker-controlled value reached target\n", "")
        self._receipts.append(
            SimpleNamespace(
                sandbox=sandbox,
                command=command,
                operation_id=operation_id,
                result=result,
            )
        )
        return result

    def receipts(self, run_id):
        return [receipt for receipt in self._receipts if receipt.sandbox.run_id == run_id]

    async def close(self, sandbox):
        self.closed.append(sandbox.id)

    async def close_run(self, run_id):
        self.closed.append(run_id)


def final_response(info, *, evidence_ids=None):
    return ModelResponse(
        parts=[
            ToolCallPart(
                info.output_tools[0].name,
                {
                    "label": "inconclusive",
                    "summary": "Observed execution requires source context.",
                    "evidence_ids": evidence_ids or [],
                    "citations": [],
                },
                tool_call_id="verdict",
            )
        ]
    )


async def test_native_tools_use_openshell_and_return_receipts():
    shell = FakeOpenShell()

    def respond(messages, info):
        if not shell.executions:
            return ModelResponse(
                parts=[
                    ToolCallPart("execute", {"command": "pytest test_sink.py"}, tool_call_id="cmd")
                ]
            )
        returns = [
            part
            for message in messages
            if isinstance(message, ModelRequest)
            for part in message.parts
            if isinstance(part, ToolReturnPart) and part.tool_name == "execute"
        ]
        content = returns[0].content
        identity = content.id if hasattr(content, "id") else content["id"]
        return final_response(info, evidence_ids=[identity])

    agent = build_agent(shell, FunctionModel(respond))
    request = InvestigationRequest(finding=Finding(title="Sink", repo_url="fixture"))
    sandbox = await shell.create("run")
    result = await agent.run(
        "Inspect sink",
        deps=InvestigationDeps(
            run_id="run",
            sandbox=sandbox,
            source_digest="digest",
            snapshot_path="/fixture",
            request=request,
        ),
    )
    assert result.output.evidence_ids == ["execute:1:cmd"]
    argv = shell.executions[0][1]
    assert argv[:2] == ["/bin/bash", "-c"] and argv[3:] == ["ih-wrapper", "110", "pytest test_sink.py"]
    assert "cd /workspace/repo && ( $2 )" in argv[2] and "timeout --preserve-status -s KILL" in argv[2]


async def test_command_killed_at_budget_is_a_completed_receipt_with_feedback():
    """Live cohort 5 stopped on the gateway's ambiguous exit 124 after a slow command. The
    in-sandbox wrapper kills first (exit 137), so the receipt is complete and the agent is told."""
    shell = FakeOpenShell()
    native_execute = shell.execute

    async def execute(sandbox, command, **kwargs):
        await native_execute(sandbox, command, **kwargs)
        return CommandResult(137, "", "Killed")

    shell.execute = execute

    def respond(messages, info):
        if not shell.executions:
            return ModelResponse(parts=[ToolCallPart(
                "execute", {"command": "npm ci"}, tool_call_id="slow")])
        returned = [part.content for message in messages if isinstance(message, ModelRequest)
                    for part in message.parts
                    if isinstance(part, ToolReturnPart) and part.tool_name == "execute"][-1]
        returned = returned.model_dump()
        assert returned["exit_code"] == 137
        assert "110s command budget" in returned["observations"]["timeout_feedback"]
        assert "not retried" in returned["observations"]["timeout_feedback"]
        return final_response(info)

    request = InvestigationRequest(finding=Finding(title="Sink", repo_url="fixture"))
    deps = InvestigationDeps(run_id="run", sandbox=await shell.create("run"),
                             source_digest="digest", snapshot_path="/fixture", request=request)
    result = await build_agent(shell, FunctionModel(respond)).run("Inspect", deps=deps)
    assert result.output.label == "inconclusive"
    _, command, operation, _ = shell.executions[0]
    assert command[3:] == ["ih-wrapper", "110", "npm ci"]
    assert operation == "execute:1:slow"


def run_wrapper(tmp_path, command):
    """Run the real shell wrapper under local bash; only the timeout binary and the
    sandbox repository path are substituted (neither exists on a development host)."""
    import subprocess

    from infosec_harness.agent import _SHELL_WRAPPER

    fake_timeout = tmp_path / "timeout"
    fake_timeout.write_text('#!/bin/bash\nshift 4\nexec "$@"\n')
    fake_timeout.chmod(0o755)
    assert _SHELL_WRAPPER.count("/usr/bin/timeout ") == 1
    assert _SHELL_WRAPPER.count("cd /workspace/repo ") == 1
    wrapper = _SHELL_WRAPPER.replace("/usr/bin/timeout ", f"{fake_timeout} ").replace(
        "cd /workspace/repo ", f"cd {tmp_path} "
    )
    completed = subprocess.run(
        ["/bin/bash", "-c", wrapper, "ih-wrapper", "5", command],
        capture_output=True,
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},
        timeout=60,
    )
    return CommandResult(
        completed.returncode, completed.stdout.decode(), completed.stderr.decode()
    )


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_wrapper_cut_is_reported_as_truncation(tmp_path, stream):
    """The wrapper cuts printed output at fixed sizes inside the sandbox. A cut must reach
    the receipt as output_truncated, or a definitive verdict's untruncated-output rule holds
    vacuously (review of 2026-10-06)."""
    from infosec_harness.agent import (
        STDERR_LIMIT,
        STDOUT_LIMIT,
        TRUNCATION_MARKER,
        unwrap_output,
    )

    limit = STDOUT_LIMIT if stream == "stdout" else STDERR_LIMIT
    redirect = "" if stream == "stdout" else " >&2"
    exact = run_wrapper(tmp_path, f"head -c {limit} /dev/zero | tr '\\0' x{redirect}; exit 3")
    assert exact.exit_code == 3
    assert unwrap_output(exact) == exact and TRUNCATION_MARKER not in exact.stderr
    assert len(getattr(exact, stream)) == limit

    cut = run_wrapper(tmp_path, f"head -c {limit + 1} /dev/zero | tr '\\0' x{redirect}; exit 3")
    assert cut.exit_code == 3 and cut.output_truncated is False
    unwrapped = unwrap_output(cut)
    assert unwrapped.output_truncated is True
    assert TRUNCATION_MARKER not in unwrapped.stderr
    assert getattr(unwrapped, stream) == "x" * limit
    assert unwrapped.exit_code == 3


async def test_cut_probe_output_is_truncated_evidence_and_never_qualifies():
    from infosec_harness.agent import TRUNCATION_MARKER

    claims = dict(target_reached=True, oracle_valid=True, positive_control=True,
                  negative_control=True, vulnerability_observed=True)
    shell = FakeOpenShell()
    native_execute = shell.execute

    async def execute(sandbox, command, **kwargs):
        await native_execute(sandbox, command, **kwargs)
        # A cut at the exact limit can leave a non-final marker line looking final.
        return CommandResult(0, "HARNESS_PROBE " + json.dumps(claims),
                             f"warning\n{TRUNCATION_MARKER}\n")

    shell.execute = execute
    returned = []

    def respond(messages, info):
        if not shell.executions:
            return ModelResponse(parts=[ToolCallPart(
                "run_probe", {"command": "python probe.py"}, tool_call_id="cut")])
        returned.extend(part.content for message in messages if isinstance(message, ModelRequest)
                        for part in message.parts
                        if isinstance(part, ToolReturnPart) and part.tool_name == "run_probe")
        return final_response(info)

    request = InvestigationRequest(finding=Finding(title="Sink", repo_url="fixture"))
    deps = InvestigationDeps(run_id="run", sandbox=await shell.create("run"),
                             source_digest="digest", snapshot_path="/fixture", request=request)
    await build_agent(shell, FunctionModel(respond)).run("Probe", deps=deps)
    evidence = returned[0]
    assert evidence.output_truncated is True
    assert evidence.stderr == "warning"
    assert evidence.observations["vulnerability_observed"] is True
    assert evidence.complete_verified_probe is False


async def test_failed_build_tool_returns_environment_feedback_once():
    """Live cohorts 7 and 8: after one failed mvn test the agent searched the filesystem and
    looped on javac until the budget ended. A failed build tool now points at the recipe."""
    shell = FakeOpenShell()
    native_execute = shell.execute

    async def execute(sandbox, command, **kwargs):
        await native_execute(sandbox, command, **kwargs)
        return CommandResult(1, "", "[ERROR] Could not resolve dependencies")

    shell.execute = execute
    seen = {}

    def respond(messages, info):
        if not shell.executions:
            return ModelResponse(parts=[ToolCallPart(
                "execute", {"command": "mvn test -Dtest=Probe"}, tool_call_id="build")])
        if len(shell.executions) == 1:
            returned = [part.content for message in messages if isinstance(message, ModelRequest)
                        for part in message.parts
                        if isinstance(part, ToolReturnPart) and part.tool_name == "execute"][-1]
            seen["build"] = returned.model_dump()["observations"]
            return ModelResponse(parts=[ToolCallPart(
                "execute", {"command": "ls -la src"}, tool_call_id="list")])
        returned = [part.content for message in messages if isinstance(message, ModelRequest)
                    for part in message.parts
                    if isinstance(part, ToolReturnPart) and part.tool_name == "execute"][-1]
        seen["list"] = returned.model_dump()["observations"]
        return final_response(info)

    request = InvestigationRequest(finding=Finding(title="Sink", repo_url="fixture"))
    deps = InvestigationDeps(run_id="run", sandbox=await shell.create("run"),
                             source_digest="digest", snapshot_path="/fixture", request=request)
    await build_agent(shell, FunctionModel(respond)).run("Inspect", deps=deps)
    assert "environment skill" in seen["build"]["environment_feedback"]
    assert "Do not search the filesystem" in seen["build"]["environment_feedback"]
    assert "environment_feedback" not in seen["list"]  # a failed plain command is not a build


async def test_probe_uses_fresh_offline_profile_and_cleans_up():
    shell = FakeOpenShell()

    def respond(messages, info):
        if not shell.executions:
            return ModelResponse(
                parts=[
                    ToolCallPart("run_probe", {"command": "python probe.py"}, tool_call_id="probe")
                ]
            )
        return final_response(info)

    agent = build_agent(shell, FunctionModel(respond))
    request = InvestigationRequest(finding=Finding(title="Sink", repo_url="fixture"))
    result = await agent.run(
        "Probe",
        deps=InvestigationDeps(
            run_id="run",
            sandbox=await shell.create("run"),
            source_digest="digest",
            snapshot_path="/fixture",
            request=request,
        ),
    )
    assert result.output.label == "inconclusive"
    assert shell.executions[0][0].profile == "probe"
    assert shell.closed == ["probe-probe:1:probe"]


async def test_read_argument_is_data_in_sandbox_not_a_worker_shell():
    shell = FakeOpenShell()

    def respond(messages, info):
        if not shell.executions:
            return ModelResponse(
                parts=[ToolCallPart("read", {"path": "$(echo hostile)"}, tool_call_id="read")]
            )
        return final_response(info)

    agent = build_agent(shell, FunctionModel(respond))
    request = InvestigationRequest(finding=Finding(title="Sink", repo_url="fixture"))
    await agent.run(
        "Read",
        deps=InvestigationDeps(
            run_id="run",
            sandbox=await shell.create("run"),
            source_digest="digest",
            snapshot_path="/fixture",
            request=request,
        ),
    )
    _, command, _, stdin = shell.executions[0]
    assert command[5:8] == ["python", "-I", "-c"]  # after the in-sandbox timeout wrapper
    assert json.loads(stdin)["path"] == "$(echo hostile)"


def test_probe_markers_require_exact_final_json_and_boolean_claims():
    from infosec_harness.agent import parse_probe_observations

    valid = {
        "target_reached": True,
        "oracle_valid": True,
        "positive_control": True,
        "negative_control": True,
        "vulnerability_observed": False,
    }
    marker = "HARNESS_PROBE " + json.dumps(valid)
    assert parse_probe_observations(marker)["origin"] == "self_reported"
    assert parse_probe_observations(marker + "\nextra output") == {}
    assert (
        parse_probe_observations("HARNESS_PROBE " + json.dumps({**valid, "target_reached": "true"}))
        == {}
    )
    assert (
        parse_probe_observations('HARNESS_PROBE {"target_reached":true,"target_reached":false}')
        == {}
    )


async def test_modified_source_refuses_probe_and_closes_offline_sandbox(tmp_path):
    from infosec_harness.sandbox import OpenShellError

    shell = FakeOpenShell()
    (tmp_path / "sink.py").write_text("original source\n")

    async def copy_workspace(workspace, probe, *, operation_id, expected_source):
        assert expected_source == tmp_path
        raise OpenShellError("Original source was modified in the workspace")

    shell.copy_workspace = copy_workspace

    def respond(messages, info):
        if not shell.executions:
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        "write",
                        {"path": "sink.py", "content": "fixed source"},
                        tool_call_id="write",
                    )
                ]
            )
        return ModelResponse(
            parts=[
                ToolCallPart("run_probe", {"command": "python negative.py"}, tool_call_id="probe")
            ]
        )

    agent = build_agent(shell, FunctionModel(respond))
    request = InvestigationRequest(finding=Finding(title="Sink", repo_url="fixture"))
    with pytest.raises(OpenShellError, match="Original source was modified"):
        await agent.run(
            "Inspect source",
            deps=InvestigationDeps(
                run_id="run",
                sandbox=await shell.create("run"),
                source_digest="digest",
                snapshot_path=str(tmp_path),
                request=request,
            ),
        )
    assert len(shell.executions) == 1
    assert shell.executions[0][0].profile == "workspace"
    assert shell.closed == ["probe-probe:2:probe"]


@pytest.mark.parametrize("definitive", [False, True])
async def test_output_feedback_repairs_exact_id_or_failed_probe_without_reexecuting(definitive):
    from pydantic_ai.messages import RetryPromptPart

    shell = FakeOpenShell()
    calls = 0

    def respond(messages, info):
        nonlocal calls
        calls += 1
        if calls == 1:
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        "execute", {"command": "python probe.py"}, tool_call_id="receipt-suffix"
                    )
                ]
            )
        if calls == 2:
            response = final_response(
                info, evidence_ids=["execute:1" if not definitive else "execute:1:receipt-suffix"]
            )
            if definitive:
                response.parts[0].args["label"] = "potentially_exploitable"
            return response
        feedback = [
            part.content
            for message in messages
            if isinstance(message, ModelRequest)
            for part in message.parts
            if isinstance(part, RetryPromptPart)
        ]
        assert feedback
        assert (
            "cannot support a definitive verdict" if definitive else "exact full Evidence.id"
        ) in feedback[-1]
        return final_response(info, evidence_ids=["execute:1:receipt-suffix"])

    request = InvestigationRequest(finding=Finding(title="Sink", repo_url="fixture"))
    result = await build_agent(shell, FunctionModel(respond)).run(
        "Inspect",
        deps=InvestigationDeps(
            run_id="run",
            sandbox=await shell.create("run"),
            source_digest="digest",
            snapshot_path="/fixture",
            request=request,
        ),
    )
    assert result.output.label == "inconclusive"
    assert calls == 3
    assert len(shell.executions) == 1


@pytest.mark.asyncio
async def test_validator_lets_a_newer_cited_probe_supersede_an_older_flawed_one():
    """Live case 'unreachable' (2026-10-05): an early buggy probe reported vulnerability_observed
    true, three corrected later probes reported false, and the verdict could never be admitted.
    The agent may disown only probes older than the cited one, and must name them."""
    from pydantic_ai import ModelRetry

    from infosec_harness.agent import validate_verdict
    from infosec_harness.models import Evidence, Verdict

    def probe(identity, observed):
        return Evidence(
            id=identity, kind="probe", command="python probe.py", exit_code=0,
            source_digest="digest", sandbox_id="offline",
            observations=dict(workspace_digest="w", origin="self_reported", source_verified=True,
                              target_reached=True, oracle_valid=True, positive_control=True,
                              negative_control=True, vulnerability_observed=observed),
        )

    flawed, corrected, later = probe("probe:6:a", True), probe("probe:9:b", False), probe("probe:12:c", True)
    ctx = SimpleNamespace(
        deps=SimpleNamespace(source_digest="digest"),
        messages=[ModelRequest(parts=[
            ToolReturnPart("run_probe", item.model_dump(), tool_call_id=item.id.split(":")[-1])
            for item in (flawed, corrected, later)])],
    )
    base = dict(label="likely_not_exploitable", summary="fixed query, flawed probe explained",
                evidence_ids=[corrected.id], citations=[dict(path="app.py", start_line=1, end_line=1)])
    # A later contrary probe blocks the verdict even when listed as superseded.
    with pytest.raises(ModelRetry, match="probe:12:c contradict.*cannot be superseded"):
        await validate_verdict(ctx, Verdict(**base, superseded_evidence_ids=[flawed.id, later.id]))
    ctx.messages[0].parts.pop()  # without the later probe, the older flawed one can be superseded
    with pytest.raises(ModelRetry, match="probe:6:a contradict"):
        await validate_verdict(ctx, Verdict(**base))
    accepted = Verdict(**base, superseded_evidence_ids=[flawed.id])
    assert await validate_verdict(ctx, accepted) == accepted
    with pytest.raises(ModelRetry, match="exact full Evidence.id"):
        await validate_verdict(ctx, Verdict(**base, superseded_evidence_ids=["probe:1:unknown"]))


@pytest.mark.parametrize(
    "failure",
    [
        None,
        "failed",
        "truncated",
        "unverified",
        "wrong-source",
        "controls",
        "target_reached",
        "oracle_valid",
        "positive_control",
        "contrary",
    ],
)
async def test_verdict_validator_requires_complete_matching_offline_evidence(failure):
    from pydantic_ai import ModelRetry

    from infosec_harness.agent import validate_verdict
    from infosec_harness.models import Evidence, Verdict

    observations = dict(
        workspace_digest="workspace",
        origin="self_reported",
        source_verified=True,
        target_reached=True,
        oracle_valid=True,
        positive_control=True,
        negative_control=True,
        vulnerability_observed=True,
    )
    if failure == "unverified":
        observations["source_verified"] = False
    if failure == "controls":
        observations["negative_control"] = False
    if failure in ("target_reached", "oracle_valid", "positive_control"):
        observations[failure] = False
    if failure == "contrary":
        observations["vulnerability_observed"] = False
    evidence = Evidence(
        id="probe:6:full-suffix",
        kind="probe",
        command="python probe.py",
        exit_code=1 if failure == "failed" else 0,
        output_truncated=failure == "truncated",
        source_digest="other" if failure == "wrong-source" else "digest",
        sandbox_id="offline",
        observations=observations,
    )
    ctx = SimpleNamespace(
        deps=SimpleNamespace(source_digest="digest"),
        messages=[
            ModelRequest(
                parts=[
                    ToolReturnPart("run_probe", evidence.model_dump(), tool_call_id="full-suffix")
                ]
            )
        ],
    )
    verdict = Verdict(
        label="potentially_exploitable",
        summary="Source-supported path",
        evidence_ids=[evidence.id],
        citations=[dict(path="sink.py", start_line=1, end_line=1)],
    )
    if failure == "target_reached":
        # A malformed exploratory citation must not hide the false target claim.
        exploratory = evidence.model_copy(update={"id": "probe:earlier", "observations": {}})
        ctx.messages[0].parts.append(
            ToolReturnPart("run_probe", exploratory.model_dump(), tool_call_id="earlier")
        )
        verdict.evidence_ids.append(exploratory.id)
    if failure:
        # Feedback must name the exact failing condition, not a generic rule restatement.
        match = {
            "failed": "is not a complete probe: exit code 1",
            "truncated": "output was truncated",
            "unverified": "is not source-verified",
            "wrong-source": "No run_probe evidence cited",
            "controls": "negative_control=false",
            "target_reached": "target_reached=false; target_reached is true when the real target",
            "oracle_valid": "oracle_valid=false",
            "positive_control": "positive_control=false",
            "contrary": "contradict potentially_exploitable",
        }[failure]
        with pytest.raises(ModelRetry, match=match):
            await validate_verdict(ctx, verdict)
    else:
        assert await validate_verdict(ctx, verdict) == verdict


async def test_output_feedback_is_bounded_and_never_retries_tool_dispatch():
    from pydantic_ai.exceptions import UnexpectedModelBehavior

    shell = FakeOpenShell()
    calls = 0

    def respond(messages, info):
        nonlocal calls
        calls += 1
        return final_response(info, evidence_ids=["invented"])

    request = InvestigationRequest(finding=Finding(title="Sink", repo_url="fixture"))
    with pytest.raises(UnexpectedModelBehavior, match="retries"):
        await build_agent(shell, FunctionModel(respond)).run(
            "Inspect",
            deps=InvestigationDeps(
                run_id="run",
                sandbox=await shell.create("run"),
                source_digest="digest",
                snapshot_path="/fixture",
                request=request,
            ),
        )
    assert calls == 3
    assert shell.executions == []


async def test_failed_offline_probe_and_successful_workspace_execution_require_inconclusive():
    from pydantic_ai.messages import RetryPromptPart

    shell = FakeOpenShell()
    native_execute = shell.execute

    async def execute(sandbox, command, **kwargs):
        result = await native_execute(sandbox, command, **kwargs)
        if sandbox.profile == "probe":
            return CommandResult(2, "", "python: can't open file '/tmp/probe.py'")
        return result

    shell.execute = execute
    calls = 0

    def respond(messages, info):
        nonlocal calls
        calls += 1
        if calls == 1:
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        "run_probe",
                        {"command": "cd /tmp && python probe.py"},
                        tool_call_id="offline",
                    )
                ]
            )
        if calls == 2:
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        "execute", {"command": "python probe.py"}, tool_call_id="workspace"
                    )
                ]
            )
        if calls == 3:
            response = final_response(info, evidence_ids=["probe:1:offline", "execute:2:workspace"])
            response.parts[0].args["label"] = "potentially_exploitable"
            response.parts[0].args["citations"] = [dict(path="sink.py", start_line=1, end_line=1)]
            return response
        assert any(
            isinstance(part, RetryPromptPart)
            and "is not a complete probe: exit code" in part.content
            for message in messages
            if isinstance(message, ModelRequest)
            for part in message.parts
        )
        return final_response(info, evidence_ids=["probe:1:offline", "execute:2:workspace"])

    request = InvestigationRequest(finding=Finding(title="Sink", repo_url="fixture"))
    result = await build_agent(shell, FunctionModel(respond)).run(
        "Inspect",
        deps=InvestigationDeps(
            run_id="run",
            sandbox=await shell.create("run"),
            source_digest="digest",
            snapshot_path="/fixture",
            request=request,
        ),
    )
    assert result.output.label == "inconclusive"
    assert len(shell.executions) == 2
    assert calls == 4
    assert shell.closed == ["probe-probe:1:offline"]


@pytest.mark.parametrize("final_line", [
    # Live cohort: Perl probes printed numeric claims and the agent spent its budget
    # on the generic "no parsed line" message.
    'HARNESS_PROBE {"target_reached":1,"oracle_valid":1,"positive_control":1,'
    '"negative_control":1,"vulnerability_observed":1}',
    "probe finished without a marker",
])
async def test_rejected_probe_line_gets_precise_feedback(final_line):
    from pydantic_ai.messages import RetryPromptPart

    from infosec_harness.agent import parse_probe_observations

    stdout = "context\n" * 2000 + final_line + "\n"  # longer than the tool-return excerpt
    assert parse_probe_observations(stdout) == {}
    rejected = final_line.startswith("HARNESS_PROBE ")
    shell = FakeOpenShell()
    native_execute = shell.execute

    async def execute(sandbox, command, **kwargs):
        await native_execute(sandbox, command, **kwargs)
        return CommandResult(0, stdout, "")

    shell.execute = execute
    calls = 0
    feedback = []

    def respond(messages, info):
        nonlocal calls
        calls += 1
        if calls == 1:
            return ModelResponse(parts=[ToolCallPart(
                "run_probe", {"command": "perl probe.pl"}, tool_call_id="p")])
        if calls == 2:
            returned = [part.content for message in messages if isinstance(message, ModelRequest)
                        for part in message.parts
                        if isinstance(part, ToolReturnPart) and part.tool_name == "run_probe"]
            assert returned[0].observations["report_excerpted"] is True
            assert returned[0].observations.get("probe_line_rejected", False) is rejected
            response = final_response(info, evidence_ids=["probe:1:p"])
            response.parts[0].args.update(
                label="potentially_exploitable",
                citations=[dict(path="sink.pl", start_line=1, end_line=1)],
            )
            return response
        feedback.extend(part.content for message in messages if isinstance(message, ModelRequest)
                        for part in message.parts if isinstance(part, RetryPromptPart))
        return final_response(info)

    request = InvestigationRequest(finding=Finding(title="Sink", repo_url="fixture"))
    deps = InvestigationDeps(run_id="run", sandbox=await shell.create("run"),
                             source_digest="digest", snapshot_path="/fixture", request=request)
    result = await build_agent(shell, FunctionModel(respond)).run("Probe", deps=deps)
    assert result.output.label == "inconclusive"
    message = feedback[-1]
    if rejected:
        assert "printed a final HARNESS_PROBE line that did not parse" in message
        assert "JSON boolean true or false" in message and "1/0" in message
        assert "vulnerability_observed" in message
        assert "has no parsed HARNESS_PROBE line" not in message
    else:
        assert "has no parsed HARNESS_PROBE line" in message
        assert "did not parse" not in message


async def test_split_probe_marker_feedback_repairs_with_new_bounded_probe():
    from pydantic_ai.messages import RetryPromptPart

    from infosec_harness.agent import parse_probe_observations

    observations = dict(
        target_reached=True,
        oracle_valid=True,
        positive_control=True,
        negative_control=True,
        vulnerability_observed=True,
    )
    split_marker = (
        json.dumps({**observations, "details": "observed controls"}) + "\nHARNESS_PROBE\n"
    )
    assert parse_probe_observations(split_marker) == {}
    shell = FakeOpenShell()
    native_execute = shell.execute

    async def execute(sandbox, command, **kwargs):
        await native_execute(sandbox, command, **kwargs)
        stdout = (
            split_marker
            if len(shell.executions) == 1
            else "HARNESS_PROBE " + json.dumps(observations) + "\n"
        )
        return CommandResult(0, stdout, "")

    shell.execute = execute
    calls = 0

    def respond(messages, info):
        nonlocal calls
        calls += 1
        if calls in (1, 3):
            if calls == 3:
                feedback = [
                    part.content
                    for message in messages
                    if isinstance(message, ModelRequest)
                    for part in message.parts
                    if isinstance(part, RetryPromptPart)
                ]
                # The computed reason names the parse failure and the exact line contract.
                assert "has no parsed HARNESS_PROBE line" in feedback[-1]
                assert "share the final stdout line" in feedback[-1]
                assert "run a new corrected probe" in feedback[-1]
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        "run_probe",
                        {"command": "python probe.py"},
                        tool_call_id="split" if calls == 1 else "repaired",
                    )
                ]
            )
        response = final_response(
            info, evidence_ids=["probe:1:split" if calls == 2 else "probe:3:repaired"]
        )
        response.parts[0].args.update(
            label="potentially_exploitable",
            citations=[dict(path="sink.py", start_line=1, end_line=1)],
        )
        return response

    request = InvestigationRequest(finding=Finding(title="Sink", repo_url="fixture"))
    result = await build_agent(shell, FunctionModel(respond)).run(
        "Inspect",
        deps=InvestigationDeps(
            run_id="run",
            sandbox=await shell.create("run"),
            source_digest="digest",
            snapshot_path="/fixture",
            request=request,
        ),
    )
    assert result.output.label == "potentially_exploitable"
    assert result.output.evidence_ids == ["probe:3:repaired"]
    assert len(shell.executions) == 2
    assert calls == 4
    assert shell.executions[0][2] != shell.executions[1][2]


async def test_blocked_target_feedback_requires_new_complete_probe():
    from pydantic_ai.messages import RetryPromptPart

    shell = FakeOpenShell()
    native_execute = shell.execute
    observations = dict(
        target_reached=False,
        oracle_valid=True,
        positive_control=True,
        negative_control=True,
        vulnerability_observed=False,
    )

    async def execute(sandbox, command, **kwargs):
        await native_execute(sandbox, command, **kwargs)
        # Mocked process evidence: normal read succeeds; the real callable rejects traversal.
        claims = {**observations, "target_reached": len(shell.executions) > 1}
        return CommandResult(
            0, "normal read OK; traversal BLOCKED\nHARNESS_PROBE " + json.dumps(claims), ""
        )

    shell.execute = execute
    calls = 0

    def respond(messages, info):
        nonlocal calls
        calls += 1
        if calls in (1, 3):
            if calls == 3:
                feedback = [
                    part.content
                    for message in messages
                    if isinstance(message, ModelRequest)
                    for part in message.parts
                    if isinstance(part, RetryPromptPart)
                ][-1]
                assert "target_reached=false" in feedback
                assert "even if its guard rejected it" in feedback
                assert "run a new corrected probe" in feedback
                assert "do not relabel" in feedback
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        "run_probe",
                        {"command": "python probe.py"},
                        tool_call_id="blocked" if calls == 1 else "repaired",
                    )
                ]
            )
        response = final_response(
            info, evidence_ids=["probe:1:blocked" if calls == 2 else "probe:3:repaired"]
        )
        response.parts[0].args.update(
            label="likely_not_exploitable",
            citations=[dict(path="reader.py", start_line=1, end_line=1)],
        )
        return response

    request = InvestigationRequest(finding=Finding(title="Traversal", repo_url="fixture"))
    result = await build_agent(shell, FunctionModel(respond)).run(
        "Inspect",
        deps=InvestigationDeps(
            run_id="run",
            sandbox=await shell.create("run"),
            source_digest="digest",
            snapshot_path="/fixture",
            request=request,
        ),
    )
    assert result.output.label == "likely_not_exploitable"
    assert result.output.evidence_ids == ["probe:3:repaired"]
    assert len(shell.executions) == 2
    assert calls == 4
    assert shell.executions[0][2] != shell.executions[1][2]


@pytest.mark.parametrize("failure", ["unsafe", "unknown", "boundary", "source"])
async def test_post_probe_integrity_failure_recovery_is_narrow(failure):
    from infosec_harness.sandbox import (
        ExecutionUnknown,
        OpenShellError,
        UnsafeSnapshotMetadata,
    )

    shell = FakeOpenShell()
    native_execute = shell.execute
    claims = dict(
        target_reached=True,
        oracle_valid=True,
        positive_control=True,
        negative_control=True,
        vulnerability_observed=False,
    )

    async def execute(sandbox, command, **kwargs):
        await native_execute(sandbox, command, **kwargs)
        return CommandResult(0, "HARNESS_PROBE " + json.dumps(claims), "")

    errors = {
        "unsafe": UnsafeSnapshotMetadata("source snapshot contains unsafe archive metadata"),
        "unknown": ExecutionUnknown("source snapshot has an unknown prior outcome"),
        "boundary": OpenShellError("source native identity changed"),
        "source": OpenShellError("workspace changed or deleted original source"),
    }

    async def verify_source(sandbox, *, expected_source, operation_id):
        if len(shell.executions) == 1:
            raise errors[failure]

    shell.execute = execute
    shell.verify_source = verify_source
    calls = 0

    def respond(messages, info):
        nonlocal calls
        calls += 1
        if calls == 1:
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        "run_probe",
                        {"command": "python probe.py"},
                        tool_call_id="unsafe" if calls == 1 else "corrected",
                    )
                ]
            )
        if calls == 2:
            returned = [
                part.content
                for message in messages
                if isinstance(message, ModelRequest)
                for part in message.parts
                if isinstance(part, ToolReturnPart) and part.tool_name == "run_probe"
            ][-1]
            returned = returned.model_dump()
            assert returned["id"] == "probe:1:unsafe"
            assert returned["exit_code"] == 0
            assert returned["observations"]["source_verified"] is False
            assert "not source-verified" in returned["observations"]["integrity_feedback"]
            assert "not retried" in returned["observations"]["integrity_feedback"]
        if calls == 3:
            # The invalid probe cannot qualify even with matching claims and citations.
            from pydantic_ai.messages import RetryPromptPart

            feedback = [
                part.content
                for message in messages
                if isinstance(message, ModelRequest)
                for part in message.parts
                if isinstance(part, RetryPromptPart)
            ][-1]
            assert "source-verified" in feedback
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        "run_probe",
                        {"command": "python corrected.py"},
                        tool_call_id="corrected",
                    )
                ]
            )
        response = final_response(
            info, evidence_ids=["probe:1:unsafe" if calls == 2 else "probe:3:corrected"]
        )
        response.parts[0].args.update(
            label="likely_not_exploitable",
            citations=[dict(path="sink.py", start_line=1, end_line=1)],
        )
        return response

    request = InvestigationRequest(finding=Finding(title="Sink", repo_url="fixture"))
    deps = InvestigationDeps(
        run_id="run",
        sandbox=await shell.create("run"),
        source_digest="digest",
        snapshot_path="/fixture",
        request=request,
    )
    agent = build_agent(shell, FunctionModel(respond))
    if failure == "unsafe":
        result = await agent.run("Inspect", deps=deps)
        assert result.output.label == "likely_not_exploitable"
        assert result.output.evidence_ids == ["probe:3:corrected"]
        assert len(shell.executions) == 2
        assert calls == 4
        assert shell.closed == ["probe-probe:1:unsafe", "probe-probe:3:corrected"]
        assert shell.executions[0][2] != shell.executions[1][2]
    else:
        with pytest.raises(type(errors[failure]), match=str(errors[failure])):
            await agent.run("Inspect", deps=deps)
        assert len(shell.executions) == 1
        assert calls == 1
        assert shell.closed == ["probe-probe:1:unsafe"]


async def test_refused_probe_after_original_source_change_is_feedback_not_failure():
    """Live cohort 4, case deserialization-fixed (2026-10-05): the agent overwrote app.py, the
    pre-copy integrity check refused the probe, and the whole investigation failed. The refusal
    stays; it now returns bounded feedback the agent can act on, with no receipt to cite."""
    from pydantic_ai.messages import RetryPromptPart

    from infosec_harness.sandbox import OpenShellError

    shell = FakeOpenShell()

    async def copy_workspace(workspace, probe, *, operation_id, expected_source):
        raise OpenShellError("workspace changed or deleted original source: app.py")

    shell.copy_workspace = copy_workspace
    calls = 0

    def respond(messages, info):
        nonlocal calls
        calls += 1
        if calls == 1:
            return ModelResponse(parts=[ToolCallPart(
                "run_probe", {"command": "python probe.py"}, tool_call_id="refused")])
        if calls == 2:
            returned = [part.content for message in messages if isinstance(message, ModelRequest)
                        for part in message.parts
                        if isinstance(part, ToolReturnPart) and part.tool_name == "run_probe"][-1]
            returned = returned.model_dump()
            assert returned["id"] == "probe:1:refused" and returned["exit_code"] is None
            assert returned["observations"]["source_verified"] is False
            assert "app.py" in returned["observations"]["integrity_feedback"]
            assert "did not run" in returned["observations"]["integrity_feedback"]
            return final_response(info, evidence_ids=["probe:1:refused"])
        feedback = [part.content for message in messages if isinstance(message, ModelRequest)
                    for part in message.parts if isinstance(part, RetryPromptPart)][-1]
        assert "exact full Evidence.id" in feedback  # a refused probe has no receipt to cite
        return final_response(info)

    request = InvestigationRequest(finding=Finding(title="Sink", repo_url="fixture"))
    deps = InvestigationDeps(run_id="run", sandbox=await shell.create("run"),
                             source_digest="digest", snapshot_path="/fixture", request=request)
    result = await build_agent(shell, FunctionModel(respond)).run("Inspect", deps=deps)
    assert result.output.label == "inconclusive" and result.output.evidence_ids == []
    assert shell.executions == [] and calls == 3
    assert shell.closed == ["probe-probe:1:refused"]


async def test_tool_return_evidence_keeps_history_shape_and_bounds():
    """Tool returns are durable history: pin exact bytes, 4096-byte bounds and flag order."""
    from pydantic_core import to_json

    shell = FakeOpenShell()
    native_execute = shell.execute
    claims = dict(
        target_reached=True,
        oracle_valid=True,
        positive_control=True,
        negative_control=True,
        vulnerability_observed=False,
    )
    # An odd leading byte puts the 4096-byte cut inside a two-byte character.
    stdout = "x" + "é" * 3000 + "\nHARNESS_PROBE " + json.dumps(claims)

    async def execute(sandbox, command, **kwargs):
        await native_execute(sandbox, command, **kwargs)
        return CommandResult(0, stdout, "err")

    shell.execute = execute
    returned = []

    def respond(messages, info):
        if not shell.executions:
            return ModelResponse(
                parts=[ToolCallPart("execute", {"command": "c" * 5000}, tool_call_id="cmd")]
            )
        if len(shell.executions) == 1:
            return ModelResponse(
                parts=[ToolCallPart("run_probe", {"command": "python p.py"}, tool_call_id="p")]
            )
        returned.extend(
            part.content
            for message in messages
            if isinstance(message, ModelRequest)
            for part in message.parts
            if isinstance(part, ToolReturnPart)
        )
        return final_response(info)

    await build_agent(shell, FunctionModel(respond)).run(
        "Inspect",
        deps=InvestigationDeps(
            run_id="run",
            sandbox=await shell.create("run"),
            source_digest="digest",
            snapshot_path="/fixture",
            request=InvestigationRequest(finding=Finding(title="Sink", repo_url="fixture")),
        ),
    )
    output = {"exit_code": 0, "stdout": "x" + "é" * 2047, "stderr": "err", "timed_out": False}
    expected = [
        {
            "id": "execute:1:cmd",
            "kind": "command",
            "command": "c" * 4096,
            **output,
            "output_truncated": False,
            "sandbox_id": "workspace-",
            "source_digest": "digest",
            "observations": {"report_excerpted": True},
        },
        {
            "id": "probe:2:p",
            "kind": "probe",
            "command": "python p.py",
            **output,
            "output_truncated": False,
            "sandbox_id": "probe-probe:2:p",
            "source_digest": "digest",
            "observations": {
                **claims,
                "origin": "self_reported",
                "report_excerpted": True,
                "workspace_digest": "workspace-digest",
                "source_verified": True,
            },
        },
    ]
    assert [to_json(item) for item in returned] == [
        json.dumps(item, separators=(",", ":"), ensure_ascii=False).encode() for item in expected
    ]


def test_definitive_support_requires_citations_cited_match_and_no_contrary():
    from infosec_harness.models import Citation, Evidence, Verdict, definitive_support

    def probe(identity, observed, **changes):
        return Evidence(
            id=identity,
            kind="probe",
            command="probe",
            exit_code=0,
            sandbox_id="probe",
            source_digest="digest",
            observations={
                "target_reached": True,
                "oracle_valid": True,
                "positive_control": True,
                "negative_control": True,
                "vulnerability_observed": observed,
                "workspace_digest": "workspace-digest",
                "source_verified": True,
                **changes,
            },
        )

    cited = [Citation(path="sink.py", start_line=1, end_line=1)]
    verdict = Verdict(label="potentially_exploitable", summary="s", evidence_ids=["a"])
    matching, contrary = probe("a", True), probe("b", False)
    incomplete = probe("c", False, negative_control=False)
    assert definitive_support(verdict, [matching]) == (False, [])
    verdict = verdict.model_copy(update={"citations": cited})
    assert definitive_support(verdict, [matching, incomplete]) == (True, [])
    assert definitive_support(verdict, [probe("z", True)]) == (False, [])
    assert definitive_support(verdict, [matching, contrary]) == (True, [contrary])
