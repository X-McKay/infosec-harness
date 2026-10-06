"""The execute and run_probe tools: bounded native commands, offline probes and receipts."""

import json

import pytest
from fakes import FakeOpenShell, final_response
from pydantic_ai.messages import ModelRequest, ModelResponse, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import FunctionModel

from infosec_harness.agents.investigator import InvestigationDeps, build_agent
from infosec_harness.contracts import Finding, InvestigationRequest
from infosec_harness.sandbox import CommandResult


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

    from infosec_harness.tools.execute import _SHELL_WRAPPER

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
    from infosec_harness.tools.execute import (
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
    from infosec_harness.tools.execute import TRUNCATION_MARKER

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

    from infosec_harness.sandbox import SourceChanged

    shell = FakeOpenShell()

    async def copy_workspace(workspace, probe, *, operation_id, expected_source):
        raise SourceChanged("workspace changed or deleted original source: app.py")

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
