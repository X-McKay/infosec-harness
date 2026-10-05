"""The single investigator's native tools and receipt boundary."""

import json
from types import SimpleNamespace

import pytest
from pydantic_ai.messages import ModelRequest, ModelResponse, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import FunctionModel

from infosec_harness.agent import InvestigationDeps, build_agent
from infosec_harness.models import Finding, InvestigationRequest
from infosec_harness.openshell import CommandResult, Sandbox


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
    assert shell.executions[0][1] == [
        "/bin/bash",
        "-lc",
        "cd /workspace/repo && pytest test_sink.py",
    ]


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
    assert command[:3] == ["python", "-I", "-c"]
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
    from infosec_harness.openshell import OpenShellError

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
