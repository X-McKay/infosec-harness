"""The read, search and write tools keep model-authored paths as data inside the sandbox."""

import json

from fakes import FakeOpenShell, final_response
from pydantic_ai.messages import ModelResponse, ToolCallPart
from pydantic_ai.models.function import FunctionModel

from infosec_harness.agents.investigator import InvestigationDeps, build_agent
from infosec_harness.contracts import Finding, InvestigationRequest


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
