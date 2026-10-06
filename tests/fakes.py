"""Shared test doubles. A fake adapter or model is never isolation or quality evidence."""

from types import SimpleNamespace

from pydantic_ai.messages import ModelResponse, ToolCallPart

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
