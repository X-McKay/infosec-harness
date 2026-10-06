"""Shared test doubles. A fake adapter or model is never isolation or quality evidence."""

from pydantic_ai.messages import ModelResponse, ToolCallPart

from infosec_harness.sandbox import CommandResult, ExecutionReceipt, Sandbox


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
            ExecutionReceipt(sandbox, operation_id, "fake-request", command, result)
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


# Agent and tool test helpers. Imports stay local so this block only appends to the module.


def tool_returns(messages, name=None):
    """Contents of the tool returns in ``messages`` (one tool's when ``name`` is given)."""
    from pydantic_ai.messages import ModelRequest, ToolReturnPart

    return [
        part.content
        for message in messages
        if isinstance(message, ModelRequest)
        for part in message.parts
        if isinstance(part, ToolReturnPart) and name in (None, part.tool_name)
    ]


def retry_feedback(messages):
    """Contents of the retry prompts (validator feedback) in ``messages``."""
    from pydantic_ai.messages import ModelRequest, RetryPromptPart

    return [
        part.content
        for message in messages
        if isinstance(message, ModelRequest)
        for part in message.parts
        if isinstance(part, RetryPromptPart)
    ]


async def make_deps(shell, **overrides):
    """Investigation deps for run "run" on ``shell``'s workspace sandbox; override any field."""
    from infosec_harness.agents.deps import InvestigationDeps
    from infosec_harness.contracts import Finding, InvestigationRequest

    if "sandbox" not in overrides:
        overrides["sandbox"] = await shell.create("run")
    defaults = dict(
        run_id="run",
        source_digest="digest",
        snapshot_path="/fixture",
        request=InvestigationRequest(finding=Finding(title="Sink", repo_url="fixture")),
    )
    return InvestigationDeps(**{**defaults, **overrides})
