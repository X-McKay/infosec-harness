"""End-to-end: the triage graph runs inside real Temporal workflows with durable agents.

Uses a local Temporal dev server and stub models. The Docker sandbox is faked at the
activity boundary so the test needs neither a daemon nor a registry.
"""

from __future__ import annotations

import shutil
import tempfile
import uuid
from pathlib import Path

import pytest

temporal_bin = shutil.which("temporal")
pytestmark = pytest.mark.skipif(temporal_bin is None, reason="temporal CLI not available")


@pytest.fixture
def fixture_repo():
    repo = tempfile.mkdtemp(prefix="harness-itest-")
    Path(repo, "requirements.txt").write_text("")
    Path(repo, "app.py").write_text(
        "def lookup(db, name):\n"
        "    return db.execute(\"SELECT * FROM u WHERE n='\" + name + \"'\")\n"
    )
    Path(repo, "tests").mkdir()
    yield repo
    shutil.rmtree(repo, ignore_errors=True)


async def _fake_build(snapshot_path, spec, tag):
    from infosec_harness.sandbox.docker import ProcResult

    return ProcResult(exit_code=0, stdout="built", stderr="", timed_out=False, duration_s=0.1)


async def _fake_probe(image, test_file_path, content, test_command, nonce, module_path=""):
    from infosec_harness.sandbox.docker import PRECONDITION_PREFIX, ProcResult

    return ProcResult(exit_code=0, stdout=f"{PRECONDITION_PREFIX}{nonce}\n", stderr="",
                      timed_out=False, duration_s=0.1)


async def _fake_shell(image, command, *, network, timeout=None):
    from infosec_harness.sandbox.docker import ProcResult

    return ProcResult(exit_code=0, stdout="harness-smoke-ok", stderr="", timed_out=False, duration_s=0.0)


async def test_batch_workflow_end_to_end(fixture_repo, monkeypatch):
    monkeypatch.setenv("HARNESS_MODEL_MODE", "stub")
    from infosec_harness.sandbox import docker

    monkeypatch.setattr(docker, "image_exists", lambda tag: _true(), raising=True)
    monkeypatch.setattr(docker, "build_image", _fake_build, raising=True)
    monkeypatch.setattr(docker, "run_probe", _fake_probe, raising=True)
    monkeypatch.setattr(docker, "run_shell", _fake_shell, raising=True)
    async def _rt(runtime=None):
        return True
    monkeypatch.setattr(docker, "runtime_available", _rt, raising=True)

    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from temporalio.client import Client
    from temporalio.testing import WorkflowEnvironment
    from temporalio.worker import Worker

    from infosec_harness.domain.models import FindingInput, VerdictLabel
    from infosec_harness.workflows.activities import ALL_ACTIVITIES
    from infosec_harness.workflows.worker import WORKFLOWS

    # The dev server occasionally misses its 5s startup window under load; retry.
    env = None
    for attempt in range(3):
        try:
            env = await WorkflowEnvironment.start_local(dev_server_existing_path=temporal_bin)
            break
        except RuntimeError:
            if attempt == 2:
                raise
    try:
        client = await Client.connect(env.client.service_client.config.target_host,
                                      plugins=[PydanticAIPlugin()])
        finding = FindingInput(title="SQLi in lookup", repo_url=fixture_repo, revision="HEAD",
                               file_path="app.py", start_line=2, cwe="CWE-89", severity="high")
        async with Worker(client, task_queue="triage", workflows=WORKFLOWS, activities=ALL_ACTIVITIES):
            from infosec_harness.workflows.workflows import TriageBatchWorkflow

            out = await client.execute_workflow(
                TriageBatchWorkflow.run, {"findings": [finding.model_dump()]},
                id=f"itest-{uuid.uuid4()}", task_queue="triage",
            )
        assert len(out) == 1
        run = out[0]
        assert run.prepared_status == "ready"
        assert run.result.verdict.label in set(VerdictLabel)
        agents = [i.agent for i in run.invocations]
        assert "context" in agents and "verdict" in agents
        assert run.result.fingerprint == run.finding.fingerprint
    finally:
        await env.shutdown()


async def _true():
    return True
