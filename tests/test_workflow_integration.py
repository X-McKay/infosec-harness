"""End-to-end: the triage graph runs inside real Temporal workflows with durable agents.

Uses a local Temporal dev server and stub models. The Docker sandbox is faked at the
activity boundary so the test needs neither a daemon nor a registry.
"""

from __future__ import annotations

import asyncio
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
    """A probe that reached the sink, returned, and observed nothing — a clean negative.

    Both markers matter: without the sink-returned one the graph would correctly treat this as
    a probe defect and enter its repair loop.

    The prepare-phase canary comes through the same door and is asking a different question --
    can a test written by the harness run here and be heard at all -- so for its nonce the
    double echoes all three markers. Answering the canary with a clean negative would say "this
    environment cannot carry a marker", which is not what this fixture is modelling.
    """
    from infosec_harness.sandbox.canary import CANARY_NONCE
    from infosec_harness.sandbox.docker import (
        ORACLE_PREFIX,
        PRECONDITION_PREFIX,
        SINK_RETURNED_PREFIX,
        ProcResult,
    )

    stdout = f"{PRECONDITION_PREFIX}{nonce}\n{SINK_RETURNED_PREFIX}{nonce}\n"
    if nonce == CANARY_NONCE:
        stdout += f"{ORACLE_PREFIX}{nonce}\n"
    return ProcResult(exit_code=0, stdout=stdout, stderr="", timed_out=False, duration_s=0.1)


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


async def test_durable_acceptance_restart_results_and_history_replay(fixture_repo, monkeypatch):
    """A submitter can disappear; a replacement worker persists outputs and replays history."""
    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from temporalio.client import Client
    from temporalio.testing import WorkflowEnvironment
    from temporalio.worker import Replayer, Worker

    from infosec_harness.domain.models import FindingInput
    from infosec_harness.persistence import db, lifecycle, store
    from infosec_harness.sandbox import docker
    from infosec_harness.settings import get_settings
    from infosec_harness.workflows.activities import ALL_ACTIVITIES
    from infosec_harness.workflows.worker import WORKFLOWS
    from infosec_harness.workflows.workflows import TriageBatchWorkflow

    monkeypatch.setattr(get_settings(), "recipe_cache_enabled", False)
    monkeypatch.setattr(get_settings(), "root_max_tokens", 100_000_000)
    monkeypatch.setattr(get_settings(), "root_max_requests", 10000)
    monkeypatch.setattr(docker, "image_exists", lambda tag: _true())
    monkeypatch.setattr(docker, "run_probe", _fake_probe)
    monkeypatch.setattr(docker, "run_shell", _fake_shell)
    monkeypatch.setattr(docker, "runtime_available", lambda runtime=None: _true())
    await db.create_all()
    batch_id = f"recovery-{uuid.uuid4().hex[:10]}"
    finding = FindingInput(title="Recovery fixture", repo_url=fixture_repo, file_path="app.py",
                           start_line=2, cwe="CWE-89", severity="high")
    payload = {"batch_id": batch_id, "findings": [finding.model_dump(mode="json")]}
    await lifecycle.accept_batch(batch_id, [finding, finding], "Recovery", payload)
    env = await WorkflowEnvironment.start_local(dev_server_existing_path=temporal_bin)
    try:
        client = await Client.connect(env.client.service_client.config.target_host,
                                      plugins=[PydanticAIPlugin()])
        # Start with no worker. Acceptance survives; a new worker can pick up the queue.
        handle = await client.start_workflow(TriageBatchWorkflow.run, payload,
            id=f"batch:{batch_id}", task_queue="durability-test")
        async with Worker(client, task_queue="durability-test", workflows=WORKFLOWS,
                          activities=ALL_ACTIVITIES):
            outputs = await handle.result()
        detail = await store.get_run(store._run_id(batch_id, outputs[0].finding.fingerprint))
        assert detail["status"] == "complete"
        assert detail["telemetry"]["wall_time_s"] > 0
        assert detail["evidence"]["executions"]
        assert {"recon", "env-planner", "context", "verdict"} <= {
            i["agent"] for i in detail["invocations"]}
        assert len(await store.list_runs(batch_id=batch_id)) == 1
        assert (await store.batch_summary(batch_id))["status"] == "complete"
        history = await handle.fetch_history()
        await Replayer(workflows=WORKFLOWS, plugins=[PydanticAIPlugin()]).replay_workflow(history)
    finally:
        await env.shutdown()


async def test_finding_failure_preserves_completed_invocations_and_budget_reason(
    fixture_repo, monkeypatch,
):
    """A later budget failure cannot erase earlier paid finding-stage calls."""
    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from pydantic_ai.exceptions import UsageLimitExceeded
    from temporalio.client import Client
    from temporalio.testing import WorkflowEnvironment
    from temporalio.worker import Worker

    from infosec_harness.domain.models import FindingInput, InconclusiveReason
    from infosec_harness.integrations import ado
    from infosec_harness.persistence import db, lifecycle, store
    from infosec_harness.sandbox import docker
    from infosec_harness.settings import get_settings
    from infosec_harness.workflows.activities import ALL_ACTIVITIES
    from infosec_harness.workflows.temporal_ops import TemporalOps
    from infosec_harness.workflows.worker import WORKFLOWS
    from infosec_harness.workflows.workflows import TriageBatchWorkflow

    monkeypatch.setattr(get_settings(), "recipe_cache_enabled", False)
    monkeypatch.setattr(docker, "image_exists", lambda tag: _true())
    monkeypatch.setattr(docker, "run_probe", _fake_probe)
    monkeypatch.setattr(docker, "run_shell", _fake_shell)
    monkeypatch.setattr(docker, "runtime_available", lambda runtime=None: _true())
    monkeypatch.setattr(get_settings(), "ado_writeback_enabled", True)
    writebacks = []

    async def fake_post(work_item_id, text, comment_id):
        writebacks.append((work_item_id, comment_id))
        return 9002

    monkeypatch.setattr(ado, "post_or_update_comment", fake_post)
    original = TemporalOps._run_agent

    async def fail_verdict(self, name, prompt, deps):
        if name == "verdict":
            raise UsageLimitExceeded("finding-stage root budget exhausted")
        return await original(self, name, prompt, deps)

    monkeypatch.setattr(TemporalOps, "_run_agent", fail_verdict)
    await db.create_all()
    batch_id = f"partial-{uuid.uuid4().hex[:10]}"
    finding = FindingInput(title="Partial finding", repo_url=fixture_repo, file_path="app.py",
                           start_line=2, cwe="CWE-89", severity="high", ado_work_item_id=43)
    payload = {"batch_id": batch_id, "findings": [finding.model_dump(mode="json")]}
    await lifecycle.accept_batch(batch_id, [finding], "Partial failure", payload)
    env = await WorkflowEnvironment.start_local(dev_server_existing_path=temporal_bin)
    try:
        client = await Client.connect(env.client.service_client.config.target_host,
                                      plugins=[PydanticAIPlugin()])
        async with Worker(client, task_queue="partial-failure", workflows=WORKFLOWS,
                          activities=ALL_ACTIVITIES):
            outputs = await client.execute_workflow(TriageBatchWorkflow.run, payload,
                id=f"batch:{batch_id}", task_queue="partial-failure")
        output = outputs[0]
        assert output.result.verdict.inconclusive_reason is InconclusiveReason.budget_exhausted
        assert "context" in {inv.agent for inv in output.invocations}
        assert "verdict" not in {inv.agent for inv in output.invocations}
        detail = await store.get_run(store._run_id(batch_id, output.finding.fingerprint))
        assert "context" in {inv["agent"] for inv in detail["invocations"]}
        assert writebacks == [(43, None)]
    finally:
        await env.shutdown()


async def test_cancellation_during_optional_writeback_cancels_batch(fixture_repo, monkeypatch):
    """Cancelling blocked ADO postprocessing still cancels the durable workflow."""
    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from temporalio.client import Client, WorkflowFailureError
    from temporalio.testing import WorkflowEnvironment
    from temporalio.worker import Worker

    from infosec_harness.domain.models import FindingInput
    from infosec_harness.integrations import ado
    from infosec_harness.persistence import db, lifecycle, store
    from infosec_harness.sandbox import docker
    from infosec_harness.settings import get_settings
    from infosec_harness.workflows.activities import ALL_ACTIVITIES
    from infosec_harness.workflows.worker import WORKFLOWS
    from infosec_harness.workflows.workflows import TriageBatchWorkflow

    monkeypatch.setattr(get_settings(), "recipe_cache_enabled", False)
    monkeypatch.setattr(get_settings(), "root_max_tokens", 100_000_000)
    monkeypatch.setattr(get_settings(), "root_max_requests", 10000)
    monkeypatch.setattr(get_settings(), "ado_writeback_enabled", True)
    monkeypatch.setattr(docker, "image_exists", lambda tag: _true())
    monkeypatch.setattr(docker, "run_probe", _fake_probe)
    monkeypatch.setattr(docker, "run_shell", _fake_shell)
    monkeypatch.setattr(docker, "runtime_available", lambda runtime=None: _true())
    entered = asyncio.Event()

    async def blocked_post(work_item_id, text, comment_id):
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(ado, "post_or_update_comment", blocked_post)
    await db.create_all()
    batch_id = f"writeback-cancel-{uuid.uuid4().hex[:10]}"
    finding = FindingInput(title="Blocked writeback", repo_url=fixture_repo, file_path="app.py",
                           start_line=2, cwe="CWE-89", severity="high", ado_work_item_id=44)
    payload = {"batch_id": batch_id, "findings": [finding.model_dump(mode="json")]}
    await lifecycle.accept_batch(batch_id, [finding], "Blocked writeback", payload)
    env = await WorkflowEnvironment.start_local(dev_server_existing_path=temporal_bin)
    try:
        client = await Client.connect(env.client.service_client.config.target_host,
                                      plugins=[PydanticAIPlugin()])
        async with Worker(client, task_queue="writeback-cancel", workflows=WORKFLOWS,
                          activities=ALL_ACTIVITIES):
            handle = await client.start_workflow(TriageBatchWorkflow.run, payload,
                id=f"batch:{batch_id}", task_queue="writeback-cancel")
            await asyncio.wait_for(entered.wait(), timeout=30)
            await handle.cancel()
            with pytest.raises(WorkflowFailureError):
                await asyncio.wait_for(handle.result(), timeout=30)
        assert (await store.batch_summary(batch_id))["status"] == "cancelled"
    finally:
        await env.shutdown()


async def test_durable_polyglot_components_prepare_independent_environments(fixture_repo, monkeypatch):
    import json

    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from temporalio.client import Client
    from temporalio.testing import WorkflowEnvironment
    from temporalio.worker import Worker

    from infosec_harness.domain.models import FindingInput
    from infosec_harness.persistence import db, lifecycle, store
    from infosec_harness.sandbox import docker
    from infosec_harness.settings import get_settings
    from infosec_harness.workflows.activities import ALL_ACTIVITIES
    from infosec_harness.workflows.worker import WORKFLOWS
    from infosec_harness.workflows.workflows import TriageBatchWorkflow

    root = Path(fixture_repo)
    (root / "services/api").mkdir(parents=True)
    (root / "services/api/requirements.txt").write_text("pytest\n")
    (root / "services/api/app.py").write_text("def target():\n    return 1\n")
    (root / "web").mkdir()
    (root / "web/package.json").write_text(json.dumps({"devDependencies": {"jest": "29.7.0"}}))
    (root / "web/app.js").write_text("export function target() { return 1; }\n")
    monkeypatch.setattr(get_settings(), "recipe_cache_enabled", False)
    monkeypatch.setattr(docker, "image_exists", lambda tag: _true())
    monkeypatch.setattr(docker, "run_probe", _fake_probe)
    monkeypatch.setattr(docker, "run_shell", _fake_shell)
    monkeypatch.setattr(docker, "runtime_available", lambda runtime=None: _true())
    await db.create_all()
    batch_id = f"components-{uuid.uuid4().hex[:10]}"
    findings = [FindingInput(title=path, repo_url=fixture_repo, file_path=path, start_line=1,
                              cwe="CWE-89", severity="high")
                for path in ("services/api/app.py", "web/app.js")]
    payload = {"batch_id": batch_id, "findings": [f.model_dump(mode="json") for f in findings]}
    await lifecycle.accept_batch(batch_id, findings, "Component fixture", payload)
    env = await WorkflowEnvironment.start_local(dev_server_existing_path=temporal_bin)
    try:
        client = await Client.connect(env.client.service_client.config.target_host,
                                      plugins=[PydanticAIPlugin()])
        async with Worker(client, task_queue="components-test", workflows=WORKFLOWS,
                          activities=ALL_ACTIVITIES):
            outputs = await client.execute_workflow(TriageBatchWorkflow.run, payload,
                id=f"batch:{batch_id}", task_queue="components-test")
        environments = [output.manifest["environment"] for output in outputs]
        assert [environment["module_path"] for environment in environments] == ["services/api", "web"]
        assert environments[0]["base_image"].startswith("python:")
        assert environments[1]["base_image"].startswith("node:")
        assert all(output.prepared_status == "ready" for output in outputs)
        assert all(sum(inv.agent == "recon" for inv in output.invocations) == 1 for output in outputs)
        assert len(await store.list_runs(batch_id=batch_id)) == 2
    finally:
        await env.shutdown()
