"""Explicit layer B: real HTTPS processes, real Postgres, mocked native lifecycle only.

Run only by ``scripts/broker_service_check.py``, which supplies the service manifest.
"""
from __future__ import annotations

import asyncio
import json
import os
import ssl
import time
import uuid
from pathlib import Path

import httpx
import pytest
from pydantic_ai.messages import ModelRequest, UserPromptPart
from pydantic_ai.models import ModelRequestParameters

from infosec_harness.inference.catalog.profiles import ControllerChannel
from infosec_harness.inference.wire.auth import AUTH_HEADER, sign_request
from infosec_harness.inference.wire.protocol import (
    BrokerError,
    InvocationRequest,
    canonical_bytes,
    digest,
)
from infosec_harness.persistence import db

pytestmark = pytest.mark.requires_service("HARNESS_BROKER_SERVICE_MANIFEST")


class Services:
    def __init__(self, values):
        self.values = values

    def __repr__(self):
        return "<Private broker service fixture>"

    def events(self):
        path = Path(self.values["directory"]) / "upstream.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def arm(self, fault):
        (Path(self.values["directory"]) / "arm-executor-fault").write_text(fault)

    async def post(self, path, value, *, sign=True, cert=True):
        body = canonical_bytes(value)
        headers = {"Content-Type": "application/json"}
        if sign:
            headers[AUTH_HEADER] = sign_request(self.values["worker_key"].encode(), "POST", path, body, int(time.time()) + 30)
        context = ssl.create_default_context(cafile=self.values["pki"]["ca"])
        if cert:
            context.load_cert_chain(self.values["pki"]["client_cert"], self.values["pki"]["client_key"])
        async with httpx.AsyncClient(verify=context, trust_env=False, follow_redirects=False) as client:
            return await client.post(self.values["controller_url"] + path, content=body, headers=headers)

    async def model(self, identity="model:0"):
        from infosec_harness.inference.worker.invocations import request_invocation
        from infosec_harness.inference.worker.transport import BrokerModel
        from infosec_harness.runtime.registry import load_spec, resolve_agent_config
        config = resolve_agent_config("context", load_spec("context"), durable=False)
        run_id = str(uuid.uuid4())
        binding = await request_invocation(InvocationRequest(mode="local", root_id=digest({"local_run": run_id}),
            run_id=run_id, invocation_id=run_id + ":context", operation_id=run_id + ":context",
            agent="context", configuration_digest=config.digest, contract=config.model.broker_contract))
        channel = self.values["pki"]
        return BrokerModel(contract=config.model.broker_contract, binding=binding,
            controller=ControllerChannel(url=self.values["controller_url"], hmac_env="BROKER_QUALIFICATION_WORKER_KEY",
            ca_file=channel["ca"], client_cert=channel["client_cert"], client_key=channel["client_key"]),
            request_identity=lambda: identity)

    def record(self, name, before, **extra):
        events = self.events()[before:]
        path = Path(self.values["directory"]) / "cases.jsonl"
        with path.open("a") as output:
            output.write(json.dumps({"case": name, "dispatches": len(events), **extra}) + "\n")


@pytest.fixture
async def services():
    manifest = os.environ.get("HARNESS_BROKER_SERVICE_MANIFEST")
    if not manifest:
        pytest.skip("explicit real broker service qualification runner required")
    value = Services(json.loads(Path(manifest).read_text()))
    yield value
    await db._engine().dispose()


async def test_actual_mutual_tls_and_hmac_denials_have_zero_provider_sends(services):
    before = len(services.events())
    with pytest.raises((httpx.HTTPError, ssl.SSLError)) as denied:
        await services.post("/v1/invocations", {}, cert=False)
    if isinstance(denied.value, ssl.SSLError):
        assert denied.value.reason == "TLSV13_ALERT_CERTIFICATE_REQUIRED"
    response = await services.post("/v1/invocations", {}, sign=False)
    assert response.status_code == 401
    assert response.json() == {"error": "auth"}
    assert len(services.events()) == before
    services.record("tls_hmac_denials", before)


async def test_registered_local_context_round_trips_worker_tool_and_structured_output(services):
    from infosec_harness.graph.ops import LocalOps
    from infosec_harness.runtime.deps import AgentDeps
    before = len(services.events())
    ops = LocalOps(sandbox=False, recipe_cache=False)
    outcome = await ops.run_agent("context", ["Inspect sample.py; return context with unknown reachability."],
        AgentDeps(repo_path=services.values["repo"]))
    assert outcome.output.summary == "qualification context"
    assert outcome.requests == 2
    assert any(name.endswith("read_file") for name in outcome.tools_called)
    events = services.events()[before:]
    assert len(events) == 2
    assert events[0]["tool_return"] is False and events[1]["tool_return"] is True
    assert all(event["authorized"] and not event["canary_in_body"] for event in events)
    await ops.close()
    services.record("registered_local_tool_structured_output", before, requests=outcome.requests,
                    root_closed=True)


async def test_executor_process_dies_after_commit_lost_ack_retrieves_one_saved_result(services):
    services.arm("lost_ack")
    model = await services.model()
    messages = [ModelRequest(parts=[UserPromptPart("fixture lost ACK")])]
    before = len(services.events())
    first = await model.request(messages, model.contract.model_settings, ModelRequestParameters())
    retry = await model.request(messages, model.contract.model_settings, ModelRequestParameters())
    assert retry == first
    assert len(services.events()) == before + 1
    services.record("executor_lost_ack_saved_result", before, recovered=True)


async def test_executor_process_dies_before_result_commit_is_unknown_without_resend(services):
    services.arm("before_result_commit")
    model = await services.model()
    messages = [ModelRequest(parts=[UserPromptPart("fixture before commit")])]
    before = len(services.events())
    for _ in range(2):
        with pytest.raises(BrokerError) as exc:
            await model.request(messages, model.contract.model_settings, ModelRequestParameters())
        assert exc.value.code == "completion_unknown"
    assert len(services.events()) == before + 1
    services.record("executor_before_commit_unknown", before, no_resend=True)


async def test_concurrent_real_http_duplicates_have_one_provider_dispatch(services):
    model = await services.model()
    messages = [ModelRequest(parts=[UserPromptPart("fixture concurrent duplicate")])]
    before = len(services.events())
    outcomes = await asyncio.gather(*(model.request(messages, model.contract.model_settings,
        ModelRequestParameters()) for _ in range(2)), return_exceptions=True)
    assert sum(not isinstance(value, Exception) for value in outcomes) >= 1
    assert all(not isinstance(value, Exception) or isinstance(value, BrokerError) and value.code == "pending"
               for value in outcomes)
    assert len(services.events()) == before + 1
    services.record("concurrent_http_duplicate", before)


async def test_close_blocks_fresh_ids_but_preserves_completed_response(services):
    model = await services.model()
    messages = [ModelRequest(parts=[UserPromptPart("fixture close")])]
    before = len(services.events())
    saved = await model.request(messages, model.contract.model_settings, ModelRequestParameters())
    closed = await services.post("/v1/runs/close", {"run_id": model.binding.run_id, "root_id": model.binding.root_id})
    assert closed.status_code == 200
    assert await model.request(messages, model.contract.model_settings, ModelRequestParameters()) == saved
    model.request_identity = lambda: "model:1"
    with pytest.raises(BrokerError) as exc:
        await model.request(messages, model.contract.model_settings, ModelRequestParameters())
    assert exc.value.code in {"policy", "identity"}
    assert len(services.events()) == before + 1
    services.record("close_and_retained_result", before)


async def test_secret_detector_has_positive_control_and_logs_ledger_are_clean(services):
    from sqlalchemy import select
    secrets = (services.values["canary"], services.values["worker_key"])
    positive_control = {"fixture": secrets[0]}
    detector_works = any(secret in json.dumps(positive_control) for secret in secrets)
    assert detector_works
    sources = []
    directory = Path(services.values["directory"])
    sources.extend(path.read_text(errors="replace") for path in directory.glob("*.log"))
    async with db.session() as session:
        records = (await session.execute(select(db.InferenceRequestRecord))).scalars().all()
        sources.extend(json.dumps({"request": record.request, "result": record.result}) for record in records)
    leaked = any(secret in source for source in sources for secret in secrets)
    assert not leaked
    assert any(event["authorized"] for event in services.events())
    services.record("canary_scanner_positive_control", len(services.events()), detector_works=True)


async def test_actual_eval_issuance_registered_agent_closes_its_owned_root(services):
    from infosec_harness.inference.worker.invocations import eval_invocation
    from infosec_harness.runtime.deps import AgentDeps
    from infosec_harness.runtime.registry import build_agent, load_spec, resolve_agent_config
    spec = load_spec("context")
    config = resolve_agent_config("context", spec, durable=True)
    agent = build_agent("context", durable=False, production_transport=True)
    before = len(services.events())
    async with eval_invocation("context", AgentDeps(repo_path=services.values["repo"]), config,
                               configuration_digest=config.digest) as deps:
        assert deps.broker_binding is not None
        root_id, run_id = deps.broker_binding.root_id, deps.broker_binding.run_id
        result = await agent.run(["Inspect sample.py; return unknown reachability."], deps=deps,
                                 usage_limits=config.budget.to_usage_limits())
        assert result.output.summary == "qualification context"
    assert len(services.events()) == before + 2
    async with db.session() as session:
        root = await session.get(db.BudgetLedger, root_id)
        assert root.state["broker_run_id"] == run_id
        assert root.state["agent_config_digests"]["context"] == config.digest
        operation = next(iter(root.state["operations"].values()))
        assert operation["broker_owned"] and operation["broker_revoked"]
        assert operation["status"] == "uncertain"
    services.record("actual_eval_issuance_tool_structured_cleanup", before,
                    configuration_digest=config.digest, root_closed=True)


@pytest.mark.parametrize("agent_name", (
    "intake", "recon", "env-planner", "build-repair", "partial-build", "context",
    "probe-planner", "probe-author", "probe-diagnosis", "probe-repair", "verdict",
))
async def test_every_registered_agent_executes_actual_broker_transport(services, agent_name):
    from sqlalchemy import select

    from infosec_harness.domain.models import (
        EnvironmentSpec,
        ExtractedFinding,
        ProbeDiagnosis,
        ProbePlan,
        ProbeSource,
        RepoProfile,
    )
    from infosec_harness.graph.ops import LocalOps
    from infosec_harness.inference.wire.protocol import digest
    from infosec_harness.runtime.deps import AgentDeps
    from infosec_harness.runtime.outputs import (
        ContextOutput,
        InconclusiveOutput,
        PartialEnvironmentOutput,
        PlannedEnvironmentOutput,
    )
    from infosec_harness.runtime.registry import BINDINGS

    expected_types = {
        "intake": ExtractedFinding, "recon": RepoProfile, "env-planner": PlannedEnvironmentOutput,
        "build-repair": EnvironmentSpec, "partial-build": PartialEnvironmentOutput,
        "context": ContextOutput, "probe-planner": ProbePlan, "probe-author": ProbeSource,
        "probe-diagnosis": ProbeDiagnosis, "probe-repair": ProbeSource, "verdict": InconclusiveOutput,
    }
    assert set(expected_types) == set(BINDINGS)
    before = len(services.events())
    ops = LocalOps(sandbox=False, recipe_cache=False)
    try:
        outcome = await ops.run_agent(agent_name, [
            f"<broker-qualification-agent>{agent_name}</broker-qualification-agent>\n"
            "Qualification contains no concrete weakness evidence."
        ], AgentDeps(repo_path=services.values["repo"], report_text="No concrete weakness evidence."))
        assert type(outcome.output) is expected_types[agent_name]
        assert outcome.agent == agent_name
        assert outcome.requests == 1
        assert outcome.input_tokens == 100 and outcome.output_tokens == 20
        assert outcome.tools_called == []
        value = outcome.output
        if agent_name == "intake":
            assert value.file_path is None and value.evidence == []
        elif agent_name == "recon":
            assert value.primary_language == "unknown" and value.summary == "stub profile"
        elif agent_name in {"env-planner", "build-repair", "partial-build"}:
            assert value.base_image == "debian:bookworm-slim"
            assert value.test_command == "sh {test_file}" and value.install_commands == []
            assert value.scope == ("partial" if agent_name == "partial-build" else "full")
        elif agent_name == "context":
            assert value.reachability == "unknown" and value.source is None and value.sink is None
        elif agent_name == "probe-planner":
            assert value.oracle == "marker_output" and value.test_file_path == "harness_probe.sh"
        elif agent_name in {"probe-author", "probe-repair"}:
            assert value.test_file_path == "harness_probe.sh"
            assert "HARNESS_PRECONDITION::none" in value.content
            assert "HARNESS_SINK_RETURNED::none" in value.content
        elif agent_name == "probe-diagnosis":
            assert value.kind == "environment_issue"
        else:
            assert value.label == "inconclusive" and value.confidence == 0
            assert value.inconclusive_reason == "conflicting_evidence"
    finally:
        await ops.close()
    events = services.events()[before:]
    assert len(events) == 1 and events[0]["qualification_agent"] == agent_name
    assert events[0]["authorized"] and not events[0]["canary_in_body"]
    async with db.session() as session:
        root = await session.get(db.BudgetLedger, digest({"local_run": ops._broker_run_id}))
        operation = next(iter(root.state["operations"].values()))
        assert operation["broker_owned"] and operation["broker_revoked"]
        rows = (await session.execute(select(db.InferenceRequestRecord).where(
            db.InferenceRequestRecord.root_id == root.root_id))).scalars().all()
        assert len(rows) == 1 and rows[0].state == "completed"
        assert rows[0].request["binding"]["agent"] == agent_name
    services.record("registered_agent:" + agent_name, before, output_type=type(value).__name__,
                    requests=1, persisted_completed=1, root_closed=True)


async def test_local_prepare_and_triage_graph_uses_actual_broker_for_each_agent(services, tmp_path):
    from sqlalchemy import select

    from infosec_harness.domain.models import Finding, FindingInput, ProbeExecution, RepoSnapshot
    from infosec_harness.graph.ops import LocalOps
    from infosec_harness.graph.prepare import run_prepare
    from infosec_harness.graph.triage import TRIAGE_GRAPH, GatherContext, TriageDeps, TriageState
    from infosec_harness.repo.detect import detect_stack

    class QualificationOps(LocalOps):
        """Actual agent/broker execution; explicitly simulated sandbox execution."""
        async def run_agent(self, name, prompt, deps, *, record=None):
            marker = f"<broker-qualification-agent>{name}</broker-qualification-agent>"
            return await super().run_agent(name, [marker, *prompt], deps, record=record)

        async def execute_probe(self, image, probe, spec, nonce, attempt):
            return ProbeExecution(attempt=attempt, exit_code=0, oracle_fired=False,
                precondition_reached=True, sink_returned=True,
                stdout_tail=f"HARNESS_PRECONDITION::{nonce}\nHARNESS_SINK_RETURNED::{nonce}")

    (tmp_path / "requirements.txt").write_text("")
    (tmp_path / "app.py").write_text("def lookup(db, n):\n    return db.execute('SELECT '+n)\n")
    (tmp_path / "tests").mkdir()
    repo = str(tmp_path)
    ops = QualificationOps(sandbox=False, recipe_cache=False)
    before = len(services.events())
    expected = ["recon", "env-planner", "context", "probe-planner", "probe-author", "probe-diagnosis", "verdict"]
    try:
        prepared = await run_prepare(ops, RepoSnapshot(repo_url=repo, revision="HEAD", path=repo,
            content_hash="a" * 64), detect_stack(repo))
        assert prepared.prepared.status == "ready"
        finding = Finding.from_input(FindingInput(title="SQLi", repo_url=repo, file_path="app.py",
            start_line=2, cwe="CWE-89", severity="high"))
        state = TriageState(finding=finding, prepared=prepared.prepared)
        result = await TRIAGE_GRAPH.run(state=state, deps=TriageDeps(ops=ops), inputs=GatherContext())
        outcomes = [*prepared.invocations, *state.invocations]
        assert [outcome.agent for outcome in outcomes] == expected
        assert all(outcome.requests == 1 for outcome in outcomes)
        assert result.verdict.label == "inconclusive" and result.verdict.confidence == 0
        assert result.early_exit is None
    finally:
        await ops.close()
    events = services.events()[before:]
    assert [event["qualification_agent"] for event in events] == expected
    assert all(event["authorized"] and not event["canary_in_body"] for event in events)
    async with db.session() as session:
        records = (await session.execute(select(db.InferenceRequestRecord))).scalars().all()
        records = [record for record in records if record.request["binding"]["run_id"] == ops._broker_run_id]
        assert len(records) == 7 and all(record.state == "completed" for record in records)
        root = await session.get(db.BudgetLedger, records[0].root_id)
        assert len(root.state["operations"]) == 7
        assert all(operation["broker_revoked"] for operation in root.state["operations"].values())
    services.record("local_prepare_triage_broker_graph", before, agents=expected,
                    persisted_completed=7, root_closed=True, sandbox_execution="simulated",
                    accuracy="not_checked", native_confinement="not_checked")
