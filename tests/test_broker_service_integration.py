"""Explicit layer B: real HTTPS processes, real Postgres, mocked native lifecycle only."""
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

from infosec_harness.inference.auth import AUTH_HEADER, sign_request
from infosec_harness.inference.protocol import (
    BrokerError,
    InvocationRequest,
    canonical_bytes,
    digest,
)
from infosec_harness.persistence import db


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
        from infosec_harness.agents.registry import load_spec, resolve_agent_config
        from infosec_harness.inference.invocations import request_invocation
        from infosec_harness.inference.transport import BrokerModel
        config = resolve_agent_config("context", load_spec("context"), durable=False)
        run_id = str(uuid.uuid4())
        binding = await request_invocation(InvocationRequest(mode="local", root_id=digest({"local_run": run_id}),
            run_id=run_id, invocation_id=run_id + ":context", operation_id=run_id + ":context",
            agent="context", configuration_digest=config.digest, contract=config.model.broker_contract))
        channel = self.values["pki"]
        return BrokerModel(contract=config.model.broker_contract, binding=binding,
            controller_url=self.values["controller_url"], secret_env="BROKER_QUALIFICATION_WORKER_KEY",
            ca_file=channel["ca"], client_cert=channel["client_cert"], client_key=channel["client_key"],
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
    with pytest.raises(httpx.HTTPError):
        await services.post("/v1/invocations", {}, cert=False)
    response = await services.post("/v1/invocations", {}, sign=False)
    assert response.status_code == 401
    assert response.json() == {"error": "auth"}
    assert len(services.events()) == before
    services.record("tls_hmac_denials", before)


async def test_registered_local_context_round_trips_worker_tool_and_structured_output(services):
    from infosec_harness.agents.deps import AgentDeps
    from infosec_harness.graph.ops import LocalOps
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
    from infosec_harness.agents.deps import AgentDeps
    from infosec_harness.agents.registry import build_agent, load_spec, resolve_agent_config
    from infosec_harness.inference.invocations import eval_invocation
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
