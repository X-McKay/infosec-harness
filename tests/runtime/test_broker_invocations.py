"""Independent issuance and codec boundary tests, using trusted injected catalogs only."""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid
from copy import deepcopy
from datetime import datetime
from types import SimpleNamespace

import httpx
import pytest
from pydantic_ai import messages as m
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.models import ModelRequestParameters

from infosec_harness.agents import models
from infosec_harness.inference import codec, invocations
from infosec_harness.inference.protocol import (
    BrokerError,
    ExecutorContract,
    InvocationRequest,
    ReservationBinding,
    canonical_bytes,
    digest,
)
from infosec_harness.inference.transport import BrokerModel
from infosec_harness.persistence import budgets, db


@pytest.fixture
async def issuance(monkeypatch):
    await db.create_all()
    contract = ExecutorContract(backend="mock", model="mock-model", profile="inference-only",
        profile_digest="a" * 64, endpoint="https://provider.test/v1", provider_binding="mock-provider",
        executor_image="sha256:" + "a" * 64, supervisor_image="sha256:" + "b" * 64,
        policy_digest="c" * 64, model_settings={"max_tokens": 100})
    root_limits = SimpleNamespace(max_requests=2, max_input_tokens=10_000,
        max_output_tokens=200, max_cost_usd=2, max_duration_seconds=600)
    bounds = SimpleNamespace(max_requests=1, max_input_tokens=5000,
        max_output_tokens=100, max_cost_usd=1, max_duration_seconds=300)
    catalog = SimpleNamespace(root_limits=root_limits, bounds_for_agent=lambda name: bounds)
    monkeypatch.setattr(models, "broker_catalog", lambda: catalog)
    monkeypatch.setattr(models, "custom_prices", lambda name: models.Prices(
        input_per_mtok=2, output_per_mtok=4, cache_read_per_mtok=0.2, cache_write_per_mtok=5))
    monkeypatch.setattr(invocations, "trusted_config", lambda name, durable: SimpleNamespace(
        digest=f"config-{name}-{durable}",
        model=SimpleNamespace(broker_contract=contract, resolved_model="mock:mock-model")))
    run_id = uuid.uuid4().hex
    request = InvocationRequest(mode="local", root_id=digest({"local_run": run_id}),
        run_id=run_id, invocation_id=f"{run_id}:context:0", operation_id=f"{run_id}:context:0",
        agent="context", configuration_digest="config-context-False", contract=contract)
    yield request, catalog
    await db._engine().dispose()


async def test_local_root_and_binding_are_issued_once_without_deadline_renewal(issuance):
    request, _ = issuance
    first = await invocations.issue_invocation(request)
    async with db.session() as session:
        root = await session.get(db.BudgetLedger, request.root_id)
        initial = deepcopy(root.state)
    retry = await invocations.issue_invocation(request)
    assert retry == first
    async with db.session() as session:
        root = await session.get(db.BudgetLedger, request.root_id)
        assert root.state["deadline_at"] == initial["deadline_at"]
        assert len(root.state["operations"]) == 1
        assert root.state["operations"][request.operation_id]["run_id"] == request.run_id
        assert root.state["operations"][request.operation_id]["invocation_id"] == request.invocation_id
    assert first.expires_at == datetime.fromisoformat(initial["deadline_at"]).timestamp()


@pytest.mark.parametrize("changes", [
    {"configuration_digest": "worker-forged"}, {"root_id": "unrelated-root"},
    {"contract": None},
])
async def test_forged_config_root_or_model_is_not_authority(issuance, changes):
    request, _ = issuance
    if changes.get("contract", "absent") is None:
        changes = {"contract": request.contract.model_copy(update={"model": "other-model"})}
    forged = request.model_copy(update=changes)
    with pytest.raises(BrokerError) as exc:
        await invocations.issue_invocation(forged)
    assert exc.value.code == "identity"
    async with db.session() as session:
        assert await session.get(db.BudgetLedger, request.root_id) is None


async def test_concurrent_local_invocations_share_one_root_ceiling(issuance):
    request, _ = issuance
    gate = asyncio.Event()
    arrived = 0

    async def issue(index):
        nonlocal arrived
        arrived += 1
        if arrived == 3:
            gate.set()
        await gate.wait()
        selected = request.model_copy(update={"invocation_id": f"inv-{index}", "operation_id": f"op-{index}"})
        return await invocations.issue_invocation(selected)
    outcomes = await asyncio.gather(*(issue(i) for i in range(3)), return_exceptions=True)
    assert sum(isinstance(value, ReservationBinding) for value in outcomes) == 2
    assert sum(isinstance(value, UsageLimitExceeded) for value in outcomes) == 1
    async with db.session() as session:
        root = await session.get(db.BudgetLedger, request.root_id)
        assert len(root.state["operations"]) == 2
        assert sum(op["reserved"]["requests"] for op in root.state["operations"].values()) == 2


async def test_temporal_requires_exact_preexisting_run_and_invocation_owner(issuance):
    request, _ = issuance
    await invocations.issue_invocation(request)
    temporal = request.model_copy(update={"mode": "temporal", "configuration_digest": "config-context-True"})
    async with db.session() as session:
        root = await session.get(db.BudgetLedger, request.root_id)
        state = deepcopy(root.state)
        state["agent_config_digests"]["context"] = "config-context-True"
        state["operations"][request.operation_id].pop("broker_binding")
        state["operations"][request.operation_id].pop("broker_configuration_digest")
        root.state = state
        await session.commit()
    binding = await invocations.issue_invocation(temporal)
    assert binding.run_id == request.run_id
    for changes in ({"run_id": "foreign-run"}, {"invocation_id": "foreign-invocation"},
                    {"operation_id": "absent"}):
        with pytest.raises(BrokerError) as exc:
            await invocations.issue_invocation(temporal.model_copy(update=changes))
        assert exc.value.code == "identity"


async def test_temporal_cannot_create_a_missing_root(issuance):
    request, _ = issuance
    with pytest.raises(BrokerError) as exc:
        await invocations.issue_invocation(request.model_copy(update={"mode": "temporal",
            "configuration_digest": "config-context-True"}))
    assert exc.value.code == "identity"
    async with db.session() as session:
        assert await session.get(db.BudgetLedger, request.root_id) is None


async def test_issued_binding_retry_after_deadline_preserves_original_reference(issuance, monkeypatch):
    request, _ = issuance
    saved = await invocations.issue_invocation(request)
    monkeypatch.setattr(budgets, "_remaining_time", lambda deadline: (_ for _ in ()).throw(
        UsageLimitExceeded("Root elapsed-time budget exhausted")))
    assert await invocations.issue_invocation(request) == saved


def test_custom_price_ceiling_covers_cache_write_rate(issuance):
    request, _ = issuance
    policy = invocations.build_reservation_policy(request)
    assert policy.input_per_mtok == 5
    assert policy.output_per_mtok == 4


def test_missing_reviewed_custom_price_blocks_issuance_policy(issuance, monkeypatch):
    request, _ = issuance
    monkeypatch.setattr(models, "custom_prices", lambda name: None)
    with pytest.raises(BrokerError) as exc:
        invocations.build_reservation_policy(request)
    assert exc.value.code == "budget"


def test_broker_factory_without_binding_never_constructs_provider(monkeypatch):
    cfg = models.ModelsConfig(backends={"mock": models.BackendConfig(
        transport="brokered", kind="openai_compatible", base_url="https://provider.test/v1")},
        default_backend="mock", model_catalog={})
    monkeypatch.setattr(models, "get_settings", lambda: SimpleNamespace(model_mode="live"))
    monkeypatch.setattr(models, "load_models_config", lambda: cfg)
    monkeypatch.setattr(models, "_build_live", lambda *args, **kwargs: pytest.fail("Provider constructed"))
    for factory in (models.resolve, models.resolve_intake_atomic):
        with pytest.raises(BrokerError) as exc:
            factory("context", "mock-model")
        assert exc.value.code == "identity"


def test_direct_resolved_model_digest_omits_optional_broker_field():
    direct = models.ResolvedModelConfig(mode="stub", backend_name="stub", backend_kind="stub",
        requested_model="test", resolved_model="stub:test", capability_profile=models.CapabilityProfile(),
        pricing_table="stub", pricing_status="known_zero")
    old_shape = direct.model_dump(mode="json")
    assert "broker_contract" not in old_shape
    expected = hashlib.sha256(json.dumps(old_shape, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]
    assert direct.digest == expected


@pytest.mark.parametrize("content", [
    m.ImageUrl(url="https://remote.test/image.png"),
    m.BinaryContent(data=b"image", media_type="image/png"),
    ["text", m.ImageUrl(url="https://remote.test/image.png")],
])
def test_tool_return_multimodal_cannot_bypass_user_prompt_guard(content):
    message = m.ModelRequest(parts=[m.ToolReturnPart(tool_name="read", tool_call_id="call1", content=content)])
    with pytest.raises(BrokerError) as exc:
        codec.encode_payload([message], {"max_tokens": 100}, ModelRequestParameters())
    assert exc.value.code == "policy"


async def test_saved_result_can_be_retrieved_after_binding_deadline(issuance, monkeypatch):
    request, _ = issuance
    monkeypatch.setenv("BROKER_RECOVERY_TEST_KEY", "q" * 32)
    calls = 0
    binding = ReservationBinding(root_id=request.root_id, run_id=request.run_id,
        invocation_id=request.invocation_id, operation_id=request.operation_id, agent=request.agent,
        contract_digest=request.contract.digest, expires_at=time.time() - 1)
    from infosec_harness.inference.codec import encode_response
    from infosec_harness.inference.protocol import InferenceRequest, InferenceResult

    def saved_result(incoming):
        nonlocal calls
        calls += 1
        selected = InferenceRequest.model_validate_json(incoming.content)
        result = InferenceResult(request_id=selected.request_id,
            response=encode_response(m.ModelResponse(parts=[m.TextPart("saved")], model_name="mock-model")))
        return httpx.Response(200, content=canonical_bytes(result.model_dump(mode="json")))
    model = BrokerModel(contract=request.contract, binding=binding,
        controller_url="https://controller.test", secret_env="BROKER_RECOVERY_TEST_KEY",
        ca_file=None, client_cert=None, client_key=None, request_identity=lambda: "model:0",
        http_transport=httpx.MockTransport(saved_result))
    response = await model.request([m.ModelRequest(parts=[m.UserPromptPart("same")])],
        request.contract.model_settings, ModelRequestParameters())
    assert response.parts[0].content == "saved"
    assert calls == 1  # Retrieval channel only; no provider is constructed.


@pytest.mark.parametrize("content", [
    m.ImageUrl(url="https://remote.test/image.png"),
    m.BinaryContent(data=b"image", media_type="image/png"),
])
def test_tool_return_wire_media_rejected_before_provider_mapping(content):
    from infosec_harness.inference.protocol import InferencePayload
    messages = [m.ModelRequest(parts=[m.ToolReturnPart(tool_name="read", tool_call_id="call1", content=content)])]
    payload = InferencePayload(messages=m.ModelMessagesTypeAdapter.dump_python(messages, mode="json"),
        parameters={}, model_settings={"max_tokens": 100})
    with pytest.raises(BrokerError) as exc:
        codec.decode_payload(payload)
    assert exc.value.code == "policy"


@pytest.mark.parametrize("extra", ["unknown", "headers", "base_url"])
def test_nested_typed_fields_cannot_be_silently_dropped(extra):
    from infosec_harness.inference.protocol import InferencePayload
    payload = InferencePayload(messages=[{"kind":"request", "parts": [{"part_kind":"user-prompt",
        "content":"text", extra:"untrusted"}]}], parameters={}, model_settings={"max_tokens":100})
    with pytest.raises(BrokerError):
        codec.decode_payload(payload)


@pytest.mark.parametrize("field", ["input_per_mtok", "cache_write_per_mtok", "cache_read_per_mtok"])
def test_negative_custom_price_is_not_a_reviewed_ceiling(issuance, monkeypatch, field):
    request, _ = issuance
    values = {"input_per_mtok":2, "output_per_mtok":4, "cache_write_per_mtok":5, "cache_read_per_mtok":0.2}
    values[field] = -1
    monkeypatch.setattr(models, "custom_prices", lambda name: models.Prices(**values))
    with pytest.raises(BrokerError) as exc:
        invocations.build_reservation_policy(request)
    assert exc.value.code == "budget"


async def test_eval_issuance_uses_production_identity_on_a_bounded_local_root(issuance):
    request, _ = issuance
    request = request.model_copy(update={"mode": "eval",
                                       "configuration_digest": "config-context-True"})
    binding = await invocations.issue_invocation(request)
    assert binding.run_id == request.run_id and binding.contract_digest == request.contract.digest
    async with db.session() as session:
        root = await session.get(db.BudgetLedger, request.root_id)
        assert root.state["agent_config_digests"]["context"] == "config-context-True"
        assert root.state["operations"][request.operation_id]["broker_owned"]
