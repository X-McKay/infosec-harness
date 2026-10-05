"""Independently preserve cumulative tool-loop budgets and exact request brakes."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from infosec_harness.agents import models
from infosec_harness.inference.catalog.profiles import ExecutorProfile
from infosec_harness.inference.controller import issuance
from infosec_harness.inference.wire.protocol import digest


def test_omitted_request_cap_preserves_existing_profile_digest():
    profile = ExecutorProfile()
    legacy = profile.model_dump(mode="json", exclude={"backend_name", "min_max_tokens",
                                                      "max_input_tokens_per_request"})
    assert profile.profile_digest == digest(legacy)
    assert "max_input_tokens_per_request" not in profile.model_dump(mode="json")
    assert profile.model_copy(update={"max_input_tokens_per_request": 100000}).profile_digest != profile.profile_digest


@pytest.mark.parametrize("value", [0, -1, True, 100000.0, "100000"])
def test_request_cap_requires_an_explicit_positive_integer(value):
    with pytest.raises(ValidationError):
        ExecutorProfile(max_input_tokens_per_request=value)


@pytest.mark.parametrize("operator_cap,authored_cap,cumulative,expected", [
    (100000, 60000, 600000, 60000),
    (40000, 60000, 600000, 40000),
    (100000, 60000, 30000, 30000),
    (None, 60000, 600000, 600000),
])
def test_trusted_request_policy_is_independent_of_cumulative_invocation(monkeypatch,
        operator_cap, authored_cap, cumulative, expected):
    contract = SimpleNamespace(profile="context", digest="contract", model_settings={"max_tokens": 18000})
    config = SimpleNamespace(digest="config", model=SimpleNamespace(
        broker_contract=contract, resolved_model="qwen"), budget=SimpleNamespace(
        effective=SimpleNamespace(max_input_tokens_per_request=authored_cap)))
    bounds = SimpleNamespace(max_input_tokens=cumulative, max_output_tokens=180000,
                             max_cost_usd=1.0)
    profile = ExecutorProfile(max_input_tokens_per_request=operator_cap)
    catalog = SimpleNamespace(bounds_for_agent=lambda _: bounds,
                              profile_for_agent=lambda _: ("context", profile))
    monkeypatch.setattr(models, "broker_catalog", lambda: catalog)
    monkeypatch.setattr(models, "custom_prices", lambda _: models.Prices(
        input_per_mtok=0.0, output_per_mtok=0.0))
    monkeypatch.setattr(issuance, "trusted_config", lambda *_, **__: config)
    request = SimpleNamespace(binding=SimpleNamespace(agent="context"), contract=contract)
    policy = issuance.build_reservation_policy(request)
    assert policy.max_input_tokens == expected
    assert catalog.bounds_for_agent("context").max_input_tokens == cumulative
    assert policy.max_output_tokens == (180000 if operator_cap is None else 18000)
    assert catalog.bounds_for_agent("context").max_output_tokens == 180000


async def test_healthy_loop_can_hold_multiple_requests_above_one_request_cap():
    import time
    import uuid

    from pydantic_ai.messages import ModelRequest, UserPromptPart
    from pydantic_ai.models import ModelRequestParameters

    from infosec_harness.inference.controller import admission, ledger
    from infosec_harness.inference.wire import codec
    from infosec_harness.inference.wire.protocol import (
        ExecutorContract,
        InferenceRequest,
        ReservationBinding,
        logical_request_id,
    )
    from infosec_harness.persistence import budgets, db

    await db.create_all()
    root_id = uuid.uuid4().hex
    # Three requests of at most 80k input and 50 output fit this independently
    # derived cumulative envelope. Holding two must not treat 80k as a run cap.
    envelope = {"requests": 3, "tokens": 240150, "cost_usd": 0}
    state = budgets.initial_state(envelope, elapsed_seconds=600)
    state["agent_config_digests"] = {"context": "config"}
    async with db.session() as session:
        session.add(db.BudgetLedger(root_id=root_id, state=state))
        await session.commit()
    await budgets.reserve(root_id, "op", envelope, "context", "config",
                          run_id="run", invocation_id="inv")
    contract = ExecutorContract(backend="mock", model="mock-model", profile="context",
        profile_digest="a" * 64, endpoint="https://provider.test/v1", provider_binding="mock",
        executor_image="sha256:" + "a" * 64, supervisor_image="sha256:" + "b" * 64,
        policy_digest="c" * 64, model_settings={"max_tokens": 50})
    binding = ReservationBinding(root_id=root_id, run_id="run", invocation_id="inv",
        operation_id="op", agent="context", contract_digest=contract.digest,
        expires_at=time.time() + 300)
    await admission.bind_reservation(binding, configuration_digest="config")
    policy = admission.ReservationPolicy("context", "context", contract.digest, "config",
                                        80000, 150, 0, 0, 0)

    def request(text, ordinal):
        payload = codec.encode_payload([ModelRequest(parts=[UserPromptPart(text)])],
                                       contract.model_settings, ModelRequestParameters())
        return InferenceRequest(request_id=logical_request_id(binding, ordinal), binding=binding,
            contract=contract, payload=payload, payload_digest=digest(payload.model_dump(mode="json")))

    try:
        for ordinal in ("model:0", "model:1"):
            value = request("x" * 60000, ordinal)
            await ledger.DurableLedger().admit(value, lease_id="lease",
                                               allocation=await admission.authorize(value, policy))
        async with db.session() as session:
            root = await session.get(db.BudgetLedger, root_id)
            held = root.state["operations"]["op"]["broker_allocated"]
        assert 100000 < held["tokens"] < 240150
        assert held["requests"] == 2
        from infosec_harness.inference.wire.protocol import BrokerError
        with pytest.raises(BrokerError) as rejected:
            await admission.authorize(request("x" * 90000, "model:2"), policy)
        assert rejected.value.code == "budget"
        async with db.session() as session:
            root = await session.get(db.BudgetLedger, root_id)
            assert root.state["operations"]["op"]["broker_allocated"] == held
    finally:
        await db._engine().dispose()
