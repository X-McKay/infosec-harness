"""Admission oracles: trusted config, ownership and expiry precede any dispatch."""
from dataclasses import replace

import pytest
from pydantic_ai.exceptions import UsageLimitExceeded
from test_inference_ledger import DEMAND, LEDGER, broker_request_fixture  # noqa: F401

from infosec_harness.inference.controller import admission
from infosec_harness.inference.executor import rendering
from infosec_harness.inference.wire.protocol import BrokerError
from infosec_harness.persistence import budgets, db


def policy_for(broker_request):
    return admission.ReservationPolicy(agent="context", profile="inference-only",
        contract_digest=broker_request.contract.digest, configuration_digest="config",
        max_input_tokens=10_000, max_output_tokens=50, max_cost_usd=1,
        input_per_mtok=2, output_per_mtok=4)


async def test_catalog_produces_allocation_without_worker_amounts(broker_request):
    allocated = await admission.authorize(broker_request, policy_for(broker_request))
    input_reserve = await rendering.required_input_reserve(broker_request.payload, broker_request.contract)
    assert allocated["requests"] == 1
    assert allocated["tokens"] == input_reserve + 50
    assert allocated["cost_usd"] >= (input_reserve * 2 + 50 * 4) / 1_000_000
    assert allocated["cost_usd"] < 1


@pytest.mark.parametrize("field,value", [("agent", "verdict"), ("profile", "other"),
                                         ("contract_digest", "0" * 64)])
async def test_forged_identity_fails_catalog_before_dispatch(broker_request, field, value):
    with pytest.raises(BrokerError) as exc:
        await admission.authorize(broker_request, replace(policy_for(broker_request), **{field: value}))
    assert exc.value.code == "identity"


@pytest.mark.parametrize("kwargs", [{"max_input_tokens": 0}, {"max_output_tokens": -1},
                                    {"max_cost_usd": float("inf")}, {"max_cost_usd": -1}])
def test_unknown_unbounded_or_negative_trusted_limits_fail(kwargs):
    defaults = dict(agent="context", profile="inference-only", contract_digest="a" * 64,
                    configuration_digest="config", max_input_tokens=50,
                    max_output_tokens=50, max_cost_usd=1)
    with pytest.raises(BrokerError):
        admission.ReservationPolicy(**(defaults | kwargs))


async def test_reservation_binding_idempotent_but_cross_run_rebind_fails(broker_request):
    await admission.bind_reservation(broker_request.binding, configuration_digest="config")
    foreign = broker_request.binding.model_copy(update={"run_id": "other-run"})
    with pytest.raises(BrokerError) as exc:
        await admission.bind_reservation(foreign, configuration_digest="config")
    assert exc.value.code == "conflict"


async def test_changed_accepted_configuration_cannot_issue_binding(broker_request):
    with pytest.raises(BrokerError) as exc:
        await admission.bind_reservation(broker_request.binding, configuration_digest="changed")
    assert exc.value.code == "identity"


async def test_missing_root_and_operation_cannot_issue_or_admit(broker_request):
    missing = broker_request.binding.model_copy(update={"root_id": "missing"})
    with pytest.raises(BrokerError) as exc:
        await admission.bind_reservation(missing, configuration_digest="config")
    assert exc.value.code == "identity"
    foreign = broker_request.model_copy(update={"binding": missing})
    with pytest.raises(BrokerError) as exc:
        await LEDGER.admit(foreign, lease_id="lease", allocation=DEMAND)
    assert exc.value.code == "identity"
    missing_op = broker_request.binding.model_copy(update={"operation_id": "missing"})
    with pytest.raises(BrokerError):
        await admission.bind_reservation(missing_op, configuration_digest="config")


async def test_unissued_binding_and_cross_run_request_fail_before_admission(broker_request):
    foreign = broker_request.model_copy(update={"binding": broker_request.binding.model_copy(update={"run_id": "foreign"})})
    with pytest.raises(BrokerError) as exc:
        await LEDGER.admit(foreign, lease_id="lease", allocation=DEMAND)
    assert exc.value.code == "identity"
    assert await LEDGER.get(broker_request.request_id) is None


async def test_broker_owned_operation_cannot_release_on_worker_observed_settle(broker_request):
    await LEDGER.admit(broker_request, lease_id="lease", allocation=DEMAND)
    await budgets.settle(broker_request.binding.root_id, "op", {"requests": 0, "tokens": 0, "cost_usd": 0},
                         {"worker": "claims-zero"})
    async with db.session() as session:
        root = await session.get(db.BudgetLedger, broker_request.binding.root_id)
        assert root.state["used"] == {"requests": 0, "tokens": 0, "cost_usd": 0}
        assert root.state["operations"]["op"]["status"] == "uncertain"
    with pytest.raises(UsageLimitExceeded) as exc:
        await budgets.reserve(broker_request.binding.root_id, "other", DEMAND, "context", "config")
    assert "cannot reserve" in str(exc.value)


async def test_input_size_and_framing_cannot_exceed_trusted_reserve(broker_request):
    required = await rendering.required_input_reserve(broker_request.payload, broker_request.contract)
    assert required > len(str(broker_request.payload))
    with pytest.raises(BrokerError) as exc:
        await admission.authorize(broker_request, replace(policy_for(broker_request), max_input_tokens=required - 1))
    assert exc.value.code == "budget"
    assert (await admission.authorize(broker_request, replace(policy_for(broker_request), max_input_tokens=required)))["tokens"] == required + 50


@pytest.mark.parametrize("change", [{"expires_at": 1}, {"expires_at": 10**12}])
async def test_new_binding_expiry_cannot_renew_root_deadline(broker_request, change):
    # A second reserved operation avoids confusing expiry rejection with immutable rebinding.
    async with db.session() as session:
        root = await session.get(db.BudgetLedger, broker_request.binding.root_id)
        state = dict(root.state)
        state["operations"] = {**state["operations"], "new-op": {
            "agent": "context", "kind": "agent", "status": "reserved", "reserved": DEMAND}}
        root.state = state
        await session.commit()
    new_binding = broker_request.binding.model_copy(update={"operation_id": "new-op", **change})
    with pytest.raises(BrokerError) as exc:
        await admission.bind_reservation(new_binding, configuration_digest="config")
    assert exc.value.code == "expired"


async def test_persisted_run_owner_prevents_first_same_agent_cross_run_binding(broker_request):
    async with db.session() as session:
        root = await session.get(db.BudgetLedger, broker_request.binding.root_id)
        state = dict(root.state)
        state["operations"] = {"owned": {"agent": "context", "kind": "agent",
            "status": "reserved", "reserved": DEMAND, "run_id": "rightful-run",
            "invocation_id": "rightful-invocation"}}
        root.state = state
        await session.commit()
    foreign = broker_request.binding.model_copy(update={"operation_id": "owned"})
    with pytest.raises(BrokerError) as exc:
        await admission.bind_reservation(foreign, configuration_digest="config")
    assert exc.value.code == "identity"


async def test_paid_models_require_reviewed_prices_and_ceiling_cannot_be_truncated(broker_request):
    with pytest.raises(BrokerError):
        replace(policy_for(broker_request), input_per_mtok=None, output_per_mtok=None)
    with pytest.raises(BrokerError):
        replace(policy_for(broker_request), output_per_mtok=None)
    with pytest.raises(BrokerError) as exc:
        await admission.authorize(broker_request, replace(policy_for(broker_request), max_cost_usd=0.000001))
    assert exc.value.code == "budget"


async def test_known_zero_is_explicit_and_uses_the_same_token_bounds(broker_request):
    policy = replace(policy_for(broker_request), max_cost_usd=0,
                     input_per_mtok=None, output_per_mtok=None)
    allocated = await admission.authorize(broker_request, policy)
    assert allocated["cost_usd"] == 0
    assert allocated["tokens"] == await rendering.required_input_reserve(broker_request.payload, broker_request.contract) + 50


async def test_issued_binding_owns_full_hold_before_any_request_admission(broker_request):
    assert await LEDGER.get(broker_request.request_id) is None
    async with db.session() as session:
        root = await session.get(db.BudgetLedger, broker_request.binding.root_id)
        issued = root.state["operations"]["op"]
        assert issued["broker_owned"] is True
        assert "broker_allocated" not in issued
        held = issued["reserved"].copy()
    await budgets.settle(broker_request.binding.root_id, "op",
                         {"requests": 0, "tokens": 0, "cost_usd": 0}, {"worker": "no result"})
    async with db.session() as session:
        root = await session.get(db.BudgetLedger, broker_request.binding.root_id)
        assert root.state["operations"]["op"]["status"] == "uncertain"
        assert root.state["operations"]["op"]["reserved"] == held
        assert root.state["used"] == {"requests": 0, "tokens": 0, "cost_usd": 0}
    with pytest.raises(UsageLimitExceeded):
        await budgets.reserve(broker_request.binding.root_id, "another", DEMAND, "context", "config")
    admitted = await LEDGER.admit(broker_request, lease_id="lease", allocation=DEMAND)
    assert admitted.state == "accepted"
