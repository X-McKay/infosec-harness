"""Independent send-count, concurrency and process-crash oracles for broker ledgers."""
import asyncio
import json
import sys
import time
import uuid
from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest

from infosec_harness.inference.controller import admission, ledger
from infosec_harness.inference.wire.protocol import (
    BrokerError,
    ExecutorContract,
    InferencePayload,
    InferenceRequest,
    InferenceResult,
    ReservationBinding,
    digest,
    logical_request_id,
)
from infosec_harness.persistence import budgets, db

DEMAND = {"requests": 1, "tokens": 100, "cost_usd": 1}
LEDGER = ledger.DurableLedger()


@pytest.fixture(name="broker_request")
async def broker_request_fixture():
    await db.create_all()
    root_id = uuid.uuid4().hex
    state = budgets.initial_state({"requests": 2, "tokens": 200, "cost_usd": 2}, elapsed_seconds=600)
    state["agent_config_digests"] = {"context": "config"}
    async with db.session() as session:
        session.add(db.BudgetLedger(root_id=root_id, state=state))
        await session.commit()
    await budgets.reserve(root_id, "op", {"requests": 2, "tokens": 200, "cost_usd": 2}, "context", "config",
                          run_id="run-" + root_id, invocation_id="inv-" + root_id)
    contract = ExecutorContract(backend="mock", model="mock-model", profile="inference-only",
        profile_digest="a" * 64, endpoint="https://provider.test/v1", provider_binding="mock-provider",
        executor_image="sha256:" + "a" * 64, supervisor_image="sha256:" + "b" * 64,
        policy_digest="c" * 64, model_settings={"max_tokens": 50})
    binding = ReservationBinding(root_id=root_id, run_id="run-" + root_id, invocation_id="inv-" + root_id,
        operation_id="op", agent="context", contract_digest=contract.digest, expires_at=time.time() + 300)
    await admission.bind_reservation(binding, configuration_digest="config")
    payload = InferencePayload(messages=[{"parts": [{"part_kind": "user-prompt", "content": "hi"}],
        "kind": "request"}], parameters={}, model_settings={"max_tokens": 50})
    yield InferenceRequest(request_id=logical_request_id(binding, "model:0"), binding=binding,
        contract=contract, payload=payload, payload_digest=digest(payload.model_dump(mode="json")))
    # Each fixture has its own loop; asyncpg pooled connections must close on that loop.
    await db._engine().dispose()


def result_for(broker_request):
    return InferenceResult(request_id=broker_request.request_id,
        response={"parts": [{"part_kind": "text", "content": "ok"}], "kind": "response",
                  "usage": {"input_tokens": 20, "output_tokens": 2}},
        usage={"input_tokens": 20, "output_tokens": 2}, provenance={"verified": True})


async def operation(broker_request):
    async with db.session() as session:
        root = await session.get(db.BudgetLedger, broker_request.binding.root_id)
        return root.state["operations"]["op"]


def barrier(monkeypatch, phase):
    gate = asyncio.Event()
    arrivals = 0

    async def checkpoint(current):
        nonlocal arrivals
        if current == phase and arrivals < 2:
            arrivals += 1
            if arrivals == 2:
                gate.set()
            await asyncio.wait_for(gate.wait(), 5)
    monkeypatch.setattr(ledger, "_checkpoint", checkpoint)


async def test_duplicate_admission_allocates_once_under_cas_barrier(broker_request, monkeypatch):
    barrier(monkeypatch, "admit_before_cas")
    rows = await asyncio.gather(*(LEDGER.admit(broker_request, lease_id="lease", allocation=DEMAND) for _ in range(2)))
    assert [row.state for row in rows] == ["accepted", "accepted"]
    assert (await operation(broker_request))["broker_allocated"] == DEMAND


async def test_duplicate_claim_one_winner_one_send_under_cas_barrier(broker_request, monkeypatch):
    await LEDGER.admit(broker_request, lease_id="lease", allocation=DEMAND)
    barrier(monkeypatch, "claim_before_cas")
    outcomes = await asyncio.gather(*(LEDGER.claim(broker_request.request_id, lease_id="lease") for _ in range(2)), return_exceptions=True)
    assert sum(not isinstance(value, Exception) for value in outcomes) == 1
    assert sum(isinstance(value, BrokerError) and value.code == "pending" for value in outcomes) == 1
    assert (await operation(broker_request))["broker_dispatches"] == 1


async def test_distinct_executor_allocations_share_one_existing_envelope(broker_request, monkeypatch):
    other = broker_request.model_copy(update={"request_id": logical_request_id(broker_request.binding, "model:1")})
    barrier(monkeypatch, "admit_before_cas")
    rows = await asyncio.gather(LEDGER.admit(broker_request, lease_id="lease-a", allocation=DEMAND),
                               LEDGER.admit(other, lease_id="lease-b", allocation=DEMAND))
    assert all(row.state == "accepted" for row in rows)
    third = broker_request.model_copy(update={"request_id": logical_request_id(broker_request.binding, "model:2")})
    with pytest.raises(BrokerError) as exc:
        await LEDGER.admit(third, lease_id="lease-c", allocation=DEMAND)
    assert exc.value.code == "budget"
    assert (await operation(broker_request))["broker_allocated"] == {"requests": 2, "tokens": 200, "cost_usd": 2}
    assert await LEDGER.get(third.request_id) is None


@pytest.mark.parametrize("phase,expected", [("admit_before_commit", None),
    ("claim_before_commit", "accepted"), ("complete_before_commit", "dispatch_intent")])
async def test_transaction_crash_seam_rolls_back_without_fabricated_result(broker_request, monkeypatch, phase, expected):
    if phase != "admit_before_commit":
        await LEDGER.admit(broker_request, lease_id="lease", allocation=DEMAND)
    permit = await LEDGER.claim(broker_request.request_id, lease_id="lease") if phase == "complete_before_commit" else None

    async def kill(current):
        if current == phase:
            raise RuntimeError("injected process boundary")
    monkeypatch.setattr(ledger, "_checkpoint", kill)
    with pytest.raises(RuntimeError, match="injected"):
        if phase == "admit_before_commit":
            await LEDGER.admit(broker_request, lease_id="lease", allocation=DEMAND)
        elif phase == "claim_before_commit":
            await LEDGER.claim(broker_request.request_id, lease_id="lease")
        else:
            await LEDGER.complete(result_for(broker_request), permit=permit)
    row = await LEDGER.get(broker_request.request_id)
    assert (row.state if row else None) == expected
    assert row is None or row.result is None
    if phase == "admit_before_commit":
        assert "broker_allocated" not in await operation(broker_request)
    if phase == "claim_before_commit":
        assert "broker_dispatches" not in await operation(broker_request)


async def test_response_persisted_before_ack_recovered_without_new_permit(broker_request):
    await LEDGER.admit(broker_request, lease_id="lease", allocation=DEMAND)
    permit = await LEDGER.claim(broker_request.request_id, lease_id="lease")
    saved = await LEDGER.complete(result_for(broker_request), permit=permit)
    assert await LEDGER.admit(broker_request, lease_id="lease", allocation=DEMAND) == saved
    assert saved.result == result_for(broker_request)
    assert await LEDGER.complete(result_for(broker_request), permit=permit) == saved
    with pytest.raises(BrokerError):
        await LEDGER.claim(broker_request.request_id, lease_id="lease")
    assert (await operation(broker_request))["broker_dispatches"] == 1


async def test_dispatch_without_result_fenced_unknown_no_resend_or_late_result(broker_request):
    await LEDGER.admit(broker_request, lease_id="lease", allocation=DEMAND)
    permit = await LEDGER.claim(broker_request.request_id, lease_id="lease")
    unknown = await LEDGER.recover(broker_request.request_id, lease_id="lease")
    assert unknown.state == "completion_unknown" and unknown.result is None
    assert await LEDGER.recover(broker_request.request_id, lease_id="lease") == unknown
    assert (await LEDGER.admit(broker_request, lease_id="lease", allocation=DEMAND)).state == "completion_unknown"
    for action in (LEDGER.claim(broker_request.request_id, lease_id="lease"), LEDGER.complete(result_for(broker_request), permit=permit)):
        with pytest.raises(BrokerError) as exc:
            await action
        assert exc.value.code == "completion_unknown"
    assert (await operation(broker_request))["broker_allocated"] == DEMAND
    assert (await operation(broker_request))["broker_dispatches"] == 1


async def test_before_dispatch_terminal_retains_allocation_and_cannot_claim(broker_request):
    await LEDGER.admit(broker_request, lease_id="lease", allocation=DEMAND)
    assert (await LEDGER.fail_before_dispatch(broker_request.request_id, lease_id="lease")).state == "failed_before_dispatch"
    with pytest.raises(BrokerError):
        await LEDGER.claim(broker_request.request_id, lease_id="lease")
    assert (await operation(broker_request))["broker_allocated"] == DEMAND


async def test_fail_before_dispatch_cannot_erase_dispatch_intent(broker_request):
    await LEDGER.admit(broker_request, lease_id="lease", allocation=DEMAND)
    await LEDGER.claim(broker_request.request_id, lease_id="lease")
    with pytest.raises(BrokerError) as exc:
        await LEDGER.fail_before_dispatch(broker_request.request_id, lease_id="lease")
    assert exc.value.code == "completion_unknown"
    assert (await LEDGER.get(broker_request.request_id)).state == "dispatch_intent"


@pytest.mark.parametrize("action", ["admit", "claim", "recover", "fail"])
async def test_foreign_lease_cannot_read_by_duplicate_or_mutate(broker_request, action):
    await LEDGER.admit(broker_request, lease_id="owner", allocation=DEMAND)
    calls = {"admit": lambda: LEDGER.admit(broker_request, lease_id="foreign", allocation=DEMAND),
        "claim": lambda: LEDGER.claim(broker_request.request_id, lease_id="foreign"),
        "recover": lambda: LEDGER.recover(broker_request.request_id, lease_id="foreign"),
        "fail": lambda: LEDGER.fail_before_dispatch(broker_request.request_id, lease_id="foreign")}
    with pytest.raises(BrokerError) as exc:
        await calls[action]()
    assert exc.value.code == "identity"
    assert (await LEDGER.get(broker_request.request_id)).state == "accepted"


async def test_changed_payload_same_id_conflicts_without_dispatch(broker_request):
    await LEDGER.admit(broker_request, lease_id="lease", allocation=DEMAND)
    changed = broker_request.payload.model_copy(update={"parameters": {"changed": True}})
    modified = broker_request.model_copy(update={"payload": changed, "payload_digest": digest(changed.model_dump(mode="json"))})
    with pytest.raises(BrokerError) as exc:
        await LEDGER.admit(modified, lease_id="lease", allocation=DEMAND)
    assert exc.value.code == "conflict"
    assert "broker_dispatches" not in await operation(broker_request)


async def test_deadline_rechecked_at_claim_but_saved_result_survives_expiry(broker_request):
    await LEDGER.admit(broker_request, lease_id="lease", allocation=DEMAND)
    async with db.session() as session:
        root = await session.get(db.BudgetLedger, broker_request.binding.root_id)
        root.state = {**root.state, "deadline_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat()}
        await session.commit()
    with pytest.raises(BrokerError) as exc:
        await LEDGER.claim(broker_request.request_id, lease_id="lease")
    assert exc.value.code == "expired"
    assert "broker_dispatches" not in await operation(broker_request)
    assert (await LEDGER.admit(broker_request, lease_id="lease", allocation=DEMAND)).state == "accepted"


async def test_revocation_blocks_claim(broker_request):
    await LEDGER.admit(broker_request, lease_id="lease", allocation=DEMAND)
    async with db.session() as session:
        root = await session.get(db.BudgetLedger, broker_request.binding.root_id)
        state = deepcopy(root.state)
        state["operations"]["op"]["broker_revoked"] = True
        root.state = state
        await session.commit()
    with pytest.raises(BrokerError) as exc:
        await LEDGER.claim(broker_request.request_id, lease_id="lease")
    assert exc.value.code == "policy"


async def test_missing_retained_record_is_explicit_failure(broker_request):
    with pytest.raises(BrokerError) as exc:
        await LEDGER.recover(broker_request.request_id, lease_id="lease")
    assert exc.value.code == "identity"


async def test_forged_fence_result_identity_invalid_response_rejected(broker_request):
    await LEDGER.admit(broker_request, lease_id="lease", allocation=DEMAND)
    permit = await LEDGER.claim(broker_request.request_id, lease_id="lease")
    for bad in (permit.model_copy(update={"fence": "forged"}), permit.model_copy(update={"lease_id": "foreign"})):
        with pytest.raises(BrokerError) as exc:
            await LEDGER.complete(result_for(broker_request), permit=bad)
        assert exc.value.code == "identity"
    with pytest.raises(BrokerError) as exc:
        await LEDGER.complete(result_for(broker_request).model_copy(update={"response": {"parts": "invalid"}}), permit=permit)
    assert exc.value.code == "invalid_response"
    assert (await LEDGER.get(broker_request.request_id)).state == "dispatch_intent"


async def test_result_usage_overrun_is_retained_without_releasing_bounds(broker_request):
    await LEDGER.admit(broker_request, lease_id="lease", allocation=DEMAND)
    permit = await LEDGER.claim(broker_request.request_id, lease_id="lease")
    response = result_for(broker_request)
    response = response.model_copy(update={"usage": {"input_tokens": 1000},
        "response": {**response.response, "usage": {"input_tokens": 1000, "output_tokens": 0}}})
    saved = await LEDGER.complete(response, permit=permit)
    assert saved.result.usage == {"input_tokens": 1000}
    assert saved.allocation == DEMAND and saved.overrun == {"tokens": 900}
    other = broker_request.model_copy(update={"request_id": logical_request_id(broker_request.binding, "after-overrun")})
    with pytest.raises(BrokerError) as exc:
        await LEDGER.admit(other, lease_id="lease", allocation=DEMAND)
    assert exc.value.code == "budget"
    assert (await operation(broker_request))["broker_allocated"] == DEMAND


@pytest.mark.parametrize("bad", [{"requests": 0, "tokens": 1, "cost_usd": 0},
    {"requests": 1, "tokens": float("nan"), "cost_usd": 0},
    {"requests": 1, "tokens": 1, "cost_usd": -1},
    {"requests": 1, "tokens": 1, "cost_usd": 0, "extra": 1}])
async def test_invalid_trusted_allocations_leave_no_record(broker_request, bad):
    with pytest.raises(BrokerError) as exc:
        await LEDGER.admit(broker_request, lease_id="lease", allocation=bad)
    assert exc.value.code == "budget"
    assert await LEDGER.get(broker_request.request_id) is None


@pytest.mark.parametrize("phase,expected", [("admit_before_commit", None),
    ("claim_before_commit", "accepted"), ("complete_before_commit", "dispatch_intent")])
async def test_abrupt_process_death_preserves_transaction_recovery(broker_request, phase, expected):
    if phase != "admit_before_commit":
        await LEDGER.admit(broker_request, lease_id="lease", allocation=DEMAND)
    permit = await LEDGER.claim(broker_request.request_id, lease_id="lease") if phase == "complete_before_commit" else None
    script = r"""
import asyncio, os, sys
from infosec_harness.inference.controller import ledger
from infosec_harness.inference.wire.protocol import DispatchPermit, InferenceRequest, InferenceResult
phase, serialized_request, serialized_permit = sys.argv[1:]
request = InferenceRequest.model_validate_json(serialized_request)
async def checkpoint(current):
    if current == phase:
        os._exit(73)
ledger._checkpoint = checkpoint
LEDGER = ledger.DurableLedger()
async def main():
    if phase == "admit_before_commit":
        await LEDGER.admit(request, lease_id="lease", allocation={"requests":1,"tokens":100,"cost_usd":1})
    elif phase == "claim_before_commit":
        await LEDGER.claim(request.request_id, lease_id="lease")
    else:
        permit = DispatchPermit.model_validate_json(serialized_permit)
        result = InferenceResult(request_id=request.request_id,
            response={"parts":[{"part_kind":"text","content":"ok"}],"kind":"response"})
        await LEDGER.complete(result, permit=permit)
asyncio.run(main())
"""
    process = await asyncio.create_subprocess_exec(sys.executable, "-c", script, phase,
        broker_request.model_dump_json(), permit.model_dump_json() if permit else json.dumps(None),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await asyncio.wait_for(process.communicate(), 15)
    assert process.returncode == 73, (stdout.decode(), stderr.decode())
    row = await LEDGER.get(broker_request.request_id)
    assert (row.state if row else None) == expected
    assert row is None or row.result is None
    if expected == "dispatch_intent":
        assert (await LEDGER.recover(broker_request.request_id, lease_id="lease")).state == "completion_unknown"
        with pytest.raises(BrokerError) as exc:
            await LEDGER.claim(broker_request.request_id, lease_id="lease")
        assert exc.value.code == "completion_unknown"


async def test_accepted_config_change_blocks_actual_dispatch(broker_request):
    await LEDGER.admit(broker_request, lease_id="lease", allocation=DEMAND)
    async with db.session() as session:
        root = await session.get(db.BudgetLedger, broker_request.binding.root_id)
        root.state = {**root.state, "agent_config_digests": {"context": "changed"}}
        await session.commit()
    with pytest.raises(BrokerError) as exc:
        await LEDGER.claim(broker_request.request_id, lease_id="lease")
    assert exc.value.code == "identity"
    assert "broker_dispatches" not in await operation(broker_request)
async def test_revoke_run_terminalizes_pending_and_blocks_fresh_identity(broker_request):
    await LEDGER.admit(broker_request, lease_id="lease", allocation=DEMAND)
    second = broker_request.model_copy(update={"request_id": logical_request_id(broker_request.binding, "model:1")})
    await LEDGER.admit(second, lease_id="lease", allocation=DEMAND)
    permit = await LEDGER.claim(second.request_id, lease_id="lease")
    await LEDGER.revoke_run(broker_request.binding.run_id, root_id=broker_request.binding.root_id)
    assert (await LEDGER.get(broker_request.request_id)).state == "failed_before_dispatch"
    assert (await LEDGER.get(second.request_id)).state == "completion_unknown"
    assert (await operation(broker_request))["broker_allocated"] == {"requests": 2, "tokens": 200, "cost_usd": 2}
    fresh = broker_request.model_copy(update={"request_id": logical_request_id(broker_request.binding, "fresh-after-close")})
    with pytest.raises(BrokerError) as exc:
        await LEDGER.admit(fresh, lease_id="fresh-lease", allocation=DEMAND)
    assert exc.value.code == "policy"
    with pytest.raises(BrokerError):
        await LEDGER.claim(broker_request.request_id, lease_id="lease")
    with pytest.raises(BrokerError) as exc:
        await LEDGER.complete(result_for(second), permit=permit)
    assert exc.value.code == "completion_unknown"
    await LEDGER.revoke_run(broker_request.binding.run_id, root_id=broker_request.binding.root_id)  # Idempotent repeat.


async def test_revoke_keeps_completed_result_and_other_runs_unchanged(broker_request):
    await LEDGER.admit(broker_request, lease_id="lease", allocation=DEMAND)
    permit = await LEDGER.claim(broker_request.request_id, lease_id="lease")
    saved = await LEDGER.complete(result_for(broker_request), permit=permit)
    foreign_root = "unrelated-" + uuid.uuid4().hex
    foreign = budgets.initial_state({"requests": 1, "tokens": 1, "cost_usd": 1}, elapsed_seconds=100)
    foreign["broker_run_id"] = "other-run"
    async with db.session() as session:
        session.add(db.BudgetLedger(root_id=foreign_root, state=foreign))
        await session.commit()
    await LEDGER.revoke_run(broker_request.binding.run_id, root_id=broker_request.binding.root_id)
    assert await LEDGER.get(broker_request.request_id) == saved
    async with db.session() as session:
        root = await session.get(db.BudgetLedger, foreign_root)
        assert root.state == foreign
    assert (await operation(broker_request))["status"] == "uncertain"


async def test_revoke_atomic_root_fence_wins_against_waiting_dispatch(broker_request, monkeypatch):
    await LEDGER.admit(broker_request, lease_id="lease", allocation=DEMAND)
    read = asyncio.Event()
    resume = asyncio.Event()
    first = True

    async def checkpoint(phase):
        nonlocal first
        if phase == "claim_before_cas" and first:
            first = False
            read.set()
            await asyncio.wait_for(resume.wait(), 5)
    monkeypatch.setattr(ledger, "_checkpoint", checkpoint)
    claimant = asyncio.create_task(LEDGER.claim(broker_request.request_id, lease_id="lease"))
    await asyncio.wait_for(read.wait(), 5)
    await LEDGER.revoke_run(broker_request.binding.run_id, root_id=broker_request.binding.root_id)
    resume.set()
    with pytest.raises(BrokerError):
        await claimant
    assert "broker_dispatches" not in await operation(broker_request)
    assert (await LEDGER.get(broker_request.request_id)).state == "failed_before_dispatch"


async def test_run_cleanup_owner_rejects_foreign_root_without_mutation(broker_request):
    await LEDGER.validate_run_owner(broker_request.binding.run_id, broker_request.binding.root_id)
    before = await operation(broker_request)
    for run_id, root_id in (("foreign", broker_request.binding.root_id),
                            (broker_request.binding.run_id, "missing-root")):
        with pytest.raises(BrokerError) as exc:
            await LEDGER.validate_run_owner(run_id, root_id)
        assert exc.value.code == "identity"
    assert await operation(broker_request) == before


async def test_run_fence_rejects_new_reserved_invocation_on_existing_root(broker_request):
    await LEDGER.revoke_run(broker_request.binding.run_id, root_id=broker_request.binding.root_id)
    with pytest.raises(ValueError, match="revoked"):
        await budgets.reserve(broker_request.binding.root_id, "new-op", DEMAND, "context", "config",
            run_id=broker_request.binding.run_id, invocation_id="new-invocation")
    async with db.session() as session:
        root = await session.get(db.BudgetLedger, broker_request.binding.root_id)
        assert "new-op" not in root.state["operations"]


@pytest.mark.parametrize("changes", [
    {"usage": {"input_tokens": -1}},
    {"usage": {"unknown_counter": 1}},
    {"usage": {"input_tokens": 0}},
])
async def test_result_usage_cannot_contradict_authoritative_response(broker_request, changes):
    await LEDGER.admit(broker_request, lease_id="lease", allocation=DEMAND)
    permit = await LEDGER.claim(broker_request.request_id, lease_id="lease")
    invalid = result_for(broker_request).model_copy(update=changes)
    with pytest.raises(BrokerError) as exc:
        await LEDGER.complete(invalid, permit=permit)
    assert exc.value.code == "invalid_response"
    assert (await LEDGER.get(broker_request.request_id)).state == "dispatch_intent"
    assert (await operation(broker_request))["broker_allocated"] == DEMAND


async def test_negative_authoritative_response_usage_is_not_a_saved_result(broker_request):
    await LEDGER.admit(broker_request, lease_id="lease", allocation=DEMAND)
    permit = await LEDGER.claim(broker_request.request_id, lease_id="lease")
    response = result_for(broker_request)
    invalid = response.model_copy(update={"usage": {},
        "response": {**response.response, "usage": {"input_tokens": -1}}})
    with pytest.raises(BrokerError) as exc:
        await LEDGER.complete(invalid, permit=permit)
    assert exc.value.code == "invalid_response"
    assert (await LEDGER.get(broker_request.request_id)).result is None


async def test_repeat_run_revocation_preserves_conservative_closure(broker_request):
    await LEDGER.admit(broker_request, lease_id="lease", allocation=DEMAND)
    await LEDGER.claim(broker_request.request_id, lease_id="lease")
    await LEDGER.revoke_run(broker_request.binding.run_id, root_id=broker_request.binding.root_id)
    async with db.session() as session:
        root = await session.get(db.BudgetLedger, broker_request.binding.root_id)
        state = deepcopy(root.state)
        state["operations"][broker_request.binding.operation_id].update(
            status="closed_unknown", operator_reconciliation={"accounting_basis": "reserved_upper_bound"})
        root.state = state
        await session.commit()
    before = await operation(broker_request)
    await LEDGER.revoke_run(broker_request.binding.run_id, root_id=broker_request.binding.root_id)
    assert await operation(broker_request) == before
    assert (await LEDGER.get(broker_request.request_id)).state == "completion_unknown"
    with pytest.raises(BrokerError) as exc:
        await LEDGER.claim(broker_request.request_id, lease_id="lease")
    assert exc.value.code == "completion_unknown"


async def test_revoke_run_is_scoped_to_its_authenticated_root(broker_request):
    """Closure touches only the authenticated root and refuses one that never held the run."""
    await LEDGER.admit(broker_request, lease_id="lease", allocation=DEMAND)
    foreign_root = "unrelated-" + uuid.uuid4().hex
    foreign = budgets.initial_state({"requests": 1, "tokens": 1, "cost_usd": 1}, elapsed_seconds=100)
    foreign["broker_run_id"] = "other-run"
    async with db.session() as session:
        session.add(db.BudgetLedger(root_id=foreign_root, state=foreign))
        await session.commit()
    with pytest.raises(BrokerError) as exc:
        await LEDGER.revoke_run(broker_request.binding.run_id, root_id=foreign_root)
    assert exc.value.code == "identity"
    async with db.session() as session:
        assert (await session.get(db.BudgetLedger, foreign_root)).state == foreign
    assert (await LEDGER.get(broker_request.request_id)).state == "accepted"


async def test_injected_clock_owns_dispatch_expiry(broker_request):
    """The controller clock, not the host wall clock, decides reservation expiry."""
    late = broker_request.binding.expires_at + 1
    with pytest.raises(BrokerError) as exc:
        await ledger.DurableLedger(clock=lambda: late).admit(broker_request, lease_id="lease",
                                                             allocation=DEMAND)
    assert exc.value.code == "expired"
    assert await LEDGER.get(broker_request.request_id) is None
