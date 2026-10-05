"""Independent workflow command-selection and retry identity oracles; no service I/O."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.inference.protocol import ExecutorContract, ReservationBinding
from infosec_harness.workflows import accounting, temporal_ops


def contract():
    return ExecutorContract(backend="mock", model="mock-model", profile="inference-only",
        profile_digest="a" * 64, endpoint="https://provider.test/v1", provider_binding="mock-provider",
        executor_image="sha256:" + "a" * 64, supervisor_image="sha256:" + "b" * 64,
        policy_digest="c" * 64, model_settings={"max_tokens": 100})


def config(broker=True):
    value = SimpleNamespace(agent_name="context", digest="accepted-config",
        model=SimpleNamespace(broker_contract=contract() if broker else None,
            transport_retries=0, pricing_status="custom", mode="live"),
        budget=SimpleNamespace(effective=SimpleNamespace(max_requests=2, max_tool_calls=3,
            max_input_tokens=5000, max_output_tokens=100, max_cost_usd=1)))
    value.for_source_files = lambda files: value
    return value


def workflow_info(attempt=1):
    return SimpleNamespace(workflow_id="triage:fingerprint:batch:root", run_id="execution-1",
        root=SimpleNamespace(workflow_id="batch:root"), parent=None, attempt=attempt)


async def test_new_broker_operation_identity_survives_attempts_but_distinguishes_invocations(monkeypatch):
    calls = []

    async def execute(activity, args, **kwargs):
        calls.append(args)
        return {"status": "reserved"}
    monkeypatch.setattr(accounting.workflow, "execute_activity", execute)
    identities = []
    for attempt in (1, 2):
        monkeypatch.setattr(accounting.workflow, "info", lambda attempt=attempt: workflow_info(attempt))
        identities.append(await accounting.RootAccounting(
            root_id="batch:root", fingerprint="fingerprint").reserve(config(), configuration_digest="accepted-config"))
    assert identities[0] == identities[1]
    assert identities[0][1] == "triage:fingerprint:batch:root:execution-1:0:context"
    reserved = [args for args in calls if "requested" in args]
    assert all(args["run_id"] == "execution-1" and args["invocation_id"] == identities[0][1] for args in reserved)
    instance = accounting.RootAccounting(root_id="batch:root", fingerprint="fingerprint")
    first = await instance.reserve(config(), configuration_digest="accepted-config")
    second = await instance.reserve(config(), configuration_digest="accepted-config")
    assert first != second


async def test_direct_accounting_identity_is_workflow_scoped_and_carries_no_broker_fields(
    monkeypatch,
):
    monkeypatch.setattr(accounting.workflow, "info", workflow_info)
    calls = []

    async def execute(activity, args, **kwargs):
        calls.append(args)
        return {"status": "reserved"}
    monkeypatch.setattr(accounting.workflow, "execute_activity", execute)
    identity = await accounting.RootAccounting(
        root_id="batch:root", fingerprint="fingerprint",
    ).reserve(config(broker=False), configuration_digest="accepted-config")
    assert identity[1] == "triage:fingerprint:batch:root:0:context"
    assert "run_id" not in calls[0] and "invocation_id" not in calls[0]


async def test_new_temporal_binding_is_an_activity_and_not_runtime_io_in_workflow(monkeypatch):
    selected = config()
    ops = temporal_ops.TemporalOps()
    ops._agents = {"context": object()}
    ops._configs = {"context": selected}
    ops._accounting.reserve = AsyncMock(return_value=("root", "operation"))
    ops._accounting.settle = AsyncMock()
    monkeypatch.setattr(temporal_ops.workflow, "info", workflow_info)
    from infosec_harness.inference import invocations
    monkeypatch.setattr(invocations, "request_invocation", lambda *args: pytest.fail("Workflow runtime I/O"))
    scheduled = []
    binding = ReservationBinding(root_id="root", run_id="execution-1", invocation_id="operation",
        operation_id="operation", agent="context", contract_digest=selected.model.broker_contract.digest,
        expires_at=10**12)

    async def activity(fn, args, **kwargs):
        scheduled.append((fn, args))
        return binding.model_dump(mode="json")
    monkeypatch.setattr(temporal_ops.workflow, "execute_activity", activity)

    async def run(name, prompt, deps):
        assert deps.broker_binding == binding
        assert deps.broker_contract == selected.model.broker_contract
        return "outcome"
    monkeypatch.setattr(ops, "_run_agent", run)
    original = AgentDeps(repo_path="/tmp/repository")
    assert await ops.run_agent("context", ["prompt"], original) == "outcome"
    assert original.broker_binding is None
    assert len(scheduled) == 1
    assert scheduled[0][1]["run_id"] == "execution-1"
    assert scheduled[0][1]["invocation_id"] == "operation"


async def test_direct_temporal_branch_does_not_schedule_broker_activity(monkeypatch):
    selected = config(broker=False)
    ops = temporal_ops.TemporalOps()
    ops._agents = {"context": object()}
    ops._configs = {"context": selected}
    ops._accounting.reserve = AsyncMock(return_value=("root", "operation"))
    ops._accounting.settle = AsyncMock()
    monkeypatch.setattr(temporal_ops.workflow, "execute_activity", AsyncMock(side_effect=AssertionError("Unexpected broker activity")))
    monkeypatch.setattr(ops, "_run_agent", AsyncMock(return_value="outcome"))
    assert await ops.run_agent("context", ["prompt"], AgentDeps(repo_path="/tmp/repository")) == "outcome"


async def test_close_before_first_reservation_performs_no_controller_activity(monkeypatch):
    ops = temporal_ops.TemporalOps()
    ops._configs = {"context": config()}
    monkeypatch.setattr(temporal_ops.workflow, "execute_activity",
                        lambda *args, **kwargs: pytest.fail("No run ownership was established"))
    await ops.close()


async def test_close_uses_the_established_run_root_ownership(monkeypatch):
    ops = temporal_ops.TemporalOps()
    ops._broker_identity = ("execution-1", "root")
    monkeypatch.setattr(temporal_ops.workflow, "patched", lambda name: True)
    calls = []
    async def execute(fn, value, **kwargs):
        calls.append((fn, value))
    monkeypatch.setattr(temporal_ops.workflow, "execute_activity", execute)
    await ops.close()
    assert calls == [(temporal_ops.activities.close_broker_run_activity,
                      {"run_id": "execution-1", "root_id": "root"})]


@pytest.mark.parametrize("code,retryable", [("unavailable", True), ("pending", True),
    ("completion_unknown", False), ("auth", False), ("expired", False), ("conflict", False)])
async def test_issuance_activity_retries_only_safe_dispositions(monkeypatch, code, retryable):
    from temporalio.exceptions import ApplicationError

    from infosec_harness.inference import invocations
    from infosec_harness.inference.protocol import BrokerError, InvocationRequest
    async def unavailable(*args):
        raise BrokerError(code)
    monkeypatch.setattr(invocations, "request_invocation", unavailable)
    request = InvocationRequest(mode="temporal", root_id="root", run_id="run",
        invocation_id="operation", operation_id="operation", agent="context",
        configuration_digest="config", contract=contract())
    with pytest.raises(ApplicationError) as failure:
        await temporal_ops.activities.issue_broker_invocation_activity(request.model_dump(mode="json"))
    assert failure.value.non_retryable is (not retryable)
