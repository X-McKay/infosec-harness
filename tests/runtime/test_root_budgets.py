import asyncio

import pytest
from pydantic_ai.exceptions import UsageLimitExceeded
from temporalio.exceptions import ActivityError, ApplicationError

from infosec_harness.domain.models import InconclusiveReason
from infosec_harness.graph.failures import classify_pipeline_failure
from infosec_harness.persistence import budgets, db


def _pinned(limits: dict, *agents: str) -> dict:
    """A root ledger that pins one accepted configuration ("cfg") per named agent."""
    state = budgets.initial_state(limits)
    state["agent_config_digests"] = dict.fromkeys(agents, "cfg")
    return state


async def test_reservation_is_durable_idempotent_and_concurrent():
    await db.create_all()
    async with db.session() as session:
        session.add(db.BudgetLedger(root_id="budget-test", state=_pinned(
            {"tokens": 100, "requests": 10, "cost_usd": 1}, "agent")))
        await session.commit()
    demand = {"tokens": 60, "requests": 3, "cost_usd": .3}
    results = await asyncio.gather(*(budgets.reserve("budget-test", f"call-{i}", demand, "agent",
                                                     "cfg")
                                    for i in range(2)), return_exceptions=True)
    assert sum(isinstance(r, UsageLimitExceeded) for r in results) == 1
    winner = next(i for i, r in enumerate(results) if not isinstance(r, BaseException))
    op = f"call-{winner}"
    assert await budgets.reserve("budget-test", op, demand, "agent", "cfg") == results[winner]
    await budgets.settle("budget-test", op, {"tokens": 20, "requests": 1, "cost_usd": .1}, {"ok": True})
    await budgets.settle("budget-test", op, {"tokens": 20, "requests": 1, "cost_usd": .1}, {"ok": True})
    assert (await budgets.reserve("budget-test", "next", demand, "agent", "cfg"))["status"] == "reserved"
    await budgets.settle("budget-test", "next", None, {"failure": "timeout"})
    with pytest.raises(UsageLimitExceeded):
        await budgets.reserve("budget-test", "after-unknown", demand, "agent", "cfg")
    async with db.session() as session:
        ledger = await session.get(db.BudgetLedger, "budget-test")
        assert ledger.state["used"]["tokens"] == 20
        assert ledger.state["operations"]["next"]["status"] == "uncertain"


@pytest.mark.parametrize("value", [-1, float("nan"), float("inf")])
async def test_non_finite_or_negative_budget_values_fail_before_storage(value):
    invalid = {"requests": 1, "tokens": value, "cost_usd": 0}
    with pytest.raises(ValueError, match="finite non-negative"):
        budgets.initial_state(invalid)
    with pytest.raises(ValueError, match="finite non-negative"):
        await budgets.reserve("nonexistent", "operation", invalid, "agent")
    with pytest.raises(ValueError, match="finite non-negative"):
        await budgets.settle("nonexistent", "operation", invalid, {})


async def test_temporal_root_scope_is_explicit_not_parsed_from_workflow_ids(monkeypatch):
    """The root and the finding come from the workflow's own arguments. Workflow ids are opaque:
    one that looks like a batch id or embeds another fingerprint changes nothing."""
    from types import SimpleNamespace

    from infosec_harness.workflows import accounting

    info = SimpleNamespace(workflow_id="triage:other-fp:batch:looks-like-a-root", run_id="run",
                           root=SimpleNamespace(workflow_id="batch:looks-like-a-root"),
                           parent=SimpleNamespace(workflow_id="batch:looks-like-a-root"))
    monkeypatch.setattr(accounting.workflow, "info", lambda: info)
    root_id, fingerprint = "batch-explicit", "fp-1"
    requests = []

    async def execute(activity, args, **kwargs):
        requests.append(args)
        return {"status": "reserved"}

    monkeypatch.setattr(accounting.workflow, "execute_activity", execute)
    config = SimpleNamespace(
        agent_name="context",
        budget=SimpleNamespace(effective=SimpleNamespace(
            max_requests=1, max_tool_calls=2, max_input_tokens=100, max_output_tokens=20, max_cost_usd=1)),
        model=SimpleNamespace(transport_retries=0, pricing_status="known_zero", mode="stub",
                              broker_contract=None),
    )
    ledger = accounting.RootAccounting(root_id=root_id, fingerprint=fingerprint)
    result = await ledger.reserve(config, configuration_digest="digest")
    execution = await ledger.reserve_execution("build_environment_activity", 60)
    reserve, progress, reserve_execution = requests
    assert result[0] == execution[0] == root_id == reserve.root_id == reserve_execution.root_id
    assert reserve.fingerprint == reserve_execution.fingerprint == fingerprint
    assert (reserve.operation_kind, reserve_execution.operation_kind) == ("agent", "execution")
    assert reserve.configuration_digest == "digest"
    assert reserve.requested["tool_calls"] > 0 and reserve.requested["agent_runs"] == 1
    assert progress.batch_id == root_id and progress.fingerprint == fingerprint


@pytest.mark.parametrize(("root_id", "fingerprint"), [("", "fp"), ("batch-x", ""), ("", "")])
def test_root_accounting_has_no_unaccounted_mode(root_id, fingerprint):
    """Regression: a workflow without a batch id ran its agents and workloads unaccounted."""
    from infosec_harness.workflows.accounting import RootAccounting

    with pytest.raises(ValueError, match="requires the batch and the finding"):
        RootAccounting(root_id=root_id, fingerprint=fingerprint)


async def test_operations_record_their_finding_and_kind_and_cannot_be_rebound():
    await db.create_all()
    async with db.session() as session:
        session.add(db.BudgetLedger(root_id="attribution", state=_pinned(
            {"tokens": 100, "requests": 10, "cost_usd": 1}, "agent")))
        await session.commit()
    demand = {"tokens": 1, "requests": 1, "cost_usd": 0}
    operation = await budgets.reserve("attribution", "op", demand, "agent", "cfg",
                                      fingerprint="fp-a")
    assert (operation["fingerprint"], operation["kind"]) == ("fp-a", "agent")
    assert await budgets.reserve("attribution", "op", demand, "agent", "cfg",
                                 fingerprint="fp-a") == operation
    with pytest.raises(ValueError, match="different budget or agent"):
        await budgets.reserve("attribution", "op", demand, "agent", "cfg", fingerprint="fp-b")


def test_serialized_temporal_budget_failure_keeps_budget_taxonomy():
    application = ApplicationError("root exhausted", type="UsageLimitExceeded")
    activity = ActivityError("activity failed", scheduled_event_id=1, started_event_id=2,
                             identity="worker", activity_type="reserve_budget_activity",
                             activity_id="3", retry_state=None)
    activity.__cause__ = application
    assert classify_pipeline_failure(activity) is InconclusiveReason.budget_exhausted


def test_terminal_persistence_retries_have_bounded_backoff():
    from infosec_harness.workflows.activity_options import TERMINAL

    retry = TERMINAL["retry_policy"]
    assert retry.maximum_attempts == 0
    assert retry.maximum_interval.total_seconds() == 30
    # A write naming a run or ledger that was never accepted cannot succeed on a retry.
    assert {"MissingDurableRecord", "MissingLedger"} <= set(retry.non_retryable_error_types)


@pytest.mark.parametrize('dimension', ['tool_calls', 'agent_runs', 'execution_seconds'])
async def test_extended_root_dimensions_reserve_atomically_and_hold_unknown(dimension):
    await db.create_all()
    limits = {'requests': 100, 'tokens': 100, 'cost_usd': 10,
              'tool_calls': 10, 'agent_runs': 10, 'execution_seconds': 10}
    root = f'extended-{dimension}'
    async with db.session() as session:
        session.add(db.BudgetLedger(root_id=root, state=_pinned(limits, "test")))
        await session.commit()
    demand = dict.fromkeys(limits, 0)
    demand[dimension] = 6
    results = await asyncio.gather(*(budgets.reserve(root, str(i), demand, 'test', 'cfg')
                                    for i in range(2)), return_exceptions=True)
    assert sum(isinstance(r, UsageLimitExceeded) for r in results) == 1
    winner = str(next(i for i, r in enumerate(results) if not isinstance(r, BaseException)))
    # Partial observations cannot silently free the unobserved dimensions.
    await budgets.settle(root, winner, {'requests': 0, 'tokens': 0, 'cost_usd': 0}, {})
    with pytest.raises(UsageLimitExceeded):
        await budgets.reserve(root, 'next', demand, 'test', 'cfg')
    observed = dict.fromkeys(limits, 0)
    observed[dimension] = 2
    await budgets.settle(root, winner, observed, {'reconciled': True})
    assert (await budgets.reserve(root, 'next', demand, 'test', 'cfg'))['status'] == 'reserved'


async def test_root_deadline_persists_and_rejects_new_dispatch(monkeypatch):
    from datetime import UTC, datetime, timedelta
    await db.create_all()
    state = budgets.initial_state({'requests': 10, 'tokens': 100, 'cost_usd': 1},
                                  elapsed_seconds=60)
    async with db.session() as session:
        session.add(db.BudgetLedger(root_id='deadline-test', state=state))
        await session.commit()
    first = await budgets.remaining_time('deadline-test')
    assert 0 < first <= 60
    # A second process's read cannot renew the acceptance-time deadline.
    assert await budgets.remaining_time('deadline-test') <= first
    async with db.session() as session:
        ledger = await session.get(db.BudgetLedger, 'deadline-test')
        ledger.state = {**ledger.state, 'deadline_at':
                        (datetime.now(UTC) - timedelta(seconds=1)).isoformat()}
        await session.commit()
    with pytest.raises(UsageLimitExceeded, match='elapsed-time'):
        await budgets.remaining_time('deadline-test')
    with pytest.raises(UsageLimitExceeded, match='elapsed-time'):
        await budgets.reserve('deadline-test', 'late', {'requests': 1, 'tokens': 1, 'cost_usd': 0}, 'test')


async def test_execution_budget_stops_before_workload_dispatch(monkeypatch):
    from infosec_harness.domain.models import EnvironmentSpec, RepoSnapshot
    from infosec_harness.workflows.temporal_ops import TemporalOps

    ops = TemporalOps(root_id='batch', fingerprint='finding')
    async def exhausted(name, seconds):
        assert name == 'build_environment_activity'
        assert seconds == 40 * 60 * 3
        raise UsageLimitExceeded('Execution envelope exhausted')
    monkeypatch.setattr(ops._accounting, 'reserve_execution', exhausted)
    with pytest.raises(UsageLimitExceeded, match='Execution envelope'):
        await ops.build_environment(RepoSnapshot(repo_url='local', revision='HEAD',
            path='/tmp/unused', content_hash='unused'),
            EnvironmentSpec(base_image='python:3.12', install_commands=[], test_command='pytest'))


def test_partial_extended_budget_limits_are_rejected():
    with pytest.raises(ValueError, match='provided together'):
        budgets.initial_state({'requests': 1, 'tokens': 1, 'cost_usd': 0, 'tool_calls': 1})


async def test_accepted_agent_configuration_cannot_change_on_worker_restart():
    await db.create_all()
    state = budgets.initial_state({'requests': 10, 'tokens': 100, 'cost_usd': 1})
    state['agent_config_digests'] = {'agent': 'accepted-config'}
    async with db.session() as session:
        session.add(db.BudgetLedger(root_id='pinned-config', state=state))
        await session.commit()
    demand = {'requests': 1, 'tokens': 20, 'cost_usd': .1}
    with pytest.raises(ValueError, match='differs from the accepted batch'):
        await budgets.reserve('pinned-config', 'attempt', demand, 'agent', 'changed-config')
    with pytest.raises(ValueError, match='differs from the accepted batch'):
        await budgets.reserve('pinned-config', 'missing', demand, 'unknown-agent', 'accepted-config')
    assert await budgets.reserve('pinned-config', 'attempt', demand, 'agent', 'accepted-config')
    with pytest.raises(ValueError, match='different budget'):
        await budgets.reserve('pinned-config', 'attempt', {**demand, 'tokens': 30}, 'agent', 'accepted-config')


def test_temporal_ops_never_loads_configuration_during_workflow_execution(monkeypatch):
    from infosec_harness.agents import registry
    from infosec_harness.workflows.temporal_ops import TemporalOps
    def forbidden():
        raise AssertionError('Workflow attempted configuration I/O')
    monkeypatch.setattr(registry, 'resolved_agent_configs', forbidden)
    monkeypatch.setattr(registry, 'resolved_model_names', forbidden)
    assert TemporalOps(root_id='batch', fingerprint='finding')._configs['context'].agent_name == 'context'
