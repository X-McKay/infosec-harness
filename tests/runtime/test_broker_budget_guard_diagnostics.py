import copy
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from test_broker_executor import request_fixture

from infosec_harness.inference import admission, ledger
from infosec_harness.inference.http_service import broker_error_body
from infosec_harness.inference.protocol import BrokerError


@pytest.mark.asyncio
@pytest.mark.parametrize('guard', ['output_cap', 'input_reserve', 'price_ceiling'])
async def test_admission_budget_logs_fixed_guard_before_allocation(monkeypatch, caplog, guard):
    request, _ = request_fixture()
    policy = admission.ReservationPolicy(request.binding.agent, request.contract.profile,
        request.contract.digest, 'secret-config', 50, 15 if guard == 'output_cap' else 16,
        0, 1 if guard == 'price_ceiling' else None, 1 if guard == 'price_ceiling' else None)
    rendered = []

    async def reserve(*args):
        rendered.append(True)
        return 51 if guard == 'input_reserve' else 50

    monkeypatch.setattr(admission, 'required_input_reserve', reserve)
    with pytest.raises(BrokerError) as error:
        await admission.authorize(request, policy)
    assert rendered == ([] if guard == 'output_cap' else [True])
    assert error.value.code == 'budget' and error.value.diagnostic is None
    assert broker_error_body(error.value) == broker_error_body(BrokerError('budget'))
    expected = f'IH_BUDGET_GUARD boundary=admission category={guard}'
    if guard == 'input_reserve':
        expected += ' reserve=51 limit=50'
    assert caplog.messages == [expected]
    assert 'secret-config' not in caplog.text and request.request_id not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize('guard', ['active_overrun', 'cumulative_allocation'])
async def test_ledger_budget_rejects_before_mutation_or_dispatch(monkeypatch, caplog, guard):
    request, _ = request_fixture()
    monkeypatch.setattr(ledger.time, 'time', lambda: 100)
    operation = {'agent': request.binding.agent, 'kind': 'agent', 'status': 'uncertain',
        'broker_binding': request.binding.model_dump(mode='json'),
        'broker_configuration_digest': 'secret-config', 'reserved': {'requests': 1, 'tokens': 100, 'cost_usd': 0},
        'broker_allocated': {'requests': 1, 'tokens': 100, 'cost_usd': 0}}
    if guard == 'active_overrun':
        operation['broker_overrun'] = {'tokens': 1}
    state = {'deadline_at': datetime.fromtimestamp(300, UTC).isoformat(),
             'agent_config_digests': {request.binding.agent: 'secret-config'},
             'operations': {request.binding.operation_id: operation}}
    original = copy.deepcopy(state)
    observations = []

    class ReadOnlySession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, model, identity):
            observations.append(model)
            if model is ledger.db.InferenceRequestRecord:
                return None
            assert model is ledger.db.BudgetLedger
            return SimpleNamespace(state=state)

        async def execute(self, *args):
            pytest.fail('Budget denial must not reach allocation CAS')

        def add(self, *args):
            pytest.fail('Budget denial must not insert a request')

        async def commit(self):
            pytest.fail('Budget denial must not commit')

    monkeypatch.setattr(ledger.db, 'session', ReadOnlySession)
    with pytest.raises(BrokerError) as error:
        await ledger.admit(request, lease_id='secret-lease', allocation={'requests': 1, 'tokens': 100, 'cost_usd': 0})
    assert error.value.code == 'budget' and state == original
    assert len(observations) == 2 and error.value.diagnostic is None
    expected = ([f'IH_BUDGET_GUARD boundary=ledger category={guard}']
                if guard == 'active_overrun' else [
                    'IH_BUDGET_GUARD boundary=ledger category=cumulative_allocation dimension=requests allocated=2 reserved=1',
                    'IH_BUDGET_GUARD boundary=ledger category=cumulative_allocation dimension=tokens allocated=200 reserved=100'])
    assert caplog.messages == expected
    assert 'secret-lease' not in caplog.text and 'secret-config' not in caplog.text
    assert request.request_id not in caplog.text


@pytest.mark.asyncio
async def test_input_reserve_at_the_exact_limit_is_accepted_without_logs_or_sql(monkeypatch, caplog):
    request, _ = request_fixture()
    policy = admission.ReservationPolicy(request.binding.agent, request.contract.profile,
        request.contract.digest, 'secret-config', 50, 16, 0)
    async def reserve(*args):
        return 50
    monkeypatch.setattr(admission, 'required_input_reserve', reserve)
    monkeypatch.setattr(admission.db, 'session', lambda: pytest.fail('Authorize cannot use SQL'))
    assert await admission.authorize(request, policy) == {'requests': 1, 'tokens': 66, 'cost_usd': 0}
    assert caplog.messages == []


@pytest.mark.asyncio
@pytest.mark.parametrize('dimension', ['requests', 'tokens', 'cost_usd', None, 'large_integer'])
async def test_cumulative_numeric_diagnostic_identifies_only_exhausted_dimension(
        monkeypatch, caplog, dimension):
    request, _ = request_fixture()
    monkeypatch.setattr(ledger.time, 'time', lambda: 100)
    demand = {'requests': 1, 'tokens': 10, 'cost_usd': 0.125}
    allocated = {'requests': 1, 'tokens': 10, 'cost_usd': 0.125}
    reserved = {'requests': 2, 'tokens': 20, 'cost_usd': 0.25}
    if dimension == 'large_integer':
        dimension = 'requests'
        reserved['tokens'] = 10 ** 400
    if dimension is not None:
        reserved[dimension] = allocated[dimension]
    operation = {'agent': request.binding.agent, 'status': 'uncertain',
        'broker_binding': request.binding.model_dump(mode='json'),
        'broker_configuration_digest': 'secret-config', 'reserved': reserved,
        'broker_allocated': allocated, 'secret-report': 'raw-payload-secret'}
    state = {'deadline_at': datetime.fromtimestamp(300, UTC).isoformat(),
        'agent_config_digests': {request.binding.agent: 'secret-config'},
        'operations': {request.binding.operation_id: operation}}
    original = copy.deepcopy(state)
    class BoundaryReached(Exception):
        pass
    class Session:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return None
        async def get(self, model, identity):
            return None if model is ledger.db.InferenceRequestRecord else SimpleNamespace(state=state)
        async def execute(self, *args):
            pytest.fail('Must not mutate SQL')
        def add(self, *args):
            pytest.fail('Must not insert a request')
        async def commit(self):
            pytest.fail('Must not commit')
    checkpoints = []
    async def checkpoint(phase):
        checkpoints.append(phase)
        raise BoundaryReached
    monkeypatch.setattr(ledger.db, 'session', Session)
    monkeypatch.setattr(ledger, '_checkpoint', checkpoint)
    with pytest.raises(BoundaryReached if dimension is None else BrokerError) as error:
        await ledger.admit(request, lease_id='secret-lease', allocation=demand)
    assert state == original
    if dimension is None:
        assert checkpoints == ['admit_before_cas'] and caplog.messages == []
    else:
        assert error.value.code == 'budget' and error.value.diagnostic is None
        assert broker_error_body(error.value) == broker_error_body(BrokerError('budget'))
        assert checkpoints == []
        assert caplog.messages == [
            'IH_BUDGET_GUARD boundary=ledger category=cumulative_allocation '
            f'dimension={dimension} allocated={allocated[dimension] + demand[dimension]:g} '
            f'reserved={reserved[dimension]:g}']
    assert not any(value in caplog.text for value in
        ['raw-payload-secret', 'secret-report', 'secret-config', 'secret-lease', request.request_id])
