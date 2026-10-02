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
    assert caplog.messages == [f'IH_BUDGET_GUARD boundary=admission category={guard}']
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
    assert caplog.messages == [f'IH_BUDGET_GUARD boundary=ledger category={guard}']
    assert 'secret-lease' not in caplog.text and 'secret-config' not in caplog.text
    assert request.request_id not in caplog.text
