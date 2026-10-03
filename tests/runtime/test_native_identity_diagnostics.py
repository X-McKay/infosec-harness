import json

import pytest
from test_openshell_controller import native_fixture

from infosec_harness.inference.http_service import broker_error_body
from infosec_harness.inference.protocol import BrokerError


@pytest.mark.asyncio
@pytest.mark.parametrize('fault,category', [('pagination', 'provider_inventory'), ('metadata', 'provider_identity')])
async def test_native_create_identity_failure_logs_only_fixed_guard(tmp_path, caplog, fault, category):
    adapter, lease, _, _, _, _ = native_fixture(tmp_path)
    lease.native_id = ''
    lease.ledger_native_id = ''
    actions = []

    async def run(args, **kwargs):
        actions.append(args[:2])
        if args[:2] == ['provider', 'create']:
            return ''
        assert args == ['provider', 'list', '-o', 'json']
        return json.dumps({'providers': [{'name': 'ih-ledger-' + lease.lease_id, 'id': 'secret-native-id',
                            'type': 'ledger-profile', 'workspace': 'secret-wrong-workspace',
                            'credential_keys': ['IH_LEDGER_TOKEN']}],
                           'next_page_token': 'secret-pagination' if fault == 'pagination' else ''})

    adapter.cli.run = run
    with pytest.raises(BrokerError) as error:
        await adapter._create(lease, adapter.spec(lease.contract))
    assert error.value.code == 'identity' and error.value.diagnostic is None
    assert broker_error_body(error.value) == broker_error_body(BrokerError('identity'))
    assert not lease.native_id and not lease.ledger_native_id
    assert actions == [['provider', 'create'], ['provider', 'list']]
    assert caplog.messages == [f'IH_NATIVE_IDENTITY_FAILURE boundary=native_create category={category}']
    assert all(value not in caplog.text for value in [lease.lease_id, lease.ledger_key, 'secret-native-id',
                                                    'secret-wrong-workspace', 'secret-pagination'])


@pytest.mark.asyncio
async def test_native_revoke_foreign_identity_logs_without_destroying(tmp_path, caplog):
    adapter, lease, _, _, _, _ = native_fixture(tmp_path)
    actions = []

    async def run(args, **kwargs):
        actions.append(args[:2])
        assert args[:2] == ['sandbox', 'list']
        return json.dumps({'sandboxes': [{'id': 'foreign-secret-id', 'name': lease.name,
                                         'labels': lease.labels()}]})

    adapter.cli.run = run
    with pytest.raises(BrokerError) as error:
        await adapter.revoke(lease)
    assert error.value.code == 'identity' and error.value.diagnostic is None
    assert lease.status == 'ready'
    assert actions == [['sandbox', 'list']]
    assert caplog.messages == ['IH_NATIVE_IDENTITY_FAILURE boundary=native_revoke category=sandbox_identity']
    assert 'foreign-secret-id' not in caplog.text and lease.lease_id not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize('fault', ['labels', 'id'])
async def test_failed_first_get_preserves_quarantine_intent_without_upload(tmp_path, caplog, fault):
    adapter, _, _, _, _, _ = native_fixture(tmp_path)
    actions = []

    async def preflight():
        return None

    async def run(args, **kwargs):
        actions.append(args[:2])
        if args == ['--version']:
            return 'openshell 0.1.2'
        lease = next(value for value in adapter.leases.values() if value.run_id == 'fresh-diagnostic-run')
        if args[:2] in [['provider', 'create'], ['sandbox', 'create']]:
            return ''
        if args[:2] == ['provider', 'list']:
            return json.dumps({'providers': [{'name': 'ih-ledger-' + lease.lease_id,
                'id': 'owned-ledger-id', 'type': 'ledger-profile', 'workspace': 'default',
                'credential_keys': ['IH_LEDGER_TOKEN']}]})
        assert args[:2] == ['sandbox', 'get']
        return json.dumps({'id': '' if fault == 'id' else 'secret-native-id',
                           'labels': {'secret-wrong-label': 'secret-value'} if fault == 'labels' else lease.labels()})

    adapter.cli.preflight = preflight
    adapter.cli.run = run
    contract = next(iter(adapter.leases.values())).contract
    with pytest.raises(BrokerError) as error:
        await adapter.ensure('fresh-diagnostic-run', contract)
    lease = next(value for value in adapter.leases.values() if value.run_id == 'fresh-diagnostic-run')
    assert error.value.code == 'identity' and error.value.diagnostic is None
    assert lease.status == 'quarantined' and not lease.native_id and lease.ledger_native_id == 'owned-ledger-id'
    assert all(action not in [['sandbox', 'upload'], ['service', 'expose']] for action in actions)
    assert caplog.messages == ['IH_NATIVE_IDENTITY_FAILURE boundary=native_create category=sandbox_creation_identity '
                              + ('labels_match=False id_present=True' if fault == 'labels' else 'labels_match=True id_present=False')]
    assert all(value not in caplog.text for value in [lease.lease_id, lease.ledger_key, 'secret-native-id',
                                                    'secret-wrong-label', 'secret-value'])
