"""Transport/security boundaries for hosted persistence, without hosted writes."""
from __future__ import annotations

import ssl
from types import SimpleNamespace

import boto3
import pytest
from alembic.script import ScriptDirectory
from botocore.exceptions import ClientError, EndpointConnectionError
from botocore.stub import Stubber

from infosec_harness.persistence import artifacts, db


def tls_settings(**changes):
    return SimpleNamespace(database_tls=True, database_tls_ca_file=None,
        database_tls_client_cert=None, database_tls_client_key=None, **changes)


def test_postgresql_system_trust_requires_certificate_and_hostname():
    context = db.database_connect_args('postgresql+asyncpg://operator:encoded%40password@db.example/harness',
                                       tls_settings())['ssl']
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert context.get_ca_certs()


@pytest.mark.parametrize('url,enabled', [('sqlite+aiosqlite:///:memory:', True),
    ('sqlite+aiosqlite:///:memory:', False), ('postgresql+asyncpg://db/harness', False)])
def test_existing_sqlite_and_non_tls_connections_do_not_receive_ssl_args(url, enabled):
    values = tls_settings()
    values.database_tls = enabled
    assert db.database_connect_args(url, values) == {}


def test_postgresql_private_ca_is_loaded_and_missing_ca_fails_closed(tmp_path):
    ca = tmp_path / 'absent-ca.pem'
    values = tls_settings()
    values.database_tls_ca_file = ca
    with pytest.raises(FileNotFoundError):
        db.database_connect_args('postgresql+asyncpg://db/harness', values)


def test_client_certificate_pair_is_complete_and_loaded(monkeypatch):
    values = tls_settings()
    values.database_tls_client_cert = 'client.pem'
    with pytest.raises(ValueError, match='configured together'):
        db.database_connect_args('postgresql+asyncpg://db/harness', values)
    values.database_tls_client_key = 'client.key'
    loaded = []
    original = ssl.create_default_context
    context = original()
    monkeypatch.setattr(ssl, 'create_default_context', lambda **_: context)
    monkeypatch.setattr(ssl.SSLContext, 'load_cert_chain', lambda self, cert, key: loaded.append((cert, key)))
    assert db.database_connect_args('postgresql+asyncpg://db/harness', values)['ssl'] is context
    assert loaded == [('client.pem', 'client.key')]
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED


def test_unqualified_database_driver_cannot_ignore_enabled_tls():
    with pytest.raises(ValueError, match=r'postgresql\+asyncpg'):
        db.database_connect_args('mysql+aiomysql://db/harness', tls_settings())


def test_migration_roundtrips_percent_url_through_real_alembic(tmp_path):
    target = tmp_path / 'encoded%20database.db'
    head = ScriptDirectory.from_config(db.alembic_config()).get_current_head()
    assert db.upgrade_to_head(f'sqlite+aiosqlite:///{target}') == head
    assert target.exists()


def s3_settings(**changes):
    values = dict(s3_endpoint='', s3_region='us-east-1', s3_bucket='owned-test-bucket',
        s3_access_key='', s3_secret_key='', s3_session_token='', s3_ca_file=None,
        s3_addressing_style='auto', s3_create_bucket=True, artifact_backend='s3')
    return SimpleNamespace(**{**values, **changes})


@pytest.fixture
def client(monkeypatch):
    value = boto3.client('s3', region_name='us-east-1', aws_access_key_id='offline-test-key',
                         aws_secret_access_key='offline-test-secret')
    observed = []
    monkeypatch.setattr(boto3, 'client', lambda *args, **kwargs: observed.append((args, kwargs)) or value)
    return value, observed


def test_hosted_s3_uses_verified_tls_session_credentials_and_addressing(client, monkeypatch, tmp_path):
    value, observed = client
    settings = s3_settings(s3_ca_file=tmp_path / 'operator-ca.pem', s3_session_token='offline-session',
                           s3_addressing_style='virtual')
    monkeypatch.setattr(artifacts, 'get_settings', lambda: settings)
    with Stubber(value) as stub:
        stub.add_response('head_bucket', {}, {'Bucket': settings.s3_bucket})
        artifacts.S3Store()
        stub.assert_no_pending_responses()
    args, options = observed[0]
    assert args == ('s3',)
    assert options['endpoint_url'] is None
    assert options['aws_access_key_id'] is None and options['aws_secret_access_key'] is None
    assert options['aws_session_token'] == 'offline-session'
    assert options['verify'] == str(settings.s3_ca_file)
    assert options['config'].s3['addressing_style'] == 'virtual'


@pytest.mark.parametrize('region', ['us-east-1', 'eu-west-1'])
def test_missing_bucket_create_is_explicit_and_region_correct(client, monkeypatch, region):
    value, _ = client
    settings = s3_settings(s3_region=region)
    monkeypatch.setattr(artifacts, 'get_settings', lambda: settings)
    request = {'Bucket': settings.s3_bucket}
    if region != 'us-east-1':
        request['CreateBucketConfiguration'] = {'LocationConstraint': region}
    with Stubber(value) as stub:
        stub.add_client_error('head_bucket', service_error_code='NoSuchBucket', http_status_code=404,
                              expected_params={'Bucket': settings.s3_bucket})
        stub.add_response('create_bucket', {}, request)
        artifacts.S3Store()
        stub.assert_no_pending_responses()


@pytest.mark.parametrize('code,status,create', [('AccessDenied',403,True), ('InternalError',500,True),
    ('NoSuchBucket',500,True), ('NoSuchBucket',404,False)])
def test_access_transient_errors_and_no_create_policy_never_create(client, monkeypatch, code, status, create):
    value, observed = client
    settings = s3_settings(s3_create_bucket=create)
    monkeypatch.setattr(artifacts, 'get_settings', lambda: settings)
    with Stubber(value) as stub:
        stub.add_client_error('head_bucket', service_error_code=code, http_status_code=status,
                              expected_params={'Bucket': settings.s3_bucket})
        with pytest.raises(ClientError):
            artifacts.S3Store()
        stub.assert_no_pending_responses()
    assert observed[0][1]['verify'] is True


def test_network_failure_does_not_attempt_bucket_creation(client, monkeypatch):
    value, _ = client
    monkeypatch.setattr(artifacts, 'get_settings', lambda: s3_settings())
    calls = []
    def fail(**_):
        raise EndpointConnectionError(endpoint_url='https://s3.example')
    monkeypatch.setattr(value, 'head_bucket', fail)
    monkeypatch.setattr(value, 'create_bucket', lambda **kwargs: calls.append(kwargs))
    with pytest.raises(EndpointConnectionError):
        artifacts.S3Store()
    assert calls == []


@pytest.mark.parametrize('backend,endpoint,expected', [('s3','','s3'), ('filesystem','https://local','fs'),
    ('auto','','fs'), ('auto','http://local','s3')])
def test_backend_selection_supports_aws_chain_and_existing_local_defaults(monkeypatch, backend, endpoint, expected):
    monkeypatch.setattr(artifacts, 'get_settings', lambda: s3_settings(artifact_backend=backend, s3_endpoint=endpoint))
    monkeypatch.setattr(artifacts, 'S3Store', lambda: 's3')
    monkeypatch.setattr(artifacts, 'FilesystemStore', lambda: 'fs')
    artifacts.get_store.cache_clear()
    try:
        assert artifacts.get_store() == expected
    finally:
        artifacts.get_store.cache_clear()


def test_operator_ca_bundle_controls_postgresql_trust(tmp_path):
    certificate = ssl.create_default_context().get_ca_certs(binary_form=True)[0]
    ca = tmp_path / 'operator-ca.pem'
    ca.write_text(ssl.DER_cert_to_PEM_cert(certificate))
    settings = tls_settings()
    settings.database_tls_ca_file = ca
    context = db.database_connect_args('postgresql+asyncpg://db.example/harness', settings)['ssl']
    assert context.get_ca_certs(binary_form=True) == [certificate]
    assert context.check_hostname is True and context.verify_mode == ssl.CERT_REQUIRED


def test_runtime_engine_receives_shared_verified_tls_policy(monkeypatch):
    values = tls_settings()
    values.database_url = 'postgresql+asyncpg://db.example/harness'
    monkeypatch.setattr(db, 'get_settings', lambda: values)
    captured = []
    monkeypatch.setattr(db, 'create_async_engine', lambda url, **options: captured.append((url, options)))
    db._engine.cache_clear()
    try:
        db._engine()
        assert captured[0][0] == values.database_url
        context = captured[0][1]['connect_args']['ssl']
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
        assert captured[0][1]['pool_pre_ping'] is True
    finally:
        db._engine.cache_clear()


def test_missing_client_certificate_files_fail_before_connection(tmp_path):
    settings = tls_settings()
    settings.database_tls_client_cert = tmp_path / 'absent-client.pem'
    settings.database_tls_client_key = tmp_path / 'absent-client.key'
    with pytest.raises(FileNotFoundError):
        db.database_connect_args('postgresql+asyncpg://db.example/harness', settings)
