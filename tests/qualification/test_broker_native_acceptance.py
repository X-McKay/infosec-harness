"""Native acceptance guards and the counted mock HTTPS provider it observes."""
from __future__ import annotations

import http.client
import json
import shutil
import ssl

import pytest
from broker_qualification_support import BOUNDS

from infosec_harness.inference.protocol import BrokerError
from infosec_harness.qualification.broker import native
from infosec_harness.qualification.broker.service import generate_pki

MOCK_ENDPOINT = "https://192.0.2.10:18443/v1"


@pytest.fixture
def pki(tmp_path):
    if shutil.which("openssl") is None:
        pytest.skip("the mock provider TLS fixture needs the OpenSSL CLI")
    directory = tmp_path / "pki"
    directory.mkdir()
    return generate_pki(directory)


def post(provider, pki, path, body=b"{}", headers=None):
    context = ssl.create_default_context(cafile=pki["ca"])
    host, port = provider.address
    connection = http.client.HTTPSConnection("localhost", port, context=context, timeout=5)
    try:
        connection.request("POST", path, body=body, headers={"Content-Type": "application/json", **(headers or {})})
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


def test_mock_provider_admits_only_the_canary_and_publishes_counts_only(tmp_path, pki):
    stats = tmp_path / "evidence" / native.STATS_FILE
    with native.MockProvider(certificate=pki["server_cert"], private_key=pki["server_key"], stats_file=stats) as provider:
        assert json.loads(stats.read_text()) == {"denied": 0, "provider_admitted": 0}
        status, body = post(provider, pki, native.PROVIDER_PATH, headers={"Authorization": native.CANARY_AUTHORIZATION})
        assert status == 200 and body["choices"][0]["message"]["content"] == native.MOCK_RESPONSE
        assert body["model"] == native.MOCK_MODEL
        assert post(provider, pki, native.PROVIDER_PATH, headers={"Authorization": "Bearer real-key"})[0] == 403
        assert post(provider, pki, "/v1/other", headers={"Authorization": native.CANARY_AUTHORIZATION})[0] == 403
        oversized = b"x" * (native.MAX_REQUEST_BYTES + 1)
        assert post(provider, pki, native.PROVIDER_PATH, body=oversized,
                    headers={"Authorization": native.CANARY_AUTHORIZATION})[0] == 413
    assert json.loads(stats.read_text()) == {"denied": 3, "provider_admitted": 1}
    assert stats.stat().st_mode & 0o077 == 0
    assert native.CANARY_AUTHORIZATION.split()[1] not in stats.read_text()


def test_mock_provider_requires_operator_tls_files(tmp_path):
    with pytest.raises(ValueError, match="certificate and private key files must exist"):
        native.MockProvider(certificate=tmp_path / "missing.pem", private_key=tmp_path / "missing.key",
                            stats_file=tmp_path / "stats.json")


def mock_contract(**changes) -> dict:
    from infosec_harness.inference.profiles import BrokerConfig, registered_agents

    profile = {"backend_name": native.MOCK_BACKEND, "endpoint": MOCK_ENDPOINT, "provider_binding": "mock-canary",
               "provider_env": "MOCK_PROVIDER", "ledger_origin": "https://controller.test",
               "ledger_profile": "ledger-v1", "executor_image": "sha256:" + "1" * 64,
               "supervisor_image": "sha256:" + "2" * 64, "approved_policy": {"version": 1, "network_policies": {}}}
    catalog = BrokerConfig.model_validate({
        "version": 1, "enabled": True,
        "controller": {"url": "https://controller.test", "hmac_env": "MOCK_WORKER_KEY", "ca_file": "/ca.pem"},
        "profiles": {"mock": profile}, "agent_profiles": dict.fromkeys(registered_agents(), "mock"),
        "root_limits": BOUNDS, "agent_limits": dict.fromkeys(registered_agents(), BOUNDS)})
    contract = catalog.resolve_contract(native.AGENT, native.MOCK_BACKEND, native.MOCK_MODEL, {"max_tokens": 32},
                                        backend_endpoint=MOCK_ENDPOINT).model_dump(mode="json")
    contract.update(changes)
    return contract


def write_config(tmp_path, monkeypatch, *, scope="local", **contract_changes):
    path = tmp_path / "native-config.json"
    path.write_text(json.dumps({"scope": scope, "contract": mock_contract(**contract_changes)}))
    monkeypatch.setenv("IH_NATIVE_FIXTURE_CONFIG", str(path))


@pytest.mark.parametrize("scope,mode", [("local", "local"), ("temporal", "temporal"), ("cachepoint", "local")])
def test_each_acceptance_scope_has_one_static_invocation(tmp_path, monkeypatch, scope, mode):
    write_config(tmp_path, monkeypatch, scope=scope)
    request = native.reference()
    assert request.mode == mode
    assert request.root_id == f"native-fixture-{scope}-root" and request.agent == native.AGENT
    assert request.contract.model == native.MOCK_MODEL


@pytest.mark.parametrize("scope,changes,message", [
    ("local", {"backend": "gateway"}, "only the mock backend"),
    ("local", {"model": "real-model"}, "only the mock model"),
    ("temporal-rerun", {}, "Unknown native acceptance scope"),
])
def test_acceptance_refuses_non_mock_targets_and_unknown_scopes(tmp_path, monkeypatch, scope, changes, message):
    write_config(tmp_path, monkeypatch, scope=scope, **changes)
    with pytest.raises(BrokerError, match=message):
        native.configuration()
