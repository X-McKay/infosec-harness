from __future__ import annotations

import http.client
import json
import ssl
import stat
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from broker_fixtures import (
    CANARY_AUTHORIZATION,
    CANARY_TOKEN,
    PLACEHOLDER,
    MockUpstream,
    assert_no_secret_material,
)
from broker_g0_executor import ExecutorSettings, _call_controller, _NoRedirect
from broker_g0_services import (
    LEDGER_PATH,
    MAX_REQUEST_BYTES,
    PROVIDER_PATH,
    ROTATED_CANARY_AUTHORIZATION,
    ROTATED_CANARY_TOKEN,
    G0Services,
)

LEDGER_TOKEN = "g0-ledger-test-token-scoped"
REQUEST_BODY = b'{"model":"fixed-model","messages":[]}'


def _request(
    url: str,
    context: ssl.SSLContext,
    *,
    path: str,
    method: str = "POST",
    authorization: str,
    body: bytes = REQUEST_BODY,
) -> tuple[int, bytes]:
    request = urllib.request.Request(
        url + path,
        data=body,
        method=method,
        headers={"Authorization": authorization, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, context=context, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


@pytest.fixture
def services(tmp_path: Path):
    with MockUpstream() as certificate_source:
        stats_path = tmp_path / "safe" / "stats.json"
        with G0Services(
            certificate=certificate_source.certificate,
            private_key=certificate_source.private_key,
            ledger_token=LEDGER_TOKEN,
            stats_file=stats_path,
            port=0,
        ) as server:
            context = ssl.create_default_context(cafile=str(certificate_source.certificate))
            host, port = server.address
            yield f"https://localhost:{port}", context, stats_path


def test_provider_and_ledger_routes_admit_only_fixed_credentials(services):
    url, context, stats_path = services
    status, provider_response = _request(
        url, context, path=PROVIDER_PATH, authorization=CANARY_AUTHORIZATION
    )
    assert status == 200
    provider = json.loads(provider_response)
    assert provider["usage"] == {
        "prompt_tokens": 3,
        "completion_tokens": 2,
        "total_tokens": 5,
    }
    assert provider["choices"][0]["message"]["content"] == "g0-fixture-response"

    status, ledger_response = _request(
        url, context, path=LEDGER_PATH, authorization=f"Bearer {LEDGER_TOKEN}"
    )
    assert status == 200
    assert json.loads(ledger_response) == {"accepted": True}
    counts = json.loads(stats_path.read_text(encoding="utf-8"))
    assert counts == {"denied": 0, "ledger_admitted": 1, "provider_admitted": 1}
    assert stat.S_IMODE(stats_path.stat().st_mode) == 0o600
    stats = stats_path.read_bytes()
    assert_no_secret_material(stats)
    assert LEDGER_TOKEN.encode() not in stats
    assert PLACEHOLDER.encode() not in stats
    assert CANARY_TOKEN.encode() not in provider_response + ledger_response


def test_frozen_executor_controller_call_accepts_real_tls_service_without_provider_dispatch(
    services,
):
    url, context, stats_path = services
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirect(),
        urllib.request.HTTPSHandler(context=context),
    )
    settings = ExecutorSettings(
        upstream_url="https://provider.invalid",
        admission_key=b"test-only-unused-controller-conformance",
        provider_placeholder="openshell:resolve:env:G0_PROVIDER_TOKEN",
        controller_url=url,
        ledger_token=LEDGER_TOKEN,
    )

    # The executor's frozen contract treats a non-accepted response as failure.
    # This call uses the real TLS fixture, not an injected or mocked response.
    _call_controller(settings, opener)
    assert json.loads(stats_path.read_text(encoding="utf-8")) == {
        "denied": 0,
        "ledger_admitted": 1,
        "provider_admitted": 0,
    }


def test_rotated_test_credential_rejects_old_value_and_preserves_ledger(tmp_path: Path):
    with MockUpstream() as certificate_source:
        stats_path = tmp_path / "rotation-stats.json"
        with G0Services(
            certificate=certificate_source.certificate,
            private_key=certificate_source.private_key,
            ledger_token=LEDGER_TOKEN,
            stats_file=stats_path,
            port=0,
            credential_revision="v2",
        ) as server:
            context = ssl.create_default_context(cafile=str(certificate_source.certificate))
            host, port = server.address
            url = f"https://localhost:{port}"
            old_status, old_response = _request(
                url,
                context,
                path=PROVIDER_PATH,
                authorization=CANARY_AUTHORIZATION,
            )
            new_status, new_response = _request(
                url,
                context,
                path=PROVIDER_PATH,
                authorization=ROTATED_CANARY_AUTHORIZATION,
            )
            ledger_status, ledger_response = _request(
                url,
                context,
                path=LEDGER_PATH,
                authorization=f"Bearer {LEDGER_TOKEN}",
            )

    assert old_status == 403
    assert json.loads(old_response) == {"error": "request_denied"}
    assert new_status == 200
    assert json.loads(new_response)["usage"]["total_tokens"] == 5
    assert ledger_status == 200
    assert json.loads(ledger_response) == {"accepted": True}
    assert json.loads(stats_path.read_text(encoding="utf-8")) == {
        "denied": 1,
        "ledger_admitted": 1,
        "provider_admitted": 1,
    }
    stats = stats_path.read_bytes()
    assert_no_secret_material(stats)
    assert_no_secret_material(stats, canary_token=ROTATED_CANARY_TOKEN)
    assert LEDGER_TOKEN.encode() not in stats


def test_missing_bad_auth_and_wrong_method_or_route_are_denied(services):
    url, context, stats_path = services
    cases = [
        (PROVIDER_PATH, ""),
        (PROVIDER_PATH, "Bearer wrong-test-value"),
        (LEDGER_PATH, CANARY_AUTHORIZATION),
        ("/unexpected", CANARY_AUTHORIZATION),
    ]
    for path, authorization in cases:
        status, body = _request(url, context, path=path, authorization=authorization)
        assert status == 403
        assert json.loads(body) == {"error": "request_denied"}

    status, body = _request(
        url,
        context,
        path=PROVIDER_PATH,
        method="PUT",
        authorization=CANARY_AUTHORIZATION,
    )
    assert status == 403
    assert json.loads(body) == {"error": "request_denied"}
    counts = json.loads(stats_path.read_text(encoding="utf-8"))
    assert counts == {"denied": 5, "ledger_admitted": 0, "provider_admitted": 0}
    assert_no_secret_material(stats_path.read_bytes())
    assert LEDGER_TOKEN.encode() not in stats_path.read_bytes()


def test_request_content_is_never_echoed_or_retained(services):
    url, context, stats_path = services
    unknown = f"{CANARY_TOKEN} {PLACEHOLDER} repository-private-body".encode()
    status, response = _request(
        url,
        context,
        path="/unknown/" + CANARY_TOKEN,
        authorization=CANARY_AUTHORIZATION,
        body=unknown,
    )
    assert status == 403
    assert CANARY_TOKEN.encode() not in response
    assert PLACEHOLDER.encode() not in response
    stats = stats_path.read_bytes()
    assert_no_secret_material(stats)
    assert b"repository-private-body" not in stats


def test_leak_scanner_positive_control_is_sanitized():
    with pytest.raises(AssertionError) as caught:
        assert_no_secret_material(CANARY_TOKEN)
    assert CANARY_TOKEN not in str(caught.value)
    assert CANARY_AUTHORIZATION not in str(caught.value)


def test_invalid_certificate_configuration_fails_closed(tmp_path: Path):
    with pytest.raises(ValueError, match="certificate and private key"):
        G0Services(
            certificate=tmp_path / "missing.crt",
            private_key=tmp_path / "missing.key",
            ledger_token=LEDGER_TOKEN,
            stats_file=tmp_path / "stats.json",
        )


def test_new_service_epoch_publishes_zero_counts_before_serving(tmp_path: Path):
    with MockUpstream() as certificate_source:
        stats_path = tmp_path / "existing-stats.json"
        stats_path.write_text(
            '{"denied":9,"ledger_admitted":8,"provider_admitted":7}\n', encoding="utf-8"
        )
        service = G0Services(
            certificate=certificate_source.certificate,
            private_key=certificate_source.private_key,
            ledger_token=LEDGER_TOKEN,
            stats_file=stats_path,
            port=0,
        )
        try:
            assert json.loads(stats_path.read_text(encoding="utf-8")) == {
                "denied": 0,
                "ledger_admitted": 0,
                "provider_admitted": 0,
            }
            assert not service.thread.is_alive()
        finally:
            service.close()


def test_tls_setup_failure_does_not_publish_fresh_zero_counts(tmp_path: Path):
    bad_cert = tmp_path / "invalid.crt"
    bad_key = tmp_path / "invalid.key"
    bad_cert.write_text("not a certificate", encoding="utf-8")
    bad_key.write_text("not a private key", encoding="utf-8")
    stats_path = tmp_path / "old-stats.json"
    old_stats = b'{"denied":4,"ledger_admitted":3,"provider_admitted":2}\n'
    stats_path.write_bytes(old_stats)

    with pytest.raises((OSError, ValueError)):
        G0Services(
            certificate=bad_cert,
            private_key=bad_key,
            ledger_token=LEDGER_TOKEN,
            stats_file=stats_path,
            port=0,
        )
    assert stats_path.read_bytes() == old_stats


def test_tls_requires_operator_ca(services):
    url, _trusted, stats_path = services
    with pytest.raises(urllib.error.URLError):
        _request(
            url,
            ssl.create_default_context(),
            path=PROVIDER_PATH,
            authorization=CANARY_AUTHORIZATION,
        )
    # A failed TLS handshake never increments the freshly published zero counters.
    assert json.loads(stats_path.read_text(encoding="utf-8")) == {
        "denied": 0,
        "ledger_admitted": 0,
        "provider_admitted": 0,
    }


def test_malformed_negative_and_oversized_lengths_reject_promptly(services):
    url, context, stats_path = services
    port = int(url.rsplit(":", 1)[1])
    for length, expected in (("malformed", 400), ("-1", 400), (str(MAX_REQUEST_BYTES + 1), 413)):
        connection = http.client.HTTPSConnection("localhost", port, context=context, timeout=5)
        try:
            connection.putrequest("POST", PROVIDER_PATH)
            connection.putheader("Authorization", CANARY_AUTHORIZATION)
            connection.putheader("Content-Length", length)
            connection.endheaders()
            response = connection.getresponse()
            response.read()
            assert response.status == expected
        finally:
            connection.close()
    assert json.loads(stats_path.read_text(encoding="utf-8")) == {
        "denied": 3,
        "ledger_admitted": 0,
        "provider_admitted": 0,
    }
