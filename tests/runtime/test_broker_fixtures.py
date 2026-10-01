from __future__ import annotations

import http.client
import json
import ssl
import urllib.error
import urllib.request

import pytest
from broker_fixtures import (
    CANARY_AUTHORIZATION,
    CANARY_TOKEN,
    CHAT_COMPLETIONS_PATH,
    MAX_REQUEST_BYTES,
    PLACEHOLDER,
    MockUpstream,
    assert_no_secret_material,
)


def request(
    url: str,
    context: ssl.SSLContext,
    *,
    path: str = CHAT_COMPLETIONS_PATH,
    method: str = "POST",
    authorization: str = CANARY_AUTHORIZATION,
    body: bytes = b'{"model":"fixture-model","messages":[]}',
) -> tuple[int, bytes]:
    req = urllib.request.Request(
        url + path,
        data=body if method == "POST" else None,
        method=method,
        headers={"Authorization": authorization, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, context=context, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def raw_tls_request(upstream: MockUpstream, *, content_length: str, body: bytes = b"") -> int:
    connection = http.client.HTTPSConnection(
        "localhost",
        upstream.server.server_port,
        context=upstream.client_context(),
        timeout=5,
    )
    try:
        connection.putrequest("POST", CHAT_COMPLETIONS_PATH)
        connection.putheader("Authorization", CANARY_AUTHORIZATION)
        connection.putheader("Content-Length", content_length)
        connection.endheaders(body)
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def test_mock_upstream_accepts_exact_route_and_canary_without_retaining_secret():
    with MockUpstream() as upstream:
        status, body = request(upstream.url, upstream.client_context())
        assert status == 200
        payload = json.loads(body)
        assert payload["choices"][0]["message"]["content"] == "fixture response"
        assert payload["usage"] == {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}
        assert upstream.permitted_count == 1
        assert upstream.denied_count == 0
        assert upstream.server.permitted == [
            {"method": "POST", "exact_route": True, "authorized": True}
        ]
        assert_no_secret_material(body)
        assert CANARY_TOKEN.encode() not in body


def test_denials_count_route_method_and_auth_mismatches_without_retaining_inputs():
    with MockUpstream() as upstream:
        trusted = upstream.client_context()
        for kwargs in ({"path": "/v1/other"}, {"method": "GET"}, {"authorization": "Bearer wrong"}):
            status, body = request(upstream.url, trusted, **kwargs)
            assert status == 403
            assert json.loads(body)["error"]["message"] == "request denied"
        assert upstream.permitted_count == 0
        assert upstream.denied_count == 3


def test_canary_in_path_and_body_is_not_retained_in_request_records():
    with MockUpstream() as upstream:
        status, response = request(
            upstream.url,
            upstream.client_context(),
            path=f"/v1/other/{CANARY_TOKEN}",
            body=f'{{"secret":"{CANARY_AUTHORIZATION}"}}'.encode(),
        )
        assert status == 403
        assert upstream.server.denied == [
            {"method": "POST", "exact_route": False, "authorized": True}
        ]
        records = repr(upstream.server.denied)
        assert CANARY_TOKEN not in records
        assert CANARY_AUTHORIZATION not in records
        assert_no_secret_material(response)
        assert CANARY_TOKEN.encode() not in response


def test_malformed_negative_and_oversized_content_lengths_reject_without_reading_body():
    with MockUpstream() as upstream:
        assert raw_tls_request(upstream, content_length="malformed") == 400
        assert raw_tls_request(upstream, content_length="-1") == 400
        # Declare more than the cap while sending no body; response proves no blocking read.
        assert raw_tls_request(upstream, content_length=str(MAX_REQUEST_BYTES + 1)) == 413
        assert upstream.permitted_count == 0
        assert upstream.denied_count == 0


def test_tls_requires_trusted_ca():
    with MockUpstream() as upstream:
        with pytest.raises(urllib.error.URLError):
            request(upstream.url, ssl.create_default_context())
        assert upstream.permitted_count == 0
        assert upstream.denied_count == 0


@pytest.mark.parametrize(
    "payload",
    [
        CANARY_TOKEN,
        CANARY_TOKEN.encode(),
        CANARY_AUTHORIZATION,
        CANARY_AUTHORIZATION.encode(),
    ],
)
def test_scanner_rejects_raw_token_and_authorization_without_echoing_it(payload):
    with pytest.raises(AssertionError) as exc:
        assert_no_secret_material(payload)
    assert CANARY_TOKEN not in str(exc.value)
    assert CANARY_AUTHORIZATION not in str(exc.value)
    assert_no_secret_material(b"safe output")


def test_scanner_rejects_placeholder_without_echoing_it():
    with pytest.raises(AssertionError) as exc:
        assert_no_secret_material(b"prefix " + PLACEHOLDER.encode() + b" suffix")
    assert PLACEHOLDER not in str(exc.value)
    assert_no_secret_material(b"safe output {{unrelated}}")
