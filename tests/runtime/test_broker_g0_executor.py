from __future__ import annotations

import http.client
import io
import json
import threading
import urllib.error
from typing import Any

import pytest
from broker_g0_executor import (
    ADMISSION_HEADER,
    LEDGER_PATH,
    REQUEST_PATH,
    UPSTREAM_PATH,
    ExecutorServer,
    ExecutorSettings,
    _NoRedirect,
    request_signature,
    settings_from_environment,
)

ADMISSION_KEY = b"g0-only-test-admission-key-never-production"
PROVIDER_PLACEHOLDER = "openshell:resolve:env:G0_PROVIDER_TOKEN"
LEDGER_TOKEN = "g0-ledger-only-test-token"
VALID_BODY = b'{"request_id":"g0-fixed","input":"g0-marker"}'
NOW = 1_800_000_000


class FakeResponse(io.BytesIO):
    def __init__(self, body: bytes, status: int = 200):
        super().__init__(body)
        self.status = status

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class FakeOpener:
    def __init__(
        self, responses: list[FakeResponse] | None = None, failure: BaseException | None = None
    ):
        self.responses = list(responses or [])
        self.failure = failure
        self.requests: list[Any] = []

    def open(self, request: Any, timeout: float) -> FakeResponse:
        self.requests.append(request)
        assert timeout == 10
        if self.failure is not None:
            raise self.failure
        if not self.responses:
            pytest.fail("unexpected additional upstream/controller call")
        return self.responses.pop(0)


def open_executor(
    opener: FakeOpener, *, controller_url: str | None = None, ledger_token: str | None = None
):
    settings = ExecutorSettings(
        upstream_url="https://mock.provider.test",
        admission_key=ADMISSION_KEY,
        provider_placeholder=PROVIDER_PLACEHOLDER,
        controller_url=controller_url,
        ledger_token=ledger_token,
    )
    server = ExecutorServer(settings, host="127.0.0.1", port=0, opener=opener, clock=lambda: NOW)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def send(
    server: ExecutorServer,
    *,
    body: bytes = VALID_BODY,
    signature: str | None = None,
    path: str = REQUEST_PATH,
    method: str = "POST",
) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection(*server.server_address, timeout=5)
    try:
        connection.putrequest(method, path)
        connection.putheader("Content-Length", str(len(body)))
        connection.putheader("Content-Type", "application/json")
        if signature is not None:
            connection.putheader(ADMISSION_HEADER, signature)
        connection.endheaders(body)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def valid_signature(body: bytes = VALID_BODY, expiry: int = NOW + 30) -> str:
    return request_signature(ADMISSION_KEY, "POST", REQUEST_PATH, body, expiry)


def upstream_success() -> FakeResponse:
    return FakeResponse(
        json.dumps(
            {
                "id": "secret-provider-response-must-not-be-forwarded",
                "choices": [{"message": {"content": "g0-marker"}}],
                "usage": {"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6},
                "headers": {"Authorization": "secret-must-not-be-returned"},
            }
        ).encode()
    )


def test_valid_g0_request_makes_one_static_authenticated_upstream_call():
    opener = FakeOpener([upstream_success()])
    server, thread = open_executor(opener)
    try:
        status, response = send(server, signature=valid_signature())
        assert status == 200
        assert json.loads(response) == {
            "marker": "g0-upstream-reached",
            "usage": {"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6},
        }
        assert len(opener.requests) == 1
        request = opener.requests[0]
        assert request.full_url == f"https://mock.provider.test{UPSTREAM_PATH}"
        assert request.get_method() == "POST"
        assert request.get_header("Authorization") == f"Bearer {PROVIDER_PLACEHOLDER}"
        assert json.loads(request.data) == {
            "model": "g0-test-model",
            "messages": [{"role": "user", "content": "g0-marker"}],
            "stream": False,
        }
        assert b"secret-provider" not in response
        assert b"secret-must-not-be-returned" not in response
        assert PROVIDER_PLACEHOLDER.encode() not in response
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("auth_kind", ["missing", "bad", "expired", "changed_body"])
def test_invalid_or_expired_admission_never_calls_upstream(auth_kind: str):
    opener = FakeOpener()
    server, thread = open_executor(opener)
    try:
        body = VALID_BODY
        signature = valid_signature()
        if auth_kind == "missing":
            signature = None
        elif auth_kind == "bad":
            signature = f"{NOW + 30}:" + "0" * 64
        elif auth_kind == "expired":
            signature = valid_signature(expiry=NOW)
        elif auth_kind == "changed_body":
            body = b'{"request_id":"g0-fixed","input":"changed"}'
        status, response = send(server, body=body, signature=signature)
        assert status == 401
        assert json.loads(response) == {"error": "unauthorized"}
        assert opener.requests == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_extra_or_duplicate_json_fields_never_call_upstream():
    opener = FakeOpener()
    server, thread = open_executor(opener)
    try:
        for body in (
            b'{"request_id":"g0-fixed","input":"g0-marker","url":"https://evil"}',
            b'{"request_id":"g0-fixed","request_id":"g0-fixed","input":"g0-marker"}',
        ):
            status, response = send(server, body=body, signature=valid_signature(body))
            assert status == 400
            assert json.loads(response) == {"error": "invalid_request"}
        assert opener.requests == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_path_and_method_are_fixed_and_do_not_call_upstream():
    opener = FakeOpener()
    server, thread = open_executor(opener)
    try:
        assert send(server, signature=valid_signature(), path="/other")[0] == 404
        assert send(server, signature=valid_signature(), method="GET")[0] == 405
        assert opener.requests == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_redirect_is_rejected_and_never_followed_or_retried():
    opener = FakeOpener([FakeResponse(b"redirect", status=302)])
    server, thread = open_executor(opener)
    try:
        status, response = send(server, signature=valid_signature())
        assert status == 502
        assert json.loads(response) == {"error": "upstream_failure"}
        assert len(opener.requests) == 1
        assert opener.requests[0].full_url == f"https://mock.provider.test{UPSTREAM_PATH}"
        assert (
            _NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://other.test")
            is None
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_upstream_failure_is_sanitized_and_never_retried_or_fallen_back():
    opener = FakeOpener(failure=urllib.error.URLError("private failure detail"))
    server, thread = open_executor(opener)
    try:
        status, response = send(server, signature=valid_signature())
        assert status == 502
        assert json.loads(response) == {"error": "upstream_failure"}
        assert b"private failure detail" not in response
        assert len(opener.requests) == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_optional_controller_is_called_at_fixed_path_with_scoped_token_before_upstream():
    opener = FakeOpener(
        [
            FakeResponse(b'{"accepted":true}'),
            upstream_success(),
        ]
    )
    server, thread = open_executor(
        opener, controller_url="https://controller.test", ledger_token=LEDGER_TOKEN
    )
    try:
        status, _response = send(server, signature=valid_signature())
        assert status == 200
        assert [request.full_url for request in opener.requests] == [
            f"https://controller.test{LEDGER_PATH}",
            f"https://mock.provider.test{UPSTREAM_PATH}",
        ]
        assert opener.requests[0].get_header("Authorization") == f"Bearer {LEDGER_TOKEN}"
        assert json.loads(opener.requests[0].data) == {
            "operation": "admit",
            "request_id": "g0-fixed",
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_environment_requires_admission_key_and_open_shell_placeholder(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.delenv("G0_ADMISSION_KEY", raising=False)
    monkeypatch.setenv("G0_PROVIDER_TOKEN", PROVIDER_PLACEHOLDER)
    with pytest.raises(ValueError, match="G0_ADMISSION_KEY is required"):
        settings_from_environment("https://provider.test")

    monkeypatch.setenv("G0_ADMISSION_KEY", "test-key")
    monkeypatch.setenv("G0_PROVIDER_TOKEN", "real-secret-is-not-allowed")
    with pytest.raises(ValueError, match="OpenShell environment placeholder"):
        settings_from_environment("https://provider.test")

    monkeypatch.setenv("G0_PROVIDER_TOKEN", PROVIDER_PLACEHOLDER)
    with pytest.raises(ValueError, match="G0_LEDGER_TOKEN is required"):
        settings_from_environment("https://provider.test", "https://controller.test")


def test_startup_urls_must_be_https_origins():
    import os

    old_key = os.environ.get("G0_ADMISSION_KEY")
    old_provider = os.environ.get("G0_PROVIDER_TOKEN")
    os.environ["G0_ADMISSION_KEY"] = "test-key"
    os.environ["G0_PROVIDER_TOKEN"] = PROVIDER_PLACEHOLDER
    try:
        with pytest.raises(ValueError, match="HTTPS origin"):
            settings_from_environment("http://provider.test")
        with pytest.raises(ValueError, match="HTTPS origin"):
            settings_from_environment("https://user:pass@provider.test")
    finally:
        if old_key is None:
            os.environ.pop("G0_ADMISSION_KEY", None)
        else:
            os.environ["G0_ADMISSION_KEY"] = old_key
        if old_provider is None:
            os.environ.pop("G0_PROVIDER_TOKEN", None)
        else:
            os.environ["G0_PROVIDER_TOKEN"] = old_provider
