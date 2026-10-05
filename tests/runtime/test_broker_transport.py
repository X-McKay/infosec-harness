from __future__ import annotations

import json
import os
import time
from dataclasses import replace
from datetime import UTC, datetime

import httpx
import pytest
from pydantic_ai import Agent
from pydantic_ai.messages import (
    ModelRequest,
    ModelResponse,
    TextPart,
    ToolCallPart,
    UserPromptPart,
)
from pydantic_ai.models import ModelRequestParameters
from test_broker_profiles import backend

from infosec_harness.inference.catalog.profiles import BrokerConfig, ControllerChannel
from infosec_harness.inference.wire.auth import AUTH_HEADER, sign_request
from infosec_harness.inference.wire.codec import encode_response
from infosec_harness.inference.wire.protocol import (
    BrokerError,
    InferenceRequest,
    InferenceResult,
    ReservationBinding,
    canonical_bytes,
)
from infosec_harness.inference.worker.identity import (
    BrokerRequestIdentity,
    current_request_identity,
)
from infosec_harness.inference.worker.transport import BrokerModel

_KEY = b"t" * 32


def _bounds() -> dict:
    return {
        "max_requests": 5,
        "max_input_tokens": 50000,
        "max_output_tokens": 10000,
        "max_cost_usd": 0.5,
        "max_duration_seconds": 600.0,
    }


def _contract(agent: str = "recon"):
    agents = (
        "intake",
        "recon",
        "env-planner",
        "build-repair",
        "partial-build",
        "context",
        "probe-planner",
        "probe-author",
        "probe-diagnosis",
        "probe-repair",
        "verdict",
    )
    profile = {
        "backend_name": "gateway",
        "endpoint": "https://provider.example/v1",
        "provider_binding": "provider-v1",
        "provider_env": "OPENAI_API_KEY",
        "ledger_origin": "https://broker.example",
        "ledger_profile": "ledger-v1",
        "executor_image": "sha256:" + "1" * 64,
        "supervisor_image": "sha256:" + "2" * 64,
        "approved_policy": {"version": 1, "network_policies": {}},
    }
    config = BrokerConfig.model_validate(
        {
            "version": 1,
            "enabled": True,
            "controller": {"url": "https://broker.example", "hmac_env": "BROKER_TEST_KEY"},
            "profiles": {"inference-only": profile},
            "agent_profiles": {name: "inference-only" for name in agents},
            "root_limits": _bounds(),
            "agent_limits": {name: _bounds() for name in agents},
        }
    )
    return config.resolve_contract(
        agent,
        "gateway",
        "model-v1",
        {"max_tokens": 2048, "temperature": 0.1},
        backend=backend(),
        atomic_intake=agent == "intake",
    )


def _binding(contract, *, run_id: str = "run-a", invocation_id: str = "invoke-a"):
    return ReservationBinding(
        root_id="root-a",
        run_id=run_id,
        invocation_id=invocation_id,
        operation_id="operation-a",
        agent="intake" if contract.atomic_intake else "recon",
        contract_digest=contract.digest,
        expires_at=time.time() + 300,
    )


def _model(contract, binding, handler, *, identity=lambda: "step:7"):
    os.environ["BROKER_TEST_KEY"] = _KEY.decode()
    return BrokerModel(
        contract=contract,
        binding=binding,
        controller=ControllerChannel(url="https://broker.example", hmac_env="BROKER_TEST_KEY",
            ca_file=None, client_cert=None, client_key=None),
        request_identity=identity,
        http_transport=httpx.MockTransport(handler),
    )


def _verified(contract) -> dict:
    """The controller's corroborated native observations for an admitted contract."""
    return {"native_id": "sandbox-test", "policy_digest": contract.policy_digest,
            "executor_image": contract.executor_image, "supervisor_image": contract.supervisor_image,
            "profile": contract.profile, "credential_revision": "provider-rev-1",
            "contract_digest": contract.digest, "lease_id": "lease-test"}


def _messages():
    return [ModelRequest(parts=[UserPromptPart(content="a safe prompt")])]


def _response():
    return ModelResponse(
        parts=[TextPart(content="safe answer")],
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
    )


def test_transport_sends_one_canonical_authenticated_request_and_decodes_response() -> None:
    contract = _contract()
    binding = _binding(contract)
    received: list[httpx.Request] = []
    upstream_errors: list[str] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        received.append(request)
        try:
            body = request.content
            assert request.method == "POST"
            assert str(request.url) == "https://broker.example/v1/infer"
            assert set(request.headers) >= {"content-type", AUTH_HEADER.lower()}
            assert request.headers["content-type"] == "application/json"
            value = json.loads(body)
            parsed = InferenceRequest.model_validate(value)
            assert parsed.contract == contract
            assert parsed.binding == binding
            assert parsed.payload.messages[0]["parts"][0]["content"] == "a safe prompt"
            expiry = int(request.headers[AUTH_HEADER].split(":")[1])
            assert request.headers[AUTH_HEADER] == sign_request(
                _KEY, "POST", "/v1/infer", body, expiry
            )
            result = InferenceResult(
                request_id=parsed.request_id,
                response=encode_response(_response()),
                provenance=_verified(parsed.contract),
            )
            return httpx.Response(200, content=canonical_bytes(result.model_dump(mode="json")))
        except Exception as exc:
            upstream_errors.append(f"{type(exc).__name__}: {exc}")
            return httpx.Response(500, content=b'{"error":"unavailable"}')

    model = _model(contract, binding, upstream)
    assert model.provider is None
    assert model.system == "openai"
    assert model.model_name == "model-v1"
    try:
        result = pytest.importorskip("asyncio").run(
            model.request(_messages(), None, ModelRequestParameters())
        )
    except Exception:
        assert upstream_errors == []
        raise
    assert upstream_errors == []
    assert replace(result, metadata=None) == _response()
    assert result.metadata["harness_broker"]["contract_digest"] == contract.digest
    assert len(received) == 1


@pytest.mark.parametrize("status", [302, 307, 503])
def test_http_failure_never_redirects_retries_or_falls_back(status: int) -> None:
    contract = _contract()
    calls = 0

    def upstream(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            status,
            headers={"Location": "https://other.example"},
            content=b'{"error":"unavailable","detail":"sensitive"}',
        )

    model = _model(contract, _binding(contract), upstream)
    with pytest.raises(Exception) as error:
        pytest.importorskip("asyncio").run(
            model.request(_messages(), None, ModelRequestParameters())
        )
    assert calls == 1
    assert "sensitive" not in str(error.value)
    assert "https://other.example" not in str(error.value)


def test_missing_stable_identity_fails_before_network() -> None:
    contract = _contract()
    calls = 0

    def upstream(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, content=b"{}")

    model = _model(contract, _binding(contract), upstream, identity=None)
    with pytest.raises(Exception) as error:
        pytest.importorskip("asyncio").run(
            model.request(_messages(), None, ModelRequestParameters())
        )
    assert getattr(error.value, "code", None) == "identity"
    assert calls == 0


def test_model_instances_isolate_bindings_and_durable_request_ids() -> None:
    contract = _contract()
    ids: list[str] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        incoming = InferenceRequest.model_validate_json(request.content)
        ids.append(incoming.request_id)
        outgoing = InferenceResult(
            request_id=incoming.request_id,
            response=encode_response(_response()),
            provenance=_verified(incoming.contract),
        )
        return httpx.Response(200, content=canonical_bytes(outgoing.model_dump(mode="json")))

    models = [
        _model(contract, _binding(contract, run_id=run), upstream, identity=lambda: "activity-7")
        for run in ("run-a", "run-b")
    ]
    asyncio = pytest.importorskip("asyncio")
    for model in models:
        asyncio.run(model.request(_messages(), None, ModelRequestParameters()))
    assert ids[0] != ids[1]
    assert models[0].binding.run_id == "run-a"
    assert models[1].binding.run_id == "run-b"


@pytest.mark.asyncio
async def test_agent_run_uses_registered_identity_capability_and_typed_response_codec() -> None:
    contract = _contract()
    binding = _binding(contract)
    request_ids: list[str] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        incoming = InferenceRequest.model_validate_json(request.content)
        request_ids.append(incoming.request_id)
        result = InferenceResult(
            request_id=incoming.request_id,
            response=encode_response(_response()),
            provenance=_verified(incoming.contract),
        )
        return httpx.Response(200, content=canonical_bytes(result.model_dump(mode="json")))

    model = _model(contract, binding, upstream, identity=current_request_identity)
    agent = Agent(model, capabilities=[BrokerRequestIdentity()])
    result = await agent.run("safe prompt")
    assert result.output == "safe answer"
    assert len(request_ids) == 1
    assert len(request_ids[0]) == 64


@pytest.mark.asyncio
async def test_agent_tool_call_parameters_and_messages_round_trip_through_codec() -> None:
    contract = _contract()
    binding = _binding(contract)
    observed_tools: list[list[str]] = []
    requests = 0

    def upstream(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        incoming = InferenceRequest.model_validate_json(request.content)
        function_tools = incoming.payload.parameters.get("function_tools", [])
        observed_tools.append([tool["name"] for tool in function_tools])
        if requests == 1:
            response = ModelResponse(
                parts=[
                    ToolCallPart(
                        tool_name="echo",
                        args={"value": "tool-value"},
                        tool_call_id="call-1",
                    )
                ],
                timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            )
        else:
            response = _response()
        result = InferenceResult(
            request_id=incoming.request_id,
            response=encode_response(response),
            provenance=_verified(incoming.contract),
        )
        return httpx.Response(200, content=canonical_bytes(result.model_dump(mode="json")))

    def echo(value: str) -> str:
        return value

    model = _model(contract, binding, upstream, identity=current_request_identity)
    agent = Agent(model, tools=[echo], capabilities=[BrokerRequestIdentity()])
    result = await agent.run("call echo")
    assert result.output == "safe answer"
    assert requests == 2
    assert observed_tools == [["echo"], ["echo"]]


def test_binding_mismatch_rejects_and_valid_model_never_constructs_provider(monkeypatch) -> None:
    import openai

    contract = _contract()
    valid_model = _model(contract, _binding(contract), lambda request: httpx.Response(200))
    monkeypatch.setattr(
        openai.AsyncOpenAI,
        "__init__",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("provider constructed")),
    )
    model = _model(contract, _binding(contract), lambda request: httpx.Response(200))
    assert model.provider is None
    assert valid_model.provider is None

    binding = _binding(contract).model_copy(update={"contract_digest": "f" * 64})
    with pytest.raises(Exception) as error:
        _model(contract, binding, lambda request: httpx.Response(200))
    assert getattr(error.value, "code", None) == "identity"


def test_atomic_intake_uses_fresh_openai_schema_profile() -> None:
    from infosec_harness.intake.schema import InlineOpenAIJsonSchemaTransformer

    contract = _contract("intake")
    model = _model(contract, _binding(contract), lambda request: httpx.Response(200))
    assert model.profile["json_schema_transformer"] is InlineOpenAIJsonSchemaTransformer


def test_expired_binding_uses_read_only_results_path_and_preserves_provenance() -> None:
    contract = _contract()
    binding = _binding(contract).model_copy(update={"expires_at": time.time() - 30})
    captured: list[str] = []
    request_ids: list[str] = []
    provenance = {
        "native_id": "sandbox-test",
        "policy_digest": contract.policy_digest,
        "executor_image": contract.executor_image,
        "supervisor_image": contract.supervisor_image,
        "profile": contract.profile,
        "credential_revision": "provider-rev-1",
        "contract_digest": contract.digest,
        "lease_id": "lease-test",
    }

    def results(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        captured.append(path)
        assert path == "/v1/results"
        body = request.content
        incoming = InferenceRequest.model_validate_json(body)
        request_ids.append(incoming.request_id)
        assert incoming.binding == binding
        expiry = int(request.headers[AUTH_HEADER].split(":")[1])
        assert expiry > int(time.time())
        assert expiry > binding.expires_at
        assert request.headers[AUTH_HEADER] == sign_request(
            _KEY, "POST", "/v1/results", body, expiry
        )
        result = InferenceResult(
            request_id=incoming.request_id,
            response=encode_response(_response()),
            provenance=provenance,
        )
        return httpx.Response(200, content=canonical_bytes(result.model_dump(mode="json")))

    model = _model(contract, binding, results)
    response = pytest.importorskip("asyncio").run(
        model.request(_messages(), None, ModelRequestParameters())
    )
    assert captured == ["/v1/results"]
    assert response.metadata == {
        "harness_broker": {"state": "completed", "request_id": request_ids[0], **provenance}
    }


@pytest.mark.parametrize(
    ("status", "error_code"),
    [(400, "identity"), (409, "pending"), (409, "completion_unknown"), (410, "expired")],
)
def test_expired_binding_without_a_completed_result_never_uses_infer(status, error_code) -> None:
    contract = _contract()
    binding = _binding(contract).model_copy(update={"expires_at": time.time() - 30})
    paths: list[str] = []

    def results(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        return httpx.Response(status, content=canonical_bytes({"error": error_code}))

    model = _model(contract, binding, results)
    with pytest.raises(BrokerError) as error:
        pytest.importorskip("asyncio").run(
            model.request(_messages(), None, ModelRequestParameters())
        )
    assert error.value.code == error_code
    assert paths == ["/v1/results"]


@pytest.mark.parametrize("change", ["unexpected", "empty", "missing_field", "other_contract",
                                    "other_image"])
def test_controller_provenance_is_mandatory_and_must_match_the_contract(change) -> None:
    """A result without exact controller observations is never accepted as broker evidence."""
    contract = _contract()
    binding = _binding(contract)
    provenance = _verified(contract)
    if change == "unexpected":
        provenance["unexpected_secret_field"] = "not persisted"
    if change == "empty":
        provenance = {}
    if change == "missing_field":
        del provenance["lease_id"]
    if change == "other_contract":
        provenance["contract_digest"] = "f" * 64
    if change == "other_image":
        provenance["executor_image"] = "sha256:" + "f" * 64

    def upstream(request: httpx.Request) -> httpx.Response:
        incoming = InferenceRequest.model_validate_json(request.content)
        result = InferenceResult(
            request_id=incoming.request_id,
            response=encode_response(_response()),
            provenance=provenance,
        )
        return httpx.Response(200, content=canonical_bytes(result.model_dump(mode="json")))

    model = _model(contract, binding, upstream)
    with pytest.raises(BrokerError) as error:
        pytest.importorskip("asyncio").run(
            model.request(_messages(), None, ModelRequestParameters())
        )
    assert error.value.code == "invalid_response"


@pytest.mark.parametrize("code", ["auth", "policy", "identity", "budget", "expired",
                                  "conflict", "invalid_response", "completion_unknown"])
def test_terminal_dispositions_cannot_be_transient_retries(code):
    from infosec_harness.inference.wire.http_service import response_error
    from infosec_harness.inference.wire.protocol import TransientBrokerError
    error = response_error(canonical_bytes({"error": code}))
    assert type(error) is BrokerError
    with pytest.raises(ValueError):
        TransientBrokerError(code)


@pytest.mark.parametrize("code", ["unavailable", "pending"])
def test_transient_activity_errors_have_distinct_retryable_type(code):
    from infosec_harness.inference.wire.http_service import response_error
    from infosec_harness.inference.wire.protocol import TransientBrokerError
    from infosec_harness.runtime.registry import ACTIVITY_RETRY
    error = response_error(canonical_bytes({"error": code}))
    assert type(error) is TransientBrokerError and error.code == code
    assert type(error).__name__ not in ACTIVITY_RETRY.non_retryable_error_types
    assert ACTIVITY_RETRY.maximum_attempts == 3


async def test_transient_retry_reuses_the_exact_request_and_visibility_payload():
    from infosec_harness.inference.wire.protocol import TransientBrokerError
    contract = _contract()
    binding = _binding(contract)
    requests = []
    def handler(request):
        value = InferenceRequest.model_validate_json(request.content)
        requests.append(value)
        return httpx.Response(503, content=canonical_bytes({"error": "unavailable"}))
    model = _model(contract, binding, handler)
    messages = [ModelRequest(parts=[UserPromptPart("x")])]
    params = ModelRequestParameters(deferred_capability_ids={"b", "a"})
    for _ in range(2):
        with pytest.raises(TransientBrokerError):
            await model.request(messages, contract.model_settings, params)
    assert len(requests) == 2 and requests[0] == requests[1]
    assert requests[0].payload.parameters["deferred_capability_ids"] == ["a", "b"]


def test_remote_error_diagnostics_are_sanitized_and_transient_type_is_preserved(caplog):
    from infosec_harness.inference.wire.http_service import response_error as _response_error
    from infosec_harness.inference.wire.protocol import TransientBrokerError

    diagnostic = {"boundary": "provider_request", "category": "wall_timeout"}
    error = _response_error(canonical_bytes({"error": "completion_unknown", "diagnostic": diagnostic}))
    assert type(error) is BrokerError and error.diagnostic == diagnostic
    assert "provider_request" in caplog.text and "wall_timeout" in caplog.text

    caplog.clear()
    secret = "https://secret.invalid/path?token=do-not-log"
    malformed = {**diagnostic, "detail": secret}
    error = _response_error(canonical_bytes({"error": "unavailable", "diagnostic": malformed,
                                                 "message": secret}))
    assert type(error) is TransientBrokerError
    assert error.code == "unavailable" and error.diagnostic is None
    assert secret not in caplog.text

    error = _response_error(canonical_bytes({"error": "unavailable", "diagnostic": diagnostic}))
    assert type(error) is TransientBrokerError and error.diagnostic == diagnostic


@pytest.mark.parametrize("status,body,code", [
    (502, b"<html>Bad gateway</html>", "unavailable"),
    (503, b"", "unavailable"),
    (409, b'{"error": "conflict"}', "unavailable"),  # Non-canonical body: status only.
    (409, canonical_bytes({"error": "conflict"}), "conflict"),
    (400, canonical_bytes({"error": "not-a-code"}), "unavailable"),
])
async def test_json_channel_checks_status_before_parsing(status, body, code):
    """A gateway error page is infrastructure unavailability, never an identity failure."""
    from infosec_harness.inference.wire.http_service import JsonChannel

    channel = JsonChannel(transport=httpx.MockTransport(lambda _r: httpx.Response(status, content=body)))
    with pytest.raises(BrokerError) as error:
        await channel.post("https://executor.test/v1/infer", b"{}", {})
    assert error.value.code == code


@pytest.mark.parametrize("body", [b"<html>ok</html>", b'{"a": 1}', b"[]",
                                  canonical_bytes({"a": 1}) + b" "])
async def test_json_channel_malformed_success_is_invalid_response(body):
    from infosec_harness.inference.wire.http_service import JsonChannel

    channel = JsonChannel(transport=httpx.MockTransport(lambda _r: httpx.Response(200, content=body)))
    with pytest.raises(BrokerError) as error:
        await channel.post("https://executor.test/v1/infer", b"{}", {})
    assert error.value.code == "invalid_response"


async def test_json_channel_bounds_response_and_maps_transport_failure():
    from infosec_harness.inference.wire.http_service import JsonChannel
    from infosec_harness.inference.wire.protocol import MAX_BODY_BYTES

    big = JsonChannel(transport=httpx.MockTransport(
        lambda _r: httpx.Response(200, content=b"x" * (MAX_BODY_BYTES + 1))))
    with pytest.raises(BrokerError) as error:
        await big.post("https://executor.test/v1/infer", b"{}", {})
    assert error.value.code == "invalid_response"

    def refuse(_request):
        raise httpx.ConnectError("refused secret-host")

    down = JsonChannel(transport=httpx.MockTransport(refuse))
    with pytest.raises(BrokerError) as error:
        await down.post("https://executor.test/v1/infer", b"{}", {})
    assert error.value.code == "unavailable" and "secret-host" not in str(error.value)


def test_request_parser_is_identity_and_response_parser_is_invalid_response():
    from infosec_harness.inference.wire.http_service import parse_request, parse_response

    for parse, code in ((parse_request, "identity"), (parse_response, "invalid_response")):
        for body in (b"", b"[]", b'{"a":1,"a":2}', b'{"a":NaN}', b'{"b":1, "a":2}'):
            with pytest.raises(BrokerError) as error:
                parse(body)
            assert error.value.code == code
        assert parse(canonical_bytes({"a": 1})) == {"a": 1}


@pytest.mark.parametrize("value", ["http://h", "https://", "https://u@h", "https://u:p@h",
                                   "https://h?q=1", "https://h#f", "https://h:0", "https://h:70000",
                                   "https://h:x"])
def test_fixed_https_url_rejects_ambiguous_authority(value):
    from infosec_harness.inference.wire.protocol import fixed_https_url

    with pytest.raises(ValueError):
        fixed_https_url(value)


def test_fixed_https_url_origin_and_path_requirements():
    from infosec_harness.inference.wire.protocol import fixed_https_url

    assert fixed_https_url("https://h:8443/") == "https://h:8443"
    assert fixed_https_url("https://h/v1/", require_path="/v1") == "https://h/v1"
    with pytest.raises(ValueError):
        fixed_https_url("https://h/v1", require_origin=True)
    with pytest.raises(ValueError):
        fixed_https_url("https://h/v2", require_path="/v1")


def test_error_codes_are_the_closed_literal():
    from typing import get_args

    from infosec_harness.inference.wire.protocol import ERROR_CODES, ErrorCode

    assert frozenset(get_args(ErrorCode)) == ERROR_CODES and "unavailable" in ERROR_CODES


@pytest.mark.parametrize("length", ["", "abc", "+2", "2_0", "２", "9" * 5000])
def test_invalid_http_body_length_is_terminal_identity(length):
    from email.message import Message
    from io import BytesIO
    from types import SimpleNamespace

    from infosec_harness.inference.wire.http_service import _BrokerHandler

    headers = Message()
    headers["Content-Length"] = length
    request = SimpleNamespace(headers=headers, rfile=BytesIO(b"{}"))
    with pytest.raises(BrokerError) as error:
        _BrokerHandler._read_body(request)
    assert error.value.code == "identity"


@pytest.mark.parametrize("failure", ["startup", "bind"])
def test_failed_service_setup_closes_its_event_loop(monkeypatch, failure):
    import asyncio
    import threading

    from infosec_harness.inference.wire import http_service

    loop = asyncio.new_event_loop()
    before = set(threading.enumerate())
    monkeypatch.setattr(http_service.asyncio, "new_event_loop", lambda: loop)

    async def startup():
        if failure == "startup":
            raise RuntimeError("setup failed")

    def bind(*args, **kwargs):
        raise RuntimeError("bind failed")

    monkeypatch.setattr(http_service, "_BoundedServer", bind)
    with pytest.raises(RuntimeError):
        http_service.serve(object(), host="127.0.0.1", port=0, tls=None,
                           loopback_executor=True, startup=startup)
    assert loop.is_closed()
    assert set(threading.enumerate()) <= before


@pytest.mark.parametrize("change", ["partial", "missing_request", "invalid_state", "invalid_id", "boolean"])
def test_recorded_broker_evidence_requires_complete_typed_observations(change):
    from infosec_harness.inference.worker.provenance import runtime_evidence

    value = {"state": "completed", "request_id": "a" * 64, **_verified(_contract())}
    if change == "partial":
        value = {"state": "completed"}
    elif change == "missing_request":
        del value["request_id"]
    elif change == "invalid_state":
        value["state"] = "accepted"
    elif change == "invalid_id":
        value["request_id"] = "not-a-request-digest"
    else:
        value["native_id"] = True
    response = _response()
    response.metadata = {"harness_broker": value}
    with pytest.raises(BrokerError) as error:
        runtime_evidence([response])
    assert error.value.code == "invalid_response"


def test_recorded_broker_evidence_preserves_complete_observations():
    from infosec_harness.inference.worker.provenance import runtime_evidence

    value = {"state": "completed", "request_id": "a" * 64, **_verified(_contract())}
    response = _response()
    response.metadata = {"harness_broker": value}
    assert runtime_evidence([response]) == [value]
