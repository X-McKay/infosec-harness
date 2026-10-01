from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic_ai.messages import ModelRequest, ModelResponse, TextPart, UserPromptPart
from pydantic_ai.models import ModelRequestParameters

from infosec_harness.inference.auth import AUTH_HEADER, sign_request, verify_request
from infosec_harness.inference.codec import encode_payload, encode_response
from infosec_harness.inference.executor import (
    Executor,
    ExecutorSettings,
    NativeLedgerChannel,
    OpenAIInference,
)
from infosec_harness.inference.protocol import (
    BrokerError,
    DispatchPermit,
    ExecutorContract,
    InferenceRequest,
    InferenceResult,
    ReservationBinding,
    canonical_bytes,
    digest,
    required_input_reserve,
)


def request_fixture():
    payload = encode_payload(
        [ModelRequest(parts=[UserPromptPart("bounded hello")])],
        {"max_tokens": 16},
        ModelRequestParameters(),
    )
    contract = ExecutorContract(
        backend="mock",
        model="test-model",
        profile="test",
        profile_digest="a" * 64,
        endpoint="https://provider.test/v1",
        provider_binding="mock",
        executor_image="sha256:" + "b" * 64,
        supervisor_image="sha256:" + "c" * 64,
        policy_digest="d" * 64,
        model_settings={"max_tokens": 16},
    )
    binding = ReservationBinding(
        root_id="root",
        run_id="run",
        invocation_id="invocation",
        operation_id="operation",
        agent="verdict",
        contract_digest=contract.digest,
        expires_at=200,
    )
    request = InferenceRequest(
        request_id="e" * 64,
        binding=binding,
        contract=contract,
        payload=payload,
        payload_digest=digest(payload.model_dump(mode="json")),
    )
    settings = ExecutorSettings(
        run_id="run",
        lease_id="lease",
        contract=contract,
        controller_origin="https://controller.test",
        ingress_key_hex="12" * 32,
        provider_env="MOCK_TOKEN",
        max_input_tokens=10000,
        max_output_tokens=16,
    )
    return request, settings


def signed(request, settings, *, expiry=130):
    body = canonical_bytes(request.model_dump(mode="json"))
    return body, {
        AUTH_HEADER: sign_request(
            bytes.fromhex(settings.ingress_key_hex), "POST", "/v1/infer", body, expiry
        )
    }


@pytest.mark.parametrize("change", ["body", "path", "key", "expired", "far_future", "malformed"])
def test_auth_binds_body_path_key_and_short_lifetime(change):
    secret = b"a" * 32
    body = b"{}"
    header = sign_request(secret, "POST", "/v1/infer", body, 130)
    path = "/v1/infer"
    if change == "body":
        body = b'{"changed":true}'
    if change == "path":
        path = "/v1/invocations"
    if change == "key":
        secret = b"b" * 32
    if change == "expired":
        header = sign_request(secret, "POST", path, body, 100)
    if change == "far_future":
        header = sign_request(secret, "POST", path, body, 161)
    if change == "malformed":
        header = "v1:130:bad"
    with pytest.raises(BrokerError, match="auth"):
        verify_request(secret, "POST", path, body, header, now=100)


def test_auth_valid_signature_and_unknown_paths_rejected():
    secret = b"a" * 32
    verify_request(
        secret,
        "POST",
        "/v1/infer",
        b"{}",
        sign_request(secret, "POST", "/v1/infer", b"{}", 130),
        now=100,
    )
    with pytest.raises(BrokerError):
        sign_request(secret, "POST", "/admin", b"{}", 130)


def executor_fixture(settings, *, fail=None):
    events = []
    state = {"claimed": False}

    async def claim(request, lease_id):
        events.append("claim")
        if state["claimed"]:
            raise BrokerError("pending")
        state["claimed"] = True
        return DispatchPermit(request_id=request.request_id, lease_id=lease_id, fence="fence")

    async def complete(result, permit):
        events.append("commit")
        if fail == "commit":
            raise OSError("lost durable acknowledgement")
        return result

    async def infer(request):
        events.append("provider")
        if fail == "provider":
            raise OSError("ambiguous transport failure")
        return InferenceResult(
            request_id=request.request_id,
            response=encode_response(
                ModelResponse(parts=[TextPart("approved")], model_name="test-model")
            ),
        )

    core = Executor(
        settings,
        ledger=SimpleNamespace(claim=claim, complete=complete),
        infer=infer,
        clock=lambda: 100,
    )
    return core, events


@pytest.mark.asyncio
async def test_executor_orders_claim_single_send_commit_and_ack():
    request, settings = request_fixture()
    core, events = executor_fixture(settings)
    body, headers = signed(request, settings)
    result = await core.handle("/v1/infer", body, headers)
    assert result["request_id"] == request.request_id
    assert events == ["claim", "provider", "commit"]


@pytest.mark.asyncio
@pytest.mark.parametrize("fail", ["provider", "commit"])
async def test_ambiguous_failures_never_repeat_provider_dispatch(fail):
    request, settings = request_fixture()
    core, events = executor_fixture(settings, fail=fail)
    body, headers = signed(request, settings)
    with pytest.raises(BrokerError, match="completion_unknown"):
        await core.handle("/v1/infer", body, headers)
    with pytest.raises(BrokerError, match="pending"):
        await core.handle("/v1/infer", body, headers)
    assert events.count("provider") == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault", ["unsigned", "different_run", "expired", "input_cap", "output_cap", "extra_field"]
)
async def test_invalid_execution_requests_have_zero_claim_and_provider(fault):
    request, settings = request_fixture()
    if fault == "different_run":
        settings = settings.model_copy(update={"run_id": "other"})
    if fault == "expired":
        request = request.model_copy(
            update={"binding": request.binding.model_copy(update={"expires_at": 99})}
        )
    if fault == "input_cap":
        settings = settings.model_copy(
            update={"max_input_tokens": await required_input_reserve(request.payload, request.contract) - 1}
        )
    if fault == "output_cap":
        settings = settings.model_copy(update={"max_output_tokens": 15})
    core, events = executor_fixture(settings)
    body, headers = signed(request, settings)
    if fault == "unsigned":
        headers = {}
    if fault == "extra_field":
        value = request.model_dump(mode="json")
        value["url"] = "https://other.test"
        body = canonical_bytes(value)
        headers = {
            AUTH_HEADER: sign_request(
                bytes.fromhex(settings.ingress_key_hex), "POST", "/v1/infer", body, 130
            )
        }
    with pytest.raises(BrokerError):
        await core.handle("/v1/infer", body, headers)
    assert events == []


@pytest.mark.parametrize("token", ["real-secret", "openshell:resolve:env:BAD-TOKEN", ""])
def test_ledger_channel_requires_native_placeholder(token):
    with pytest.raises(BrokerError) as exc:
        NativeLedgerChannel("https://controller.test", token)
    assert exc.value.code == "identity"


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [200, 429, 500])
async def test_locked_sdk_uses_compatible_transport_and_one_request_only(status):
    import time

    import httpx2
    from pydantic_ai.exceptions import ModelHTTPError

    request, _ = request_fixture()
    request = request.model_copy(
        update={"binding": request.binding.model_copy(update={"expires_at": time.time() + 60})}
    )
    sends = []

    def respond(native_request):
        sends.append(native_request)
        return httpx2.Response(
            status,
            json={
                "id": "mock",
                "object": "chat.completion",
                "created": 1,
                "model": "test-model",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "approved"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
            },
        )

    infer = OpenAIInference(
        request.contract,
        "openshell:resolve:env:MOCK_TOKEN",
        http_transport=httpx2.MockTransport(respond),
    )
    if status == 200:
        result = await infer(request)
        assert result.usage["input_tokens"] == 3
        assert result.usage["output_tokens"] == 2
    else:
        with pytest.raises(ModelHTTPError):
            await infer(request)
    assert len(sends) == 1
    assert sends[0].url == "https://provider.test/v1/chat/completions"
    assert sends[0].headers["authorization"] == "Bearer openshell:resolve:env:MOCK_TOKEN"


async def test_provider_timeout_override_cannot_extend_wall_deadline(monkeypatch):
    import asyncio
    import time

    import httpx2

    from infosec_harness.inference import executor as module

    request, _ = request_fixture()
    model_settings = {"max_tokens": 16, "timeout": 999.0}
    contract = request.contract.model_copy(update={"model_settings": model_settings})
    payload = encode_payload([ModelRequest(parts=[UserPromptPart("bounded hello")])],
                             model_settings, ModelRequestParameters())
    request = request.model_copy(update={"contract": contract, "payload": payload,
        "payload_digest": digest(payload.model_dump(mode="json")),
        "binding": request.binding.model_copy(update={"contract_digest": contract.digest,
                                                      "expires_at": time.time() + 60})})
    sends = []
    async def slow(native_request):
        sends.append(native_request)
        await asyncio.sleep(1)
        raise AssertionError("Outer provider wall deadline must cancel this request")
    monkeypatch.setattr(module, "PROVIDER_TIMEOUT_S", 0.02)
    infer = OpenAIInference(contract, "openshell:resolve:env:MOCK_TOKEN",
                           http_transport=httpx2.MockTransport(slow))
    with pytest.raises(TimeoutError):
        await infer(request)
    assert len(sends) == 1


async def test_provider_trickle_bytes_cannot_renew_wall_deadline(monkeypatch):
    import asyncio
    import time

    import httpx2

    from infosec_harness.inference import executor as module

    request, _ = request_fixture()
    request = request.model_copy(update={"binding": request.binding.model_copy(update={"expires_at": time.time() + 60})})
    sends = []
    class Trickle(httpx2.AsyncByteStream):
        async def __aiter__(self):
            while True:
                await asyncio.sleep(0.005)
                yield b" "
    async def respond(native_request):
        sends.append(native_request)
        return httpx2.Response(200, stream=Trickle(), headers={"Content-Type": "application/json"})
    monkeypatch.setattr(module, "PROVIDER_TIMEOUT_S", 0.02)
    infer = OpenAIInference(request.contract, "openshell:resolve:env:MOCK_TOKEN",
                           http_transport=httpx2.MockTransport(respond))
    with pytest.raises(TimeoutError):
        await infer(request)
    assert len(sends) == 1
