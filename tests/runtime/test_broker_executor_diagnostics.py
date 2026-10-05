"""Fixed nonsecret diagnostics retain single-send and unknown-completion behavior."""
from __future__ import annotations

import asyncio
import logging
import ssl
import time
from types import SimpleNamespace

import httpx
import httpx2
import pytest
from openai import APIConnectionError, APIResponseValidationError
from pydantic import ValidationError
from pydantic_ai.exceptions import ModelAPIError, ModelHTTPError, UnexpectedModelBehavior
from pydantic_ai.messages import ModelResponse, TextPart
from test_broker_executor import request_fixture, signed

from infosec_harness.inference import executor as module
from infosec_harness.inference.codec import encode_response
from infosec_harness.inference.executor import Executor, OpenAIInference
from infosec_harness.inference.http_service import JsonChannel, broker_error_body
from infosec_harness.inference.protocol import (
    BrokerError,
    DispatchPermit,
    InferenceResult,
    canonical_bytes,
)

SECRET = "secret-bearing-body-header-key-DO-NOT-LOG"


@pytest.mark.parametrize("stage,category", [("inference", "internal"), ("ledger_complete", "ledger")])
async def test_postclaim_failure_logs_only_fixed_stage_category_and_never_retries(caplog, stage, category):
    request, settings = request_fixture()
    calls = []

    async def claim(received, lease):
        calls.append("claim")
        return DispatchPermit(request_id=received.request_id, lease_id=lease, fence="fixed-fence")

    async def infer(received):
        calls.append("infer")
        if stage == "inference":
            raise RuntimeError(SECRET)
        return InferenceResult(request_id=received.request_id,
            response=encode_response(ModelResponse(parts=[TextPart("fixture")])))

    async def complete(_result, _permit):
        calls.append("complete")
        raise BrokerError("invalid_response", SECRET)

    core = Executor(settings, ledger=SimpleNamespace(claim=claim, complete=complete), infer=infer, clock=lambda: 100)
    caplog.set_level(logging.WARNING, logger=module.__name__)
    body, headers = signed(request, settings)
    with pytest.raises(BrokerError) as error:
        await core.handle("/v1/infer", body, headers)
    assert error.value.code == "completion_unknown"
    assert calls == (["claim", "infer"] if stage == "inference" else ["claim", "infer", "complete"])
    assert [record.getMessage() for record in caplog.records if record.name == module.__name__] == [
        f"IH_INFERENCE_FAILURE stage={stage} category={category}"]
    assert SECRET not in caplog.text
    assert request.request_id not in caplog.text
    assert settings.ingress_key_hex not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)


@pytest.mark.parametrize("failure,category", [("tls", "tls"), ("network", "network"),
                                               ("status", "provider_status"), ("schema", "provider_schema"), ("codec", "codec")])
async def test_actual_sdk_failure_stage_is_distinguished_without_secret_leakage(caplog, monkeypatch, failure, category):
    request, _ = request_fixture()
    request = request.model_copy(update={"binding": request.binding.model_copy(update={"expires_at": time.time() + 60})})
    calls = []

    def respond(native_request):
        calls.append("provider")
        if failure in {"tls", "network"}:
            error = httpx2.ConnectError(SECRET, request=native_request)
            if failure == "tls":
                error.__cause__ = ssl.SSLCertVerificationError(SECRET)
            raise error
        if failure == "status":
            return httpx2.Response(503, json={"error": {"message": SECRET}})
        return httpx2.Response(200, json={"id": "offline", "object": "chat.completion", "created": 1,
            "model": "test-model", "choices": [{"index": 0, "message": {"role": "assistant", "content": "fixture"},
                "finish_reason": "stop"}], "usage": {"prompt_tokens": 3, "completion_tokens": 2, **({} if failure == "schema" else {"total_tokens": 5})}})

    def reject_codec(_response):
        raise BrokerError("invalid_response", SECRET)

    if failure == "codec":
        monkeypatch.setattr(module, "encode_response", reject_codec)
    caplog.set_level(logging.WARNING, logger=module.__name__)
    inference = OpenAIInference(request.contract, "openshell:resolve:env:MOCK_TOKEN",
                               http_transport=httpx2.MockTransport(respond))
    with pytest.raises((APIConnectionError, APIResponseValidationError, ValidationError,
                        ModelAPIError, ModelHTTPError, UnexpectedModelBehavior, BrokerError)):
        await inference(request)
    assert calls == ["provider"]
    stage = "response_codec" if failure == "codec" else "provider_request"
    assert [record.getMessage() for record in caplog.records if record.name == module.__name__] == [
        f"IH_INFERENCE_FAILURE stage={stage} category={category}"]
    assert SECRET not in caplog.text
    assert request.request_id not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)


def test_unrecognized_secret_exception_stays_internal():
    class SecretException(RuntimeError):
        pass

    assert module._failure_category(SecretException(SECRET), "inference") == "internal"


@pytest.mark.parametrize("failure,category", [("read", "read_timeout"), ("wall", "wall_timeout")])
async def test_actual_sdk_timeout_diagnostic_survives_existing_json_relay(caplog, monkeypatch, failure, category):
    request, settings = request_fixture()
    request = request.model_copy(update={"binding": request.binding.model_copy(update={"expires_at": time.time() + 60})})
    calls = []

    async def provider(native_request):
        calls.append("provider")
        if failure == "read":
            raise httpx2.ReadTimeout(SECRET, request=native_request)
        await asyncio.sleep(1)
        raise AssertionError("provider wall bound must cancel this call")

    async def claim(received, lease):
        calls.append("claim")
        return DispatchPermit(request_id=received.request_id, lease_id=lease, fence="fixed-fence")

    async def complete(*_args):
        calls.append("complete")
        raise AssertionError("uncertain provider result cannot complete")

    if failure == "wall":
        monkeypatch.setattr(module, "PROVIDER_TIMEOUT_S", .02)
    inference = OpenAIInference(request.contract, "openshell:resolve:env:MOCK_TOKEN",
                               http_transport=httpx2.MockTransport(provider))
    core = Executor(settings, ledger=SimpleNamespace(claim=claim, complete=complete), infer=inference, clock=lambda: 100)
    body, headers = signed(request, settings)

    async def relay(native_request):
        calls.append("relay")
        try:
            await core.handle("/v1/infer", native_request.content, dict(native_request.headers))
        except BrokerError as error:
            return httpx.Response(409, content=canonical_bytes(broker_error_body(error)))
        raise AssertionError("provider failure must remain an error")

    caplog.set_level(logging.WARNING)
    channel = JsonChannel(transport=httpx.MockTransport(relay))
    with pytest.raises(BrokerError) as error:
        await channel.post("https://executor.test/v1/infer", body, headers)
    assert error.value.code == "completion_unknown"
    assert error.value.diagnostic == {"boundary": "provider_request", "category": category}
    assert calls == ["relay", "claim", "provider"]
    remote = [record.getMessage() for record in caplog.records
              if record.getMessage().startswith("IH_REMOTE_INFERENCE_FAILURE")]
    assert remote == [f"IH_REMOTE_INFERENCE_FAILURE boundary=provider_request category={category}"]
    assert SECRET not in caplog.text
    assert request.request_id not in caplog.text
    assert settings.ingress_key_hex not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)


@pytest.mark.parametrize("diagnostic", [None, SECRET, [],
    {"boundary": SECRET, "category": "internal"},
    {"boundary": "provider_request", "category": SECRET},
    {"boundary": "provider_request", "category": "read_timeout", "message": SECRET},
    {"boundary": [SECRET], "category": "read_timeout"}])
async def test_untrusted_diagnostic_is_discarded_without_changing_error_code(caplog, diagnostic):
    async def relay(_request):
        return httpx.Response(409, content=canonical_bytes({"error": "completion_unknown", "diagnostic": diagnostic}))

    caplog.set_level(logging.WARNING)
    with pytest.raises(BrokerError) as error:
        await JsonChannel(transport=httpx.MockTransport(relay)).post("https://executor.test/v1/infer", b"{}", {})
    assert error.value.code == "completion_unknown"
    assert error.value.diagnostic is None
    assert not caplog.records


def test_error_serializer_revalidates_mutated_diagnostic():
    error = BrokerError("completion_unknown", SECRET,
                        diagnostic={"boundary": "provider_request", "category": "read_timeout"})
    assert broker_error_body(error) == {"error": "completion_unknown",
        "diagnostic": {"boundary": "provider_request", "category": "read_timeout"}}
    error.diagnostic["message"] = SECRET
    assert broker_error_body(error) == {"error": "completion_unknown"}
    assert BrokerError("completion_unknown").diagnostic is None


async def test_successful_saved_response_is_unaffected_by_error_diagnostics(caplog):
    saved = {"response": {"saved": "exact"}, "diagnostic": {"boundary": "provider_request", "category": "read_timeout"}}

    async def relay(_request):
        return httpx.Response(200, content=canonical_bytes(saved))

    caplog.set_level(logging.WARNING)
    assert await JsonChannel(transport=httpx.MockTransport(relay)).post("https://executor.test/v1/infer", b"{}", {}) == saved
    assert not caplog.records


async def test_postclaim_cancellation_is_recorded_then_propagates(caplog):
    """A cancelled executor request is never converted into an ordinary error response."""
    request, settings = request_fixture()
    calls = []

    async def claim(received, lease):
        calls.append("claim")
        return DispatchPermit(request_id=received.request_id, lease_id=lease, fence="fixed-fence")

    async def infer(_received):
        calls.append("infer")
        raise asyncio.CancelledError(SECRET)

    async def complete(*_args):
        pytest.fail("A cancelled dispatch must not complete")

    core = Executor(settings, ledger=SimpleNamespace(claim=claim, complete=complete), infer=infer,
                    clock=lambda: 100)
    caplog.set_level(logging.WARNING, logger=module.__name__)
    body, headers = signed(request, settings)
    with pytest.raises(asyncio.CancelledError):
        await core.handle("/v1/infer", body, headers)
    assert calls == ["claim", "infer"]
    assert [record.getMessage() for record in caplog.records if record.name == module.__name__] == [
        "IH_INFERENCE_FAILURE stage=inference category=cancelled"]
    assert SECRET not in caplog.text
