"""Fixed nonsecret diagnostics retain single-send and unknown-completion behavior."""
from __future__ import annotations

import logging
import ssl
import time
from types import SimpleNamespace

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
from infosec_harness.inference.protocol import BrokerError, DispatchPermit, InferenceResult

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
