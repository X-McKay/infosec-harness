"""Minimal isolated inference service: claim once, send once, commit before replying."""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import ssl
import time
from pathlib import Path

import httpx2
from openai import AsyncOpenAI
from pydantic_ai.providers.openai import OpenAIProvider

from infosec_harness.inference.executor.compat import model_for_contract
from infosec_harness.inference.executor.rendering import check_request_bounds
from infosec_harness.inference.wire.auth import verify_headers
from infosec_harness.inference.wire.codec import decode_payload, encode_response
from infosec_harness.inference.wire.diagnostics import record_failure
from infosec_harness.inference.wire.http_service import (
    JsonChannel,
    https_origin,
    parse_request,
    serve,
)
from infosec_harness.inference.wire.protocol import (
    ENV_NAME_PATTERN,
    INFER_PATH,
    LEDGER_CLAIM_PATH,
    LEDGER_COMPLETE_PATH,
    BrokerError,
    DispatchPermit,
    ExecutorContract,
    InferenceRequest,
    InferenceResult,
    canonical_bytes,
    parse_model,
)
from infosec_harness.inference.wire.settings import ExecutorSettings, read_private
from infosec_harness.inference.wire.timing import PROVIDER_TIMEOUT_S, remaining_timeout

PLACEHOLDER = re.compile("^openshell:resolve:env:" + ENV_NAME_PATTERN.removeprefix("^"))


def _placeholder(value: str, role: str) -> str:
    if not PLACEHOLDER.fullmatch(value):
        raise BrokerError("identity", f"Native {role} credential placeholder is required")
    return value


class NativeLedgerChannel:
    def __init__(self, origin: str, placeholder: str, *, channel: JsonChannel | None = None):
        self.origin = https_origin(origin)
        self.authorization = {"Authorization": "Bearer " + _placeholder(placeholder, "ledger")}
        self.channel = channel or JsonChannel()

    async def claim(self, request: InferenceRequest, lease_id: str) -> DispatchPermit:
        value = await self.channel.post(
            self.origin + LEDGER_CLAIM_PATH,
            canonical_bytes({"request": request.model_dump(mode="json"), "lease_id": lease_id}),
            self.authorization,
        )
        return DispatchPermit.model_validate(value)

    async def complete(self, result: InferenceResult, permit: DispatchPermit) -> InferenceResult:
        value = await self.channel.post(
            self.origin + LEDGER_COMPLETE_PATH,
            canonical_bytes(
                {"permit": permit.model_dump(mode="json"), "result": result.model_dump(mode="json")}
            ),
            self.authorization,
        )
        return InferenceResult.model_validate(value)


class OpenAIInference:
    """One SDK request. No ambient credentials, custom URLs, retries, redirects, or tools."""

    def __init__(self, contract: ExecutorContract, placeholder: str, *, http_transport=None):
        self.contract = contract
        self.placeholder = _placeholder(placeholder, "provider")
        self.http_transport = http_transport

    async def __call__(self, request: InferenceRequest) -> InferenceResult:
        messages, settings, params = decode_payload(request.payload)
        timeout = remaining_timeout(request.binding.expires_at, PROVIDER_TIMEOUT_S)
        # SSL_CERT_FILE names OpenShell's injected trust bundle; verification remains on.
        context = ssl.create_default_context()
        async with (
            httpx2.AsyncClient(
                verify=context,
                trust_env=False,
                follow_redirects=False,
                timeout=timeout,
                transport=self.http_transport,
            ) as transport,
            AsyncOpenAI(
                base_url=self.contract.endpoint,
                api_key=self.placeholder,
                max_retries=0,
                http_client=transport,
            ) as client,
        ):
            model = model_for_contract(self.contract, OpenAIProvider(openai_client=client))
            try:
                async with asyncio.timeout(timeout):
                    response = await model.request(messages, settings, params)
            except asyncio.CancelledError as error:
                # The request may have reached the provider: record, then honour cancellation.
                record_failure("provider_request", error)
                raise
            except Exception as error:
                raise BrokerError("completion_unknown",
                                  diagnostic=record_failure("provider_request", error)) from None
        usage = {
            key: value
            for key, value in vars(response.usage).items()
            if isinstance(value, int) and not isinstance(value, bool)
        }
        try:
            # Provenance is attached only by the controller after it verifies the lease.
            return InferenceResult(request_id=request.request_id,
                                   response=encode_response(response), usage=usage)
        except Exception as error:
            raise BrokerError("completion_unknown",
                              diagnostic=record_failure("response_codec", error)) from None


class Executor:
    def __init__(self, settings: ExecutorSettings, *, ledger, infer, clock=time.time):
        self.settings = settings
        self.ledger = ledger
        self.infer = infer
        self.clock = clock

    async def handle(self, path: str, body: bytes, headers: dict[str, str]) -> dict:
        if path != INFER_PATH:
            raise BrokerError("policy")
        verify_headers(bytes.fromhex(self.settings.ingress_key_hex), path, body, headers,
                       now=int(self.clock()))
        request = parse_model(InferenceRequest, parse_request(body))
        if (
            request.binding.run_id != self.settings.run_id
            or request.contract != self.settings.contract
        ):
            raise BrokerError("identity")
        if request.binding.expires_at <= self.clock():
            raise BrokerError("expired")
        # Conservative byte ceiling rejects before claim; tokenizer refinement is separately versioned.
        await check_request_bounds(request, max_input_tokens=self.settings.max_input_tokens,
                                   max_output_tokens=self.settings.max_output_tokens,
                                   boundary="executor")
        permit = await self.ledger.claim(request, self.settings.lease_id)
        if permit.request_id != request.request_id or permit.lease_id != self.settings.lease_id:
            raise BrokerError("identity")
        stage = "inference"
        try:
            result = await self.infer(request)
            if result.request_id != request.request_id:
                stage = "response_codec"
                raise BrokerError("invalid_response")
            # A lost completion acknowledgement must never cause another provider request.
            stage = "ledger_complete"
            return (await self.ledger.complete(result, permit)).model_dump(mode="json")
        except asyncio.CancelledError as error:
            # Dispatch may have happened; the controller reconciles the claimed request.
            record_failure(stage, error)
            raise
        except Exception as error:
            raise BrokerError("completion_unknown", diagnostic=record_failure(stage, error)) from None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    deadline = time.monotonic() + 30
    while not args.config.exists() and time.monotonic() < deadline:
        time.sleep(0.1)
    # The native upload's file owner is not qualified; mode and type are checked before reading.
    settings = ExecutorSettings.model_validate_json(read_private(
        args.config, same_owner=False, message="Native uploaded lease identity must be owner-only"))
    provider_token = os.environ.get(settings.provider_env, "")
    ledger_token = os.environ.get(settings.ledger_env, "")
    ledger_channel = NativeLedgerChannel(settings.controller_origin, ledger_token)
    core = Executor(
        settings, ledger=ledger_channel, infer=OpenAIInference(settings.contract, provider_token)
    )
    serve(core, host="127.0.0.1", port=args.port, tls=None, loopback_executor=True)


if __name__ == "__main__":
    main()
