"""Minimal isolated inference service: claim once, send once, commit before replying."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import re
import ssl
import time
from pathlib import Path

from pydantic import Field, ValidationError

from .auth import AUTH_HEADER, verify_request
from .codec import decode_payload, encode_response
from .diagnostics import (
    exception_chain,
    report_transport_failure,
    sanitize_diagnostic,
    transport_failure_category,
)
from .http_service import JsonChannel, https_origin, parse_request, serve
from .protocol import (
    BrokerError,
    DispatchPermit,
    ExecutorContract,
    InferenceRequest,
    InferenceResult,
    StrictModel,
    canonical_bytes,
    required_input_reserve,
)
from .timing import PROVIDER_TIMEOUT_S, remaining_timeout

_LOG = logging.getLogger(__name__)
_DIAGNOSTIC_STAGES = frozenset({"provider_request", "response_codec", "inference", "ledger_complete"})
_DIAGNOSTIC_CATEGORIES = frozenset({"tls", "network", "provider_status", "provider_schema", "codec", "ledger", "internal"})


def _failure_category(error: BaseException, stage: str) -> str:
    """Only fixed categories; exception messages, names and request data never cross this boundary."""
    import httpx
    import httpx2
    from openai import APIConnectionError, APIResponseValidationError, APIStatusError
    from pydantic import ValidationError
    from pydantic_ai.exceptions import ModelHTTPError, UnexpectedModelBehavior

    causes = exception_chain(error)
    if any(isinstance(cause, ssl.SSLError) for cause in causes):
        return "tls"
    if any(isinstance(cause, (APIConnectionError, httpx.TransportError, httpx2.TransportError,
                             ConnectionError, TimeoutError)) for cause in causes):
        return "network"
    if stage == "ledger_complete":
        return "ledger"
    if stage == "response_codec" or isinstance(error, BrokerError) and error.code == "invalid_response":
        return "codec"
    if any(isinstance(cause, (APIStatusError, ModelHTTPError)) for cause in causes):
        return "provider_status"
    if any(isinstance(cause, (APIResponseValidationError, ValidationError, UnexpectedModelBehavior)) for cause in causes):
        return "provider_schema"
    return "internal"


def _report_failure(stage: str, error: BaseException) -> None:
    category = _failure_category(error, stage)
    if stage not in _DIAGNOSTIC_STAGES or category not in _DIAGNOSTIC_CATEGORIES:
        raise ValueError("Invalid fixed diagnostic category")
    _LOG.warning("IH_INFERENCE_FAILURE stage=%s category=%s", stage, category)


def _failure_diagnostic(stage: str, error: BaseException) -> dict[str, str]:
    existing = sanitize_diagnostic(error.diagnostic) if isinstance(error, BrokerError) else None
    if existing is not None:
        return existing
    category = _failure_category(error, stage)
    if category in {"tls", "network"}:
        category = transport_failure_category(error)
    diagnostic = sanitize_diagnostic({"boundary": stage, "category": category})
    if diagnostic is None:
        raise ValueError("Invalid fixed diagnostic category")
    return diagnostic


PLACEHOLDER = re.compile(r"^openshell:resolve:env:[A-Za-z_][A-Za-z0-9_]*$")


class ExecutorSettings(StrictModel):
    run_id: str
    lease_id: str
    contract: ExecutorContract
    controller_origin: str
    ingress_key_hex: str = Field(pattern=r"^[a-f0-9]{64}$", repr=False)
    provider_env: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    ledger_env: str = "IH_LEDGER_TOKEN"
    max_input_tokens: int = Field(gt=0)
    max_output_tokens: int = Field(gt=0)


class NativeLedgerChannel:
    def __init__(self, origin: str, placeholder: str, *, channel: JsonChannel | None = None):
        self.origin = https_origin(origin)
        if not PLACEHOLDER.fullmatch(placeholder):
            raise BrokerError("identity", "Native ledger credential placeholder is required")
        self.placeholder = placeholder
        self.channel = channel or JsonChannel()

    async def claim(self, request: InferenceRequest, lease_id: str) -> DispatchPermit:
        value = await self.channel.post(
            self.origin + "/v1/ledger/claim",
            canonical_bytes({"request": request.model_dump(mode="json"), "lease_id": lease_id}),
            {"Authorization": f"Bearer {self.placeholder}"},
        )
        return DispatchPermit.model_validate(value)

    async def complete(self, result: InferenceResult, permit: DispatchPermit) -> InferenceResult:
        value = await self.channel.post(
            self.origin + "/v1/ledger/complete",
            canonical_bytes(
                {"permit": permit.model_dump(mode="json"), "result": result.model_dump(mode="json")}
            ),
            {"Authorization": f"Bearer {self.placeholder}"},
        )
        return InferenceResult.model_validate(value)


class OpenAIInference:
    """One SDK request. No ambient credentials, custom URLs, retries, redirects, or tools."""

    def __init__(self, contract: ExecutorContract, placeholder: str, *, http_transport=None):
        if not PLACEHOLDER.fullmatch(placeholder):
            raise BrokerError("identity", "Native provider credential placeholder is required")
        self.contract = contract
        self.placeholder = placeholder
        self.http_transport = http_transport

    async def __call__(self, request: InferenceRequest) -> InferenceResult:
        import httpx2
        from openai import AsyncOpenAI
        from pydantic_ai.providers.openai import OpenAIProvider

        from .compat import model_for_contract

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
                report_transport_failure("provider_request", error)
                _LOG.warning("IH_INFERENCE_FAILURE stage=provider_request category=cancelled")
                raise
            except Exception as error:
                report_transport_failure("provider_request", error)
                _report_failure("provider_request", error)
                raise BrokerError("completion_unknown", diagnostic=_failure_diagnostic("provider_request", error)) from None
        usage = {
            key: value
            for key, value in vars(response.usage).items()
            if isinstance(value, int) and not isinstance(value, bool)
        }
        try:
            return InferenceResult(
                request_id=request.request_id,
                response=encode_response(response),
                usage=usage,
                provenance={"contract_digest": self.contract.digest, "provider_retries": 0},
            )
        except Exception as error:
            _report_failure("response_codec", error)
            raise BrokerError("completion_unknown", diagnostic=_failure_diagnostic("response_codec", error)) from None


class Executor:
    def __init__(self, settings: ExecutorSettings, *, ledger, infer, clock=time.time):
        https_origin(settings.controller_origin)
        self.settings = settings
        self.ledger = ledger
        self.infer = infer
        self.clock = clock

    async def handle(self, path: str, body: bytes, headers: dict[str, str]) -> dict:
        if path != "/v1/infer":
            raise BrokerError("policy")
        lower = {name.lower(): value for name, value in headers.items()}
        verify_request(
            bytes.fromhex(self.settings.ingress_key_hex),
            "POST",
            path,
            body,
            lower.get(AUTH_HEADER.lower(), ""),
            now=int(self.clock()),
        )
        try:
            request = InferenceRequest.model_validate(parse_request(body))
        except ValidationError:
            raise BrokerError("identity") from None
        decode_payload(request.payload)
        if (
            request.binding.run_id != self.settings.run_id
            or request.contract != self.settings.contract
        ):
            raise BrokerError("identity")
        if request.binding.expires_at <= self.clock():
            raise BrokerError("expired")
        output = request.contract.model_settings.get("max_tokens")
        if (
            not isinstance(output, int)
            or isinstance(output, bool)
            or output < request.contract.min_max_tokens
            or output <= 0
            or output > self.settings.max_output_tokens
        ):
            raise BrokerError("budget")
        # Conservative byte ceiling rejects before claim; tokenizer refinement is separately versioned.
        if await required_input_reserve(request.payload, request.contract) > self.settings.max_input_tokens:
            raise BrokerError("budget")
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
        except asyncio.CancelledError:
            # Dispatch may have happened; the controller reconciles the claimed request.
            _LOG.warning("IH_INFERENCE_FAILURE stage=%s category=cancelled", stage)
            raise
        except Exception as error:
            _report_failure(stage, error)
            raise BrokerError("completion_unknown", diagnostic=_failure_diagnostic(stage, error)) from None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    deadline = time.monotonic() + 30
    while not args.config.exists() and time.monotonic() < deadline:
        time.sleep(0.1)
    if args.config.is_symlink() or not args.config.is_file():
        raise BrokerError("identity", "Native uploaded lease identity is unavailable")
    settings = ExecutorSettings.model_validate_json(args.config.read_bytes())
    if args.config.stat().st_mode & 0o077:
        raise BrokerError("identity", "Lease configuration must be owner-only")
    provider_token = os.environ.get(settings.provider_env, "")
    ledger_token = os.environ.get(settings.ledger_env, "")
    ledger_channel = NativeLedgerChannel(settings.controller_origin, ledger_token)
    core = Executor(
        settings, ledger=ledger_channel, infer=OpenAIInference(settings.contract, provider_token)
    )
    serve(core, host="127.0.0.1", port=args.port, tls=None, loopback_executor=True)


if __name__ == "__main__":
    main()
