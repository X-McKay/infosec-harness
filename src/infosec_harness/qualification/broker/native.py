"""Mock-provider native acceptance through the production controller, adapter, executor and ledger.

An operator supplies a private JSON file named by ``IH_NATIVE_FIXTURE_CONFIG`` containing
``native`` (``NativeDeploymentConfig`` fields), the full executor ``contract``,
``controller_origin``, ``controller_ca`` and ``scope``. Only one static, bounded mock invocation
per scope is registered; there is no arbitrary root issuance. The contract must name the mock
backend and model below, and provider counts are observed at the mock, never inferred from names.

    python -m infosec_harness.qualification.broker.native mock-provider --certificate ... --stats-file ...
    python -m infosec_harness.qualification.broker.native worker
    python -m infosec_harness.qualification.broker.native prove

Start the controller with ``--factory infosec_harness.qualification.broker.native:controller_factory``.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import ssl
import tempfile
import threading
import time
from collections.abc import Mapping
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

CONFIGURATION = "native-fixture-config"
AGENT = "context"
WORKER_KEY = b"native-test-only-worker-key-000000000000"
MOCK_BACKEND = "mock"
MOCK_MODEL = "native-fixture-model"
MOCK_RESPONSE = "native-fixture-response"
SCOPES = ("local", "temporal", "cachepoint")
# The gateway provider record for the mock holds this test-only canary, never a real credential.
CANARY_AUTHORIZATION = "Bearer broker-fixture-canary-do-not-log"
PROVIDER_PATH = "/v1/chat/completions"
MAX_REQUEST_BYTES = 64 * 1024
STATS_FILE = "native-mock-stats.json"
COMMIT_MARKER = "native-temporal-committed.json"
RELEASE_MARKER = "native-temporal-release"


# ---------------------------------------------------------------------------------------------
# Mock HTTPS provider: admits only the canary on the chat route and publishes counts only.


def publish_stats(path: Path, counts: Mapping[str, int]) -> None:
    """Atomically publish bounded counters with restrictive permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            fd = -1
            json.dump(dict(counts), output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp_path, path)
    except BaseException:
        if fd >= 0:
            os.close(fd)
        temp_path.unlink(missing_ok=True)
        raise


class _MockServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], stats_file: Path) -> None:
        super().__init__(address, _MockHandler)
        self.stats_file = stats_file
        self.lock = threading.Lock()
        self.counts = {"provider_admitted": 0, "denied": 0}

    def record(self, category: str) -> None:
        with self.lock:
            self.counts[category] += 1
            publish_stats(self.stats_file, self.counts)


_RESPONSE = {
    "id": "chatcmpl-native-fixture", "object": "chat.completion", "created": 1, "model": MOCK_MODEL,
    "choices": [{"index": 0, "message": {"role": "assistant", "content": MOCK_RESPONSE},
                 "finish_reason": "stop"}],
    "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
}


class _MockHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def _handle(self) -> None:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None or not raw_length.isascii() or not raw_length.isdecimal():
            self._reply(400, {"error": "request_rejected"}, "denied")
            return
        length = int(raw_length)
        if length > MAX_REQUEST_BYTES:
            self._reply(413, {"error": "request_rejected"}, "denied")
            return
        if len(self.rfile.read(length) if length else b"") != length:
            self._reply(400, {"error": "request_rejected"}, "denied")
            return
        if (self.command == "POST" and self.path == PROVIDER_PATH
                and self.headers.get("Authorization") == CANARY_AUTHORIZATION):
            self._reply(200, _RESPONSE, "provider_admitted")
        else:
            self._reply(403, {"error": "request_denied"}, "denied")

    def _reply(self, status: int, payload: dict[str, Any], category: str) -> None:
        self.server.record(category)
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.close_connection = True
        self.end_headers()
        self.wfile.write(body)

    def __getattr__(self, name: str) -> Any:
        # Every syntactically accepted method is an ordinary counted denial unless admitted above.
        if name.startswith("do_"):
            return self._handle
        raise AttributeError(name)


class MockProvider:
    """HTTPS mock provider using operator-supplied certificate and key files."""

    def __init__(self, *, certificate: str | Path, private_key: str | Path, stats_file: str | Path,
                 bind_address: str = "127.0.0.1", port: int = 0) -> None:
        if not Path(certificate).is_file() or not Path(private_key).is_file():
            raise ValueError("Operator certificate and private key files must exist")
        self.server = _MockServer((bind_address, port), Path(stats_file))
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(certificate), str(private_key))
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
            # A fresh process owns a fresh observed-count epoch, published before serving.
            publish_stats(self.server.stats_file, self.server.counts)
        except BaseException:
            self.server.server_close()
            raise
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def address(self) -> tuple[str, int]:
        host, port = self.server.server_address[:2]
        return str(host), int(port)

    def __enter__(self) -> MockProvider:
        self.thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        if self.thread.is_alive():
            self.server.shutdown()
            self.thread.join(timeout=5)
        self.server.server_close()


# ---------------------------------------------------------------------------------------------
# Native acceptance through the production controller.


def configuration() -> dict:
    from infosec_harness.inference.protocol import BrokerError, ExecutorContract

    value = json.loads(Path(os.environ["IH_NATIVE_FIXTURE_CONFIG"]).read_text())
    contract = ExecutorContract.model_validate(value["contract"])
    if contract.backend != MOCK_BACKEND:
        raise BrokerError("policy", "Native acceptance accepts only the mock backend")
    if contract.model != MOCK_MODEL:
        raise BrokerError("policy", "Native acceptance accepts only the mock model")
    if value.get("scope") not in SCOPES:
        raise BrokerError("identity", "Unknown native acceptance scope")
    return value


def evidence_directory() -> Path:
    return Path(os.environ["IH_NATIVE_FIXTURE_CONFIG"]).parent


def reference(value: dict | None = None):
    from infosec_harness.inference.protocol import ExecutorContract, InvocationRequest

    value = configuration() if value is None else value
    scope = value["scope"]
    return InvocationRequest(
        mode="temporal" if scope == "temporal" else "local",
        root_id=f"native-fixture-{scope}-root", run_id=f"native-fixture-{scope}-run",
        invocation_id="native-fixture-invocation", operation_id="native-fixture-operation",
        agent=AGENT, configuration_digest=CONFIGURATION,
        contract=ExecutorContract.model_validate(value["contract"]),
    )


def controller_factory():
    from infosec_harness.inference import admission
    from infosec_harness.inference.controller import Controller
    from infosec_harness.inference.http_service import JsonChannel
    from infosec_harness.inference.openshell import NativeDeploymentConfig
    from infosec_harness.inference.protocol import (
        INFER_PATH,
        BrokerError,
        ReservationBinding,
        canonical_bytes,
    )
    from infosec_harness.persistence import budgets, db

    value = configuration()
    native = NativeDeploymentConfig.model_validate(value["native"])
    expected = reference(value)
    contract = expected.contract
    policy = admission.ReservationPolicy(AGENT, contract.profile, contract.digest, CONFIGURATION,
                                         10000, 32, 0, input_per_mtok=0, output_per_mtok=0)

    async def issue(request):
        if request != expected:
            raise BrokerError("identity")
        await db.create_all()
        async with db.session() as session:
            root = await session.get(db.BudgetLedger, expected.root_id)
            if root is not None:
                existing = root.state.get("operations", {}).get(expected.operation_id, {}).get("broker_binding")
                if existing:
                    return ReservationBinding.model_validate(existing)
            else:
                state = budgets.initial_state({"requests": 4, "tokens": 40000, "cost_usd": 0}, elapsed_seconds=600)
                state["agent_config_digests"] = {AGENT: CONFIGURATION}
                state["broker_run_id"] = expected.run_id
                session.add(db.BudgetLedger(root_id=expected.root_id, state=state))
                await session.commit()
        await budgets.reserve(expected.root_id, expected.operation_id,
            {"requests": 4, "tokens": 40000, "cost_usd": 0}, AGENT, CONFIGURATION,
            run_id=expected.run_id, invocation_id=expected.invocation_id)
        binding = ReservationBinding(root_id=expected.root_id, run_id=expected.run_id,
            invocation_id=expected.invocation_id, operation_id=expected.operation_id, agent=AGENT,
            contract_digest=contract.digest, expires_at=time.time() + 300)
        await admission.bind_reservation(binding, configuration_digest=CONFIGURATION)
        return binding

    core = Controller(
        adapter=native.build(), policies={(AGENT, contract.digest): policy}, worker_key=WORKER_KEY,
        issue_invocation=issue,
        executor_channel=JsonChannel(ca_file=str(native.gateway_ca),
            cert=(str(native.gateway_client_certificate), str(native.gateway_client_key)),
            gateway_origin=native.gateway, service_domain=native.service_domain),
    )
    if expected.mode == "temporal":
        # Acceptance-only ACK barrier: the production core has already committed its ledger row.
        original = core.handle
        marker, release = evidence_directory() / COMMIT_MARKER, evidence_directory() / RELEASE_MARKER

        async def delayed(path, body, headers):
            response = await original(path, body, headers)
            if path == INFER_PATH:
                try:
                    fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                except FileExistsError:
                    return response
                with os.fdopen(fd, "wb") as output:
                    output.write(canonical_bytes({"request_id": response["request_id"], "state": "completed"}))
                    output.flush()
                    os.fsync(output.fileno())
                deadline = time.monotonic() + 60
                while not release.exists() and time.monotonic() < deadline:
                    await asyncio.sleep(0.05)
            return response

        core.handle = delayed
    return core


async def post(channel, origin, path, body):
    from infosec_harness.inference.auth import AUTH_HEADER, sign_request

    return await channel.post(origin + path, body,
        {AUTH_HEADER: sign_request(WORKER_KEY, "POST", path, body, int(time.time()) + 30)})


async def worker() -> None:
    from pydantic_ai import Agent
    from pydantic_ai.messages import CachePoint

    from infosec_harness.agents.render import render_prompt
    from infosec_harness.domain.models import StackFingerprint
    from infosec_harness.inference.http_service import JsonChannel
    from infosec_harness.inference.protocol import (
        INVOCATIONS_PATH,
        ReservationBinding,
        canonical_bytes,
    )
    from infosec_harness.inference.transport import BrokerModel

    value = configuration()
    channel = JsonChannel(ca_file=value["controller_ca"])
    binding = ReservationBinding.model_validate(await post(channel, value["controller_origin"],
        INVOCATIONS_PATH, canonical_bytes(reference(value).model_dump(mode="json"))))
    os.environ["IH_NATIVE_WORKER_KEY"] = WORKER_KEY.decode()
    model = BrokerModel(contract=reference(value).contract, binding=binding,
        controller_url=value["controller_origin"], secret_env="IH_NATIVE_WORKER_KEY",
        ca_file=value["controller_ca"], client_cert=None, client_key=None,
        request_identity=lambda: "native-fixture-step")
    prompt = "native fixture"
    if value["scope"] == "cachepoint":
        prompt = render_prompt("Exercise the authored cache marker.", {"finding": {"cwe": "CWE-89"}},
            stack=StackFingerprint(languages={"python": 2}, test_frameworks=["pytest"]))
        if sum(isinstance(part, CachePoint) for part in prompt) != 1:
            raise AssertionError("Rendered prompt must carry exactly one authored cache marker")
    result = await Agent(model=model, output_type=str, model_settings={"max_tokens": 32}).run(prompt)
    if result.output != MOCK_RESPONSE:
        raise AssertionError("Native worker did not receive the mock provider response")
    print("NATIVE_PRODUCTION_WORKER_AGENT_OK")


async def prove() -> None:
    from sqlalchemy import select

    from infosec_harness.inference.auth import AUTH_HEADER
    from infosec_harness.inference.http_service import JsonChannel
    from infosec_harness.inference.protocol import (
        INFER_PATH,
        LEDGER_CLAIM_PATH,
        RESULTS_PATH,
        RUN_CLOSE_PATH,
        BrokerError,
        canonical_bytes,
    )
    from infosec_harness.persistence import db

    value, expected = configuration(), reference()
    channel, origin = JsonChannel(ca_file=value["controller_ca"]), value["controller_origin"]
    stats_file = evidence_directory() / STATS_FILE
    before = json.loads(stats_file.read_text())
    async with db.session() as session:
        rows = [row for row in (await session.scalars(select(db.InferenceRequestRecord))).all()
                if row.state == "completed" and row.request["binding"]["root_id"] == expected.root_id]
    if len(rows) != 1:
        raise AssertionError("Exactly one committed request must exist for the acceptance root")
    row = rows[0]
    request = row.request
    if value["scope"] == "cachepoint":
        markers = [item for message in request["payload"]["messages"]
                   for part in message["parts"] if part.get("part_kind") == "user-prompt"
                   for item in (part["content"] if isinstance(part["content"], list) else [])
                   if isinstance(item, dict) and item.get("kind") == "cache-point"]
        if markers != [{"kind": "cache-point", "ttl": "5m"}]:
            raise AssertionError("Committed request lost the exact cache marker representation")
        if before != {"provider_admitted": 1, "denied": 0}:
            raise AssertionError("Mock provider must observe exactly one admitted send")
    body = canonical_bytes(request)
    for path, payload, headers, message in (
            (INFER_PATH, body, {AUTH_HEADER: f"v1:{int(time.time()) + 30}:" + "0" * 64},
             "Unsigned ingress accepted"),
            (LEDGER_CLAIM_PATH, canonical_bytes({"request": request, "lease_id": row.lease_id}),
             {"Authorization": "Bearer " + WORKER_KEY.decode()},
             "Worker key accepted on executor ledger channel")):
        try:
            await channel.post(origin + path, payload, headers)
        except BrokerError as error:
            if error.code != "auth":
                raise
        else:
            raise AssertionError(message)
    result = await post(channel, origin, RESULTS_PATH, body)
    if result["request_id"] != row.request_id or (result["usage"]["input_tokens"],
                                                  result["usage"]["output_tokens"]) != (3, 2):
        raise AssertionError("Saved result differs from the committed mock response")
    close = canonical_bytes({"run_id": expected.run_id, "root_id": expected.root_id})
    if (await post(channel, origin, RUN_CLOSE_PATH, close))["state"] != "closed":
        raise AssertionError("Native run did not close")
    if await post(channel, origin, RESULTS_PATH, body) != result:
        raise AssertionError("Saved result changed after close")
    if (await post(channel, origin, RUN_CLOSE_PATH, close))["state"] != "closed":
        raise AssertionError("Repeat close was not idempotent")
    if json.loads(stats_file.read_text()) != before:
        raise AssertionError("Proof steps reached the mock provider")
    proof = {"scope": value["scope"], "completed": True, "request": request, "result": result,
             "worker_auth_denied": True, "worker_ledger_auth_denied": True, "closed": True,
             "saved_after_close": True, "provider_counts": before}
    (evidence_directory() / f"native-{value['scope']}-proof.json").write_text(json.dumps(proof, sort_keys=True))
    print("NATIVE_AUTH_COMMIT_CLOSE_SAVED_RESULT_OK")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=("mock-provider", "worker", "prove"))
    parser.add_argument("--bind-address", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18443)
    parser.add_argument("--certificate")
    parser.add_argument("--private-key")
    parser.add_argument("--stats-file", type=Path)
    args = parser.parse_args(argv)
    if args.mode == "mock-provider":
        if not (args.certificate and args.private_key and args.stats_file):
            parser.error("The mock provider requires --certificate, --private-key and --stats-file")
        try:
            provider = MockProvider(certificate=args.certificate, private_key=args.private_key,
                                    stats_file=args.stats_file, bind_address=args.bind_address, port=args.port)
        except (OSError, ValueError):
            parser.error("Mock provider configuration or TLS setup failed")
        with provider, suppress(KeyboardInterrupt):
            provider.thread.join()
        return 0
    asyncio.run(worker() if args.mode == "worker" else prove())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
