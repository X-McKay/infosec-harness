"""Qualification-only service fixtures for real HTTPS, PostgreSQL and Temporal broker gates.

Used only by ``scripts/broker_service_check.py``. The fake native adapter, mock provider and
credential substitutions exercise the production controller, executor and SDK transports, but
provide no OpenShell confinement or credential-nonexposure evidence. Nothing in serving code
imports this module, and a production deployment never routes through it::

    python -m infosec_harness.qualification.broker.service {provider,controller,executor,temporal-worker}
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import uuid
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from infosec_harness.qualification.broker.validators import ROOT

AGENTS = ("intake", "recon", "env-planner", "build-repair", "partial-build", "context",
          "probe-planner", "probe-author", "probe-diagnosis", "probe-repair", "verdict")


def private_json(path: Path, value) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as output:
        json.dump(value, output)


def free_port() -> int:
    with socket.socket() as endpoint:
        endpoint.bind(("127.0.0.1", 0))
        return endpoint.getsockname()[1]


def generate_pki(directory: Path) -> dict[str, str]:
    """Create one-day private fixture certificates with the host OpenSSL CLI."""
    def openssl(*args: str) -> None:
        subprocess.run(["openssl", *args], check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)

    ca = directory / "ca.pem"
    ca_key = directory / "ca.key.pem"
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=broker-qualification-only", "-keyout", str(ca_key), "-out", str(ca))
    result = {"ca": str(ca)}
    for role, usage in (("server", "serverAuth"), ("client", "clientAuth")):
        key, cert, csr = (directory / f"{role}.{suffix}.pem" for suffix in ("key", "cert", "csr"))
        extensions = directory / f"{role}.extensions"
        extensions.write_text("basicConstraints=CA:FALSE\nextendedKeyUsage=" + usage +
                              ("\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n" if role == "server" else "\n"))
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
                "-keyout", str(key), "-out", str(csr))
        openssl("x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
                "-CAcreateserial", "-days", "1", "-extfile", str(extensions), "-out", str(cert))
        result[f"{role}_key"], result[f"{role}_cert"] = str(key), str(cert)
    for path in directory.iterdir():
        if path.is_file():
            path.chmod(0o600)
    return result


def settings_files(directory: Path, pki: dict, controller_port: int, provider_port: int) -> dict:
    import yaml
    controller = f"https://127.0.0.1:{controller_port}"
    provider = f"https://127.0.0.1:{provider_port}/v1"
    model = {"backends": {"qualification": {"kind": "openai_compatible", "transport": "brokered",
        "base_url": provider, "max_retries": 0, "max_retries_under_temporal": 0,
        "prices": {"qualification-model": {"input_per_mtok": 0.0, "output_per_mtok": 0.0}}}},
        "default_backend": "qualification", "model_catalog": {tier: {"qualification": "qualification-model"}
            for tier in ("sonnet", "opus", "haiku")}, "model_policies": {
                "fast-v1": "haiku", "balanced-v1": "sonnet", "reasoning-v1": "opus"}}
    agent = {"max_requests": 50, "max_input_tokens": 1_000_000, "max_output_tokens": 100_000,
             "max_cost_usd": 1.0, "max_duration_seconds": 300.0}
    root = {**agent, "max_requests": 1000, "max_input_tokens": 20_000_000,
            "max_output_tokens": 2_000_000, "max_cost_usd": 100.0, "max_duration_seconds": 600.0}
    catalog = {"version": 1, "enabled": True, "controller": {"url": controller,
        "hmac_env": "BROKER_QUALIFICATION_WORKER_KEY", "ca_file": pki["ca"],
        "client_cert": pki["client_cert"], "client_key": pki["client_key"]},
        "profiles": {"inference-only": {"backend_name": "qualification", "endpoint": provider,
            "provider_binding": "qualification-provider", "provider_env": "QUALIFICATION_PROVIDER",
            "ledger_origin": controller, "ledger_profile": "qualification-ledger",
            "executor_image": "sha256:" + "1" * 64, "supervisor_image": "sha256:" + "2" * 64,
            "approved_policy": {"version": 1, "network_policies": {}}, "inspection": []}},
        "agent_profiles": {name: "inference-only" for name in AGENTS}, "root_limits": root,
        "agent_limits": {name: agent for name in AGENTS}}
    paths = {}
    for name, value in (("models", model), ("broker", catalog)):
        path = directory / f"{name}.yaml"
        path.write_text(yaml.safe_dump(value))
        path.chmod(0o600)
        paths[name] = str(path)
    return {**paths, "controller_url": controller, "provider_url": provider}


def environment(manifest: dict) -> dict[str, str]:
    values = dict(os.environ)
    values.update(HARNESS_MODEL_MODE="live", HARNESS_MODELS_CONFIG=manifest["models"],
        HARNESS_BROKER_CONFIG=manifest["broker"], HARNESS_DATABASE_URL=manifest["database_url"],
        HARNESS_MODEL_BACKEND="qualification", BROKER_QUALIFICATION_WORKER_KEY=manifest["worker_key"],
        HARNESS_BROKER_SERVICE_MANIFEST=manifest["manifest"], SSL_CERT_FILE=manifest["pki"]["ca"],
        PYTHONPATH=str(ROOT / "src"),
        PYDANTIC_AI_NO_BANNER="1", HARNESS_AGENT_RUN_TIMEOUT_S="90")
    return values


class FakeNativeAdapter:
    """TEST ONLY: no sandbox, native policy, or secret isolation claims."""
    def __init__(self, manifest: dict):
        from infosec_harness.inference.openshell import LeaseStore
        self.manifest = manifest
        self.deployment = "qualification-" + manifest["run_id"]
        self.store = LeaseStore(Path(manifest["directory"]) / "leases")
        self.leases = {lease.lease_id: lease for lease in self.store.load()}
        self._lock = asyncio.Lock()
        self.lock = self._lock

    def spec(self, contract):
        from infosec_harness.agents.registry import resolved_agent_configs
        from infosec_harness.inference.protocol import BrokerError
        allowed = [value.model.broker_contract for value in resolved_agent_configs().values()]
        if contract not in allowed:
            raise BrokerError("identity")
        return SimpleSpec()

    async def ensure(self, run_id, contract):
        async with self._lock:
            return await self._ensure(run_id, contract)

    async def _ensure(self, run_id, contract):
        from infosec_harness.inference.executor import ExecutorSettings
        from infosec_harness.inference.openshell import Lease
        from infosec_harness.inference.protocol import BrokerError
        self.spec(contract)
        if self.store.is_run_revoked(run_id):
            raise BrokerError("policy")
        for lease in self.leases.values():
            if lease.run_id == run_id and lease.contract == contract and lease.status == "ready":
                return lease
        lease_id = str(uuid.uuid4())
        port = free_port()
        lease = Lease(lease_id=lease_id, deployment=self.deployment, run_id=run_id, contract=contract,
            credential_revision="mock-only", name=f"https://127.0.0.1:{port}/v1/infer",
            ingress_key_hex=secrets.token_hex(32), ledger_key=secrets.token_urlsafe(32),
            native_id="fixture-without-native-isolation", status="ready")
        settings = ExecutorSettings(run_id=run_id, lease_id=lease_id, contract=contract,
            controller_origin=self.manifest["controller_url"], ingress_key_hex=lease.ingress_key_hex,
            provider_env="QUALIFICATION_PROVIDER", max_input_tokens=1_000_000, max_output_tokens=100_000)
        marker = Path(self.manifest["directory"]) / "arm-executor-fault"
        fault = marker.read_text().strip() if marker.exists() else "none"
        marker.unlink(missing_ok=True)
        path = Path(self.manifest["directory"]) / f"executor-{lease_id}.json"
        private_json(path, {"settings": settings.model_dump(mode="json"), "ledger_key": lease.ledger_key,
                           "port": port, "fault": fault})
        with open(Path(self.manifest["directory"]) / f"executor-{lease_id}.log", "ab") as log:
            process = subprocess.Popen([sys.executable, "-m", "infosec_harness.qualification.broker.service",
                "executor", "--manifest",
                self.manifest["manifest"], "--config", str(path)], env=environment(self.manifest),
                stdout=log, stderr=log)
        with open(Path(self.manifest["directory"]) / "pids.jsonl", "a") as output:
            output.write(json.dumps({"pid": process.pid, "role": "executor", "lease": lease_id}) + "\n")
        self.leases[lease_id] = lease
        self.store.save(lease)
        await wait_port(port, process=process)
        return lease

    async def verify(self, lease):
        from infosec_harness.inference.protocol import BrokerError
        if lease.deployment != self.deployment or lease.status != "ready":
            raise BrokerError("identity")
        return {"native_id": lease.native_id, "policy_digest": lease.contract.policy_digest,
                "executor_image": lease.contract.executor_image, "supervisor_image": lease.contract.supervisor_image,
                "profile": lease.contract.profile, "credential_revision": lease.credential_revision}

    def service_url(self, lease):
        return lease.name

    async def revoke(self, lease):
        lease.status = "revoked"
        self.store.save(lease)
        for line in (Path(self.manifest["directory"]) / "pids.jsonl").read_text().splitlines():
            value = json.loads(line)
            if value.get("lease") == lease.lease_id:
                with suppress(ProcessLookupError):
                    os.kill(value["pid"], signal.SIGTERM)


class SimpleSpec:
    """An explicit fake lifecycle spec, never an OpenShell NativeSpec."""


async def wait_port(port: int, *, process=None) -> None:
    for _ in range(200):
        if process is not None and process.poll() is not None:
            raise RuntimeError("Fixture process stopped before readiness")
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            await writer.wait_closed()
            return
        except OSError:
            await asyncio.sleep(0.05)
    raise TimeoutError("Fixture listener unavailable")


def run_provider(manifest: dict) -> None:
    import threading
    lock = threading.Lock()
    event_path = Path(manifest["directory"]) / "upstream.jsonl"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            size = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(size)
            value = json.loads(raw)
            authorized = self.headers.get("Authorization") == "Bearer " + manifest["canary"]
            has_tool = any(message.get("role") == "tool" for message in value.get("messages", []))
            # Test-only opt-in routing. Normal context tool/fault fixtures retain their path.
            import re
            user_parts = []
            for message in value.get("messages", []):
                if message.get("role") != "user":
                    continue
                content = message.get("content", "")
                if isinstance(content, str):
                    user_parts.append(content)
                else:
                    user_parts.extend(part["text"] for part in content if part.get("type") == "text")
            user_text = "\n".join(user_parts)
            markers = re.findall(r"<broker-qualification-agent>([^<]+)</broker-qualification-agent>", user_text)
            qualification_agent = markers[0] if len(markers) == 1 and markers[0] in AGENTS else None
            with lock, event_path.open("a") as output:
                output.write(json.dumps({"path": self.path, "authorized": authorized,
                        "canary_in_body": manifest["canary"].encode() in raw, "tool_return": has_tool,
                        "qualification_agent": qualification_agent}) + "\n")
            tools = [tool["function"] for tool in value.get("tools", [])]
            read = next((tool for tool in tools if tool["name"].endswith("read_file")), None)
            final = next((tool for tool in tools if "summary" in tool.get("parameters", {}).get("properties", {})), None)
            if qualification_agent is not None:
                from infosec_harness.agents.stubs import _STUBS
                arguments = {} if qualification_agent == "intake" else _STUBS[qualification_agent](user_text)
                expected = "final_result_inconclusive" if qualification_agent == "verdict" else "final_result"
                output = next((tool for tool in tools if tool["name"] == expected), None)
                if output is None:
                    raise AssertionError("Qualification requires the actual registered output tool")
                name = output["name"]
            elif read is not None and not has_tool:
                name, arguments = read["name"], {"path": "sample.py"}
            elif final is not None:
                name, arguments = final["name"], {"summary": "qualification context", "source": None,
                    "sink": None, "path": [], "sanitizers": [], "reachability": "unknown",
                    "reachability_rationale": "fixture evidence is deliberately incomplete"}
            else:
                name, arguments = "final_result", {"summary": "qualification context", "source": None,
                    "sink": None, "path": [], "sanitizers": [], "reachability": "unknown",
                    "reachability_rationale": "fixture evidence is deliberately incomplete"}
            response = {"id": "qualification-response", "object": "chat.completion", "created": 1,
                "model": "qualification-model", "choices": [{"index": 0, "finish_reason": "tool_calls",
                    "message": {"role": "assistant", "content": None, "tool_calls": [{"id": "fixture-call",
                        "type": "function", "function": {"name": name, "arguments": json.dumps(arguments)}}]}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}}
            encoded = json.dumps(response).encode()
            self.send_response(200 if authorized and self.path == "/v1/chat/completions" else 401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
    server = ThreadingHTTPServer(("127.0.0.1", manifest["provider_port"]), Handler)
    from infosec_harness.inference.http_service import server_tls
    server.socket = server_tls(manifest["pki"]["server_cert"], manifest["pki"]["server_key"]).wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def run_executor(manifest: dict, config: dict) -> None:
    import httpx2

    from infosec_harness.inference.executor import (
        Executor,
        ExecutorSettings,
        NativeLedgerChannel,
        OpenAIInference,
    )
    from infosec_harness.inference.http_service import JsonChannel, serve, server_tls
    settings = ExecutorSettings.model_validate(config["settings"])

    class MockLedgerSubstitution(JsonChannel):
        async def post(self, url, body, headers, **kwargs):
            if url.endswith(("/v1/ledger/claim", "/v1/ledger/complete")):
                headers = {**headers, "Authorization": "Bearer " + config["ledger_key"]}
            return await super().post(url, body, headers, **kwargs)

    class MockProviderSubstitution(httpx2.AsyncBaseTransport):
        def __init__(self):
            self.wrapped = httpx2.AsyncHTTPTransport(verify=ssl.create_default_context(cafile=manifest["pki"]["ca"]), trust_env=False, retries=0)

        async def handle_async_request(self, request):
            request.headers["Authorization"] = "Bearer " + manifest["canary"]
            return await self.wrapped.handle_async_request(request)

        async def aclose(self):
            await self.wrapped.aclose()

    class FaultFixture:
        def __init__(self, core):
            self.core = core

        async def handle(self, path, body, headers):
            result = await self.core.handle(path, body, headers)
            if config["fault"] != "none":
                marker = Path(manifest["directory"]) / "executor-result-committed"
                marker.write_text(result["request_id"])
                if config["fault"] == "lost_ack":
                    os._exit(77)
                if config["fault"] == "hold_ack":
                    while not (Path(manifest["directory"]) / "release-executor-ack").exists():
                        await asyncio.sleep(0.05)
            return result

    channel = MockLedgerSubstitution(ca_file=manifest["pki"]["ca"], cert=(manifest["pki"]["client_cert"], manifest["pki"]["client_key"]))
    inference = OpenAIInference(settings.contract, "openshell:resolve:env:QUALIFICATION_PROVIDER",
                               http_transport=MockProviderSubstitution())

    async def fault_inference(request):
        result = await inference(request)
        if config["fault"] == "before_result_commit":
            os._exit(78)
        return result

    core = Executor(settings, ledger=NativeLedgerChannel(settings.controller_origin,
        "openshell:resolve:env:IH_LEDGER_TOKEN", channel=channel),
        infer=fault_inference)
    serve(FaultFixture(core), host="127.0.0.1", port=config["port"],
        tls=server_tls(manifest["pki"]["server_cert"], manifest["pki"]["server_key"], client_ca=manifest["pki"]["ca"]))


def run_controller(manifest: dict) -> None:
    from infosec_harness.inference.controller import Controller
    from infosec_harness.inference.http_service import JsonChannel, serve, server_tls
    from infosec_harness.inference.invocations import build_reservation_policy, issue_invocation
    from infosec_harness.persistence import db
    async def bootstrap():
        await db.create_all()
        await db._engine().dispose()
    asyncio.run(bootstrap())
    class ObservedController(Controller):
        async def infer(self, request):
            from infosec_harness.inference.protocol import BrokerError
            try:
                return await super().infer(request)
            except BrokerError as exc:
                if exc.code == "conflict":
                    stored = await self.ledger.get(request.request_id)
                    if stored is not None:
                        def differences(left, right, path=""):
                            if type(left) is not type(right):
                                return [path + ":type"]
                            if isinstance(left, dict):
                                keys = left.keys() | right.keys()
                                return [item for key in sorted(keys) for item in
                                    differences(left.get(key), right.get(key), path + "." + key)]
                            if isinstance(left, list):
                                if len(left) != len(right):
                                    return [path + ":length"]
                                return [item for index, (a, b) in enumerate(zip(left, right, strict=True))
                                    for item in differences(a, b, path + "." + str(index))]
                            return [] if left == right else [path]
                        fields = differences(stored.request.model_dump(mode="json"), request.model_dump(mode="json"))
                        with (Path(manifest["directory"]) / "conflict-fields.jsonl").open("a") as output:
                            output.write(json.dumps({"request_id": request.request_id, "fields": fields,
                                "deferred_capability_sets_equal": set(stored.request.payload.parameters.get("deferred_capability_ids", [])) ==
                                    set(request.payload.parameters.get("deferred_capability_ids", []))}) + "\n")
                raise
    core = ObservedController(adapter=FakeNativeAdapter(manifest), policies=build_reservation_policy,
        worker_key=manifest["worker_key"].encode(), issue_invocation=issue_invocation,
        executor_channel=JsonChannel(ca_file=manifest["pki"]["ca"],
            cert=(manifest["pki"]["client_cert"], manifest["pki"]["client_key"])))
    serve(core, host="127.0.0.1", port=manifest["controller_port"],
        tls=server_tls(manifest["pki"]["server_cert"], manifest["pki"]["server_key"], client_ca=manifest["pki"]["ca"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("provider", "controller", "executor", "temporal-worker"))
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--direct-stub", action="store_true")
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    os.environ.update(environment(manifest))
    if args.direct_stub:
        os.environ["HARNESS_MODEL_MODE"] = "stub"
    if args.role == "provider":
        run_provider(manifest)
    elif args.role == "controller":
        run_controller(manifest)
    elif args.role == "executor":
        run_executor(manifest, json.loads(args.config.read_text()))
    else:
        from infosec_harness.qualification.broker.service_workflow import serve_worker
        asyncio.run(serve_worker(manifest))


if __name__ == "__main__":
    main()
