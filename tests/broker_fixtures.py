"""Test-only TLS mock upstream for credential broker transport tests."""

from __future__ import annotations

import json
import shutil
import ssl
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

CANARY_TOKEN = "broker-fixture-canary-do-not-log"
CANARY_AUTHORIZATION = f"Bearer {CANARY_TOKEN}"
PLACEHOLDER = "{{HARNESS_BROKER_TOKEN}}"
CHAT_COMPLETIONS_PATH = "/v1/chat/completions"
MAX_REQUEST_BYTES = 1_000_000
_KNOWN_METHODS = frozenset({"POST", "GET", "PUT", "DELETE"})


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], expected_authorization: str):
        super().__init__(server_address, _Handler)
        self.expected_authorization = expected_authorization
        self.lock = threading.Lock()
        self.permitted: list[dict[str, Any]] = []
        self.denied: list[dict[str, Any]] = []

    def record(
        self, bucket: list[dict[str, Any]], *, method: str, exact_route: bool, authorized: bool
    ) -> None:
        # Retain only bounded classifications; request paths and bodies can contain secrets.
        safe_method = method if method in _KNOWN_METHODS else "OTHER"
        with self.lock:
            bucket.append(
                {"method": safe_method, "exact_route": exact_route, "authorized": authorized}
            )


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def _handle(self) -> None:
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length) if raw_length is not None else 0
        except ValueError:
            self._reject(400)
            return
        if length < 0:
            self._reject(400)
            return
        if length > MAX_REQUEST_BYTES:
            self._reject(413)
            return
        body = self.rfile.read(length) if length else b""
        if len(body) != length:
            self._reject(400)
            return

        auth_ok = self.headers.get("Authorization") == self.server.expected_authorization
        route_ok = self.path == CHAT_COMPLETIONS_PATH
        method_ok = self.command == "POST"
        allowed = auth_ok and route_ok and method_ok
        record = self.server.permitted if allowed else self.server.denied
        self.server.record(record, method=self.command, exact_route=route_ok, authorized=auth_ok)
        if allowed:
            payload = {
                "id": "chatcmpl-fixture",
                "object": "chat.completion",
                "created": 1,
                "model": "fixture-model",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "fixture response"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
            }
            self._reply(200, payload)
        else:
            self._reply(403, {"error": {"message": "request denied", "type": "permission_error"}})

    def _reject(self, status: int) -> None:
        # Do not read an oversized or malformed body and close to avoid keep-alive desync.
        self._reply(
            status, {"error": {"message": "request rejected", "type": "invalid_request_error"}}
        )

    def _reply(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.close_connection = True
        self.end_headers()
        self.wfile.write(body)

    do_POST = _handle
    do_GET = _handle
    do_PUT = _handle
    do_DELETE = _handle


class MockUpstream:
    """Ephemeral localhost TLS server; callers supply trusted CA via ``client_context``."""

    def __init__(self, expected_authorization: str = CANARY_AUTHORIZATION):
        if expected_authorization != CANARY_AUTHORIZATION:
            raise ValueError("fixture accepts only its fixed test canary")
        self._tmp = tempfile.TemporaryDirectory(prefix="broker-upstream-")
        self.server: _Server | None = None
        self.thread: threading.Thread | None = None
        try:
            self.directory = Path(self._tmp.name)
            self.certificate = self.directory / "server.crt"
            self.private_key = self.directory / "server.key"
            openssl = shutil.which("openssl")
            if not openssl:
                raise RuntimeError("openssl is required for the TLS mock upstream fixture")
            subprocess.run(
                [
                    openssl,
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(self.private_key),
                    "-out",
                    str(self.certificate),
                    "-days",
                    "1",
                    "-subj",
                    "/CN=localhost",
                    "-addext",
                    "subjectAltName=DNS:localhost,IP:127.0.0.1",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.private_key.chmod(0o600)
            self.server = _Server(("127.0.0.1", 0), expected_authorization)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(self.certificate), str(self.private_key))
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
        except BaseException:
            if self.server is not None:
                self.server.server_close()
            self._tmp.cleanup()
            raise

    @property
    def url(self) -> str:
        assert self.server is not None
        return f"https://localhost:{self.server.server_port}"

    def client_context(self) -> ssl.SSLContext:
        return ssl.create_default_context(cafile=str(self.certificate))

    @property
    def permitted_count(self) -> int:
        assert self.server is not None
        with self.server.lock:
            return len(self.server.permitted)

    @property
    def denied_count(self) -> int:
        assert self.server is not None
        with self.server.lock:
            return len(self.server.denied)

    def close(self) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        if self.thread is not None:
            self.thread.join(timeout=5)
        self._tmp.cleanup()

    def __enter__(self) -> MockUpstream:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def assert_no_secret_material(
    data: bytes | str, *, canary_token: str = CANARY_TOKEN, placeholder: str = PLACEHOLDER
) -> None:
    """Scan for the credential value, its authorization header, and placeholders."""
    raw = data.encode() if isinstance(data, str) else data
    if f"Bearer {canary_token}".encode() in raw:
        raise AssertionError("canary authorization detected in scanned output")
    if canary_token.encode() in raw:
        raise AssertionError("canary secret detected in scanned output")
    if placeholder.encode() in raw:
        raise AssertionError("credential placeholder detected in scanned output")
