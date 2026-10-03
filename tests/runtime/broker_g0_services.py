"""Test-only HTTPS provider and ledger endpoints for OpenShell G0 qualification.

This fixture is not a durable ledger or production service. It accepts only a
fixed test canary for the provider route and a separately scoped test token for
the ledger route. Captured state and stats contain counts only.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import threading
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from broker_fixtures import CANARY_AUTHORIZATION

PROVIDER_PATH = "/v1/chat/completions"
LEDGER_PATH = "/ledger/g0"
MAX_REQUEST_BYTES = 64 * 1024
_KNOWN_METHODS = frozenset({"POST", "GET", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"})
ROTATED_CANARY_TOKEN = "broker-fixture-canary-rotated-do-not-log"
ROTATED_CANARY_AUTHORIZATION = f"Bearer {ROTATED_CANARY_TOKEN}"
_PROVIDER_AUTHORIZATIONS = {
    "v1": CANARY_AUTHORIZATION,
    "v2": ROTATED_CANARY_AUTHORIZATION,
}


class _ServiceServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        *,
        ledger_token: str,
        stats_file: Path,
        credential_revision: str,
    ) -> None:
        super().__init__(address, _ServiceHandler)
        if not ledger_token:
            self.server_close()
            raise ValueError("a test ledger token is required")
        self.ledger_token = ledger_token
        self._expected_provider_authorization = _PROVIDER_AUTHORIZATIONS[credential_revision]
        self.stats_file = stats_file
        self.lock = threading.Lock()
        self.counts = {
            "provider_admitted": 0,
            "ledger_admitted": 0,
            "denied": 0,
        }

    def record(self, category: str) -> None:
        with self.lock:
            if category == "provider_admitted" or category == "ledger_admitted":
                self.counts[category] += 1
            else:
                self.counts["denied"] += 1
            _publish_stats(self.stats_file, self.counts)


def _publish_stats(path: Path, counts: Mapping[str, int]) -> None:
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
        path.chmod(0o600)
    except BaseException:
        if fd >= 0:
            os.close(fd)
        temp_path.unlink(missing_ok=True)
        raise


class _ServiceHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def _handle(self) -> None:
        raw_length = self.headers.get("Content-Length")
        try:
            if raw_length is None or not raw_length.isascii() or not raw_length.isdecimal():
                raise ValueError
            length = int(raw_length)
        except ValueError:
            self._reject(400)
            return
        if length > MAX_REQUEST_BYTES:
            self._reject(413)
            return
        body = self.rfile.read(length) if length else b""
        if len(body) != length:
            self._reject(400)
            return

        server = self.server
        provider_auth = self.headers.get("Authorization") == server._expected_provider_authorization
        ledger_auth = self.headers.get("Authorization") == f"Bearer {server.ledger_token}"
        provider_allowed = self.command == "POST" and self.path == PROVIDER_PATH and provider_auth
        ledger_allowed = self.command == "POST" and self.path == LEDGER_PATH and ledger_auth
        if provider_allowed:
            server.record("provider_admitted")
            self._reply(200, _PROVIDER_RESPONSE)
        elif ledger_allowed:
            server.record("ledger_admitted")
            self._reply(200, {"accepted": True})
        else:
            server.record("denied")
            self._reply(403, {"error": "request_denied"})

    def _reject(self, status: int) -> None:
        # Do not consume malformed or oversized bodies; close to prevent keep-alive desync.
        self.server.record("denied")
        self._reply(status, {"error": "request_rejected"})

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
    do_PATCH = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle

    def __getattr__(self, name: str) -> Any:
        # BaseHTTPRequestHandler dispatches verbs through ``do_<METHOD>``. Treat any
        # syntactically accepted but unimplemented method as an ordinary denied request.
        if name.startswith("do_"):
            return self._handle
        raise AttributeError(name)


_PROVIDER_RESPONSE = {
    "id": "chatcmpl-g0-fixture",
    "object": "chat.completion",
    "created": 1,
    "model": "g0-fixture-model",
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": "g0-fixture-response"},
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
}


class G0Services:
    """HTTPS fixture which uses operator-supplied certificate and key files."""

    def __init__(
        self,
        *,
        certificate: str | Path,
        private_key: str | Path,
        ledger_token: str,
        stats_file: str | Path,
        bind_address: str = "127.0.0.1",
        port: int = 18443,
        credential_revision: str = "v1",
    ) -> None:
        cert_path = Path(certificate)
        key_path = Path(private_key)
        if not cert_path.is_file() or not key_path.is_file():
            raise ValueError("operator certificate and private key files must exist")
        if not 0 <= port <= 65535:
            raise ValueError("port must be between 0 and 65535")
        if credential_revision not in _PROVIDER_AUTHORIZATIONS:
            raise ValueError("unsupported test credential revision")
        self.server = _ServiceServer(
            (bind_address, port),
            ledger_token=ledger_token,
            stats_file=Path(stats_file),
            credential_revision=credential_revision,
        )
        try:
            import ssl

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(cert_path), str(key_path))
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
            # A fresh process owns a fresh observed-count epoch. Publish readiness
            # counters only after certificate setup succeeds and before serving starts.
            _publish_stats(self.server.stats_file, self.server.counts)
        except BaseException:
            self.server.server_close()
            raise
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def address(self) -> tuple[str, int]:
        host, port = self.server.server_address[:2]
        return str(host), int(port)

    def start(self) -> G0Services:
        self.thread.start()
        return self

    def close(self) -> None:
        if self.thread.is_alive():
            self.server.shutdown()
            self.thread.join(timeout=5)
        self.server.server_close()

    def __enter__(self) -> G0Services:
        return self.start()

    def __exit__(self, *_exc: object) -> None:
        self.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind-address", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18443)
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--stats-file", required=True)
    parser.add_argument(
        "--credential-revision", choices=tuple(_PROVIDER_AUTHORIZATIONS), default="v1"
    )
    args = parser.parse_args()
    token = os.environ.get("G0_LEDGER_TOKEN")
    if not token:
        parser.error("G0_LEDGER_TOKEN is required")
    try:
        services = G0Services(
            certificate=args.certificate,
            private_key=args.private_key,
            ledger_token=token,
            stats_file=args.stats_file,
            bind_address=args.bind_address,
            port=args.port,
            credential_revision=args.credential_revision,
        )
    except (OSError, ValueError):
        parser.error("service configuration or TLS setup failed")
    try:
        with services:
            services.thread.join()
    except KeyboardInterrupt:
        services.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
