"""G0-only executor proof; test-only HMAC proves reachability, not reservation authority.

This module is not production inference transport. Its local HMAC does not reserve budget,
authorize durable replay, or establish exactly-once provider dispatch.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import hmac
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
REQUEST_PATH = "/infer"
LEDGER_PATH = "/ledger/g0"
UPSTREAM_PATH = "/v1/chat/completions"
ADMISSION_HEADER = "X-Harness-G0"
LEDGER_HEADER = "Authorization"
_PLACEHOLDER = re.compile(r"^openshell:resolve:env:[A-Za-z_][A-Za-z0-9_]*$")
_EXPIRY = re.compile(r"^(0|[1-9][0-9]*)$")
_SIGNATURE = re.compile(r"^[0-9a-f]{64}$")


class AdmissionError(ValueError):
    """The test-only G0 caller proof was missing or invalid."""


class UpstreamError(RuntimeError):
    """A fixed endpoint failed or returned an invalid result."""


@dataclass(frozen=True)
class ExecutorSettings:
    upstream_url: str
    admission_key: bytes
    provider_placeholder: str
    controller_url: str | None = None
    ledger_token: str | None = None


def _validate_https_origin(value: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError as exc:
        raise ValueError("executor endpoint must be an HTTPS origin") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("executor endpoint must be an HTTPS origin")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("executor endpoint must be an HTTPS origin") from exc
    return urllib.parse.urlunsplit(("https", parsed.netloc, "", "", ""))


def settings_from_environment(
    upstream_url: str, controller_url: str | None = None
) -> ExecutorSettings:
    key = os.environ.get("G0_ADMISSION_KEY")
    placeholder = os.environ.get("G0_PROVIDER_TOKEN")
    if not key:
        raise ValueError("G0_ADMISSION_KEY is required")
    if not placeholder or not _PLACEHOLDER.fullmatch(placeholder):
        raise ValueError("G0_PROVIDER_TOKEN must be an OpenShell environment placeholder")
    if controller_url is not None and not os.environ.get("G0_LEDGER_TOKEN"):
        raise ValueError("G0_LEDGER_TOKEN is required when the controller is configured")
    controller_token = os.environ.get("G0_LEDGER_TOKEN") if controller_url is not None else None
    return ExecutorSettings(
        upstream_url=_validate_https_origin(upstream_url),
        admission_key=key.encode(),
        provider_placeholder=placeholder,
        controller_url=_validate_https_origin(controller_url) if controller_url else None,
        ledger_token=controller_token,
    )


def request_signature(key: bytes, method: str, path: str, body: bytes, expiry: int) -> str:
    """Build the explicitly test-only caller signature: expiry:hex-HMAC."""
    if not isinstance(expiry, int) or isinstance(expiry, bool):
        raise ValueError("expiry must be an integer")
    body_digest = hashlib.sha256(body).hexdigest()
    message = f"{method}\n{path}\n{body_digest}\n{expiry}".encode("ascii")
    return f"{expiry}:{hmac.new(key, message, hashlib.sha256).hexdigest()}"


def _verify_admission(
    settings: ExecutorSettings, method: str, path: str, body: bytes, header: str | None, now: float
) -> None:
    if not header or header.count(":") != 1:
        raise AdmissionError
    expiry_text, signature = header.split(":", 1)
    if not _EXPIRY.fullmatch(expiry_text) or not _SIGNATURE.fullmatch(signature):
        raise AdmissionError
    expiry = int(expiry_text)
    if expiry <= int(now):
        raise AdmissionError
    expected = request_signature(settings.admission_key, method, path, body, expiry).split(":", 1)[
        1
    ]
    if not hmac.compare_digest(expected, signature):
        raise AdmissionError


def _json_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _make_opener() -> Any:
    # This is the workload's ordinary trust configuration. The OpenShell-provided
    # SSL_CERT_FILE is honored by create_default_context; verification stays enabled.
    context = ssl.create_default_context()
    return urllib.request.build_opener(
        urllib.request.ProxyHandler(),
        _NoRedirect(),
        urllib.request.HTTPSHandler(context=context),
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _read_response(response: Any) -> bytes:
    with response:
        status = getattr(response, "status", None)
        if status != 200:
            raise UpstreamError
        body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise UpstreamError
    return body


def _post_json(opener: Any, url: str, payload: dict[str, Any], headers: dict[str, str]) -> bytes:
    request = urllib.request.Request(
        url,
        data=_json_bytes(payload),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        response = opener.open(request, timeout=10)
        return _read_response(response)
    except (urllib.error.URLError, TimeoutError, OSError, UpstreamError) as exc:
        raise UpstreamError from exc


def _call_controller(settings: ExecutorSettings, opener: Any) -> None:
    if settings.controller_url is None:
        return
    if not settings.ledger_token:
        raise UpstreamError
    body = _post_json(
        opener,
        settings.controller_url + LEDGER_PATH,
        {"request_id": "g0-fixed", "operation": "admit"},
        {LEDGER_HEADER: f"Bearer {settings.ledger_token}"},
    )
    # The test controller need only return a small acknowledgement object; discard it.
    try:
        ack = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpstreamError from exc
    if type(ack) is not dict or ack.get("accepted") is not True:
        raise UpstreamError


def _call_upstream(settings: ExecutorSettings, opener: Any) -> dict[str, Any]:
    payload = {
        "model": "g0-test-model",
        "messages": [{"role": "user", "content": "g0-marker"}],
        "stream": False,
    }
    body = _post_json(
        opener,
        settings.upstream_url + UPSTREAM_PATH,
        payload,
        {"Authorization": f"Bearer {settings.provider_placeholder}"},
    )
    try:
        result = json.loads(body)
        usage = result["usage"]
        numbers = {
            name: usage[name] for name in ("prompt_tokens", "completion_tokens", "total_tokens")
        }
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise UpstreamError from exc
    if any(type(value) is not int or value < 0 for value in numbers.values()):
        raise UpstreamError
    return {"marker": "g0-upstream-reached", "usage": numbers}


def _parse_request(body: bytes) -> bool:
    def no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        payload = json.loads(body, object_pairs_hook=no_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return False
    return type(payload) is dict and payload == {"request_id": "g0-fixed", "input": "g0-marker"}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: Any) -> None:
        # Do not retain attacker-controlled paths, headers, or body data in logs.
        return

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(5)

    def do_POST(self) -> None:
        if self.path != REQUEST_PATH:
            self._reply(404, {"error": "not_found"})
            return
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not re.fullmatch(r"(?:0|[1-9][0-9]*)", lengths[0]):
            self._reply(400, {"error": "invalid_request"})
            return
        length = int(lengths[0])
        if length > MAX_REQUEST_BYTES:
            self._reply(413, {"error": "request_too_large"})
            return
        try:
            body = self.rfile.read(length)
        except OSError:
            self._reply(400, {"error": "invalid_request"})
            return
        if len(body) != length:
            self._reply(400, {"error": "invalid_request"})
            return
        try:
            _verify_admission(
                self.server.settings,
                self.command,
                self.path,
                body,
                self.headers.get(ADMISSION_HEADER),
                self.server.clock(),
            )
        except AdmissionError:
            self._reply(401, {"error": "unauthorized"})
            return
        if not _parse_request(body):
            self._reply(400, {"error": "invalid_request"})
            return
        try:
            _call_controller(self.server.settings, self.server.opener)
            result = _call_upstream(self.server.settings, self.server.opener)
        except UpstreamError:
            self._reply(502, {"error": "upstream_failure"})
            return
        self._reply(200, result)

    def do_GET(self) -> None:
        self._reply(405, {"error": "method_not_allowed"})

    do_PUT = do_GET
    do_PATCH = do_GET
    do_DELETE = do_GET

    def _reply(self, status: int, payload: dict[str, Any]) -> None:
        body = _json_bytes(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.close_connection = True
        self.end_headers()
        with contextlib.suppress(OSError):
            self.wfile.write(body)


class ExecutorServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        settings: ExecutorSettings,
        *,
        host: str = "127.0.0.1",
        port: int = 8765,
        opener: Any | None = None,
        clock: Callable[[], float] = time.time,
    ):
        self.settings = settings
        self.opener = opener if opener is not None else _make_opener()
        self.clock = clock
        super().__init__((host, port), _Handler)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream-url", required=True)
    parser.add_argument("--controller-url")
    args = parser.parse_args()
    try:
        settings = settings_from_environment(args.upstream_url, args.controller_url)
    except ValueError as exc:
        parser.error(str(exc))
    with ExecutorServer(settings) as server:
        # Keep startup output independent of endpoints and credentials.
        print("G0 test executor listening on 127.0.0.1:8765", flush=True)
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
