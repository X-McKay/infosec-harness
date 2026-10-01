"""Bounded JSON channels with explicit TLS; no payload/header logging."""

from __future__ import annotations

import asyncio
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

import httpcore
import httpx

from .diagnostics import report_transport_failure
from .protocol import MAX_BODY_BYTES, BrokerError, canonical_bytes
from .timing import SERVER_TIMEOUT_S


def https_origin(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise BrokerError("policy", "A fixed HTTPS origin is required")
    _ = parsed.port
    return value.rstrip("/")


def parse_body(body: bytes) -> dict[str, Any]:
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        if not body or len(body) > MAX_BODY_BYTES:
            raise ValueError
        value = json.loads(
            body,
            object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
        if not isinstance(value, dict) or canonical_bytes(value) != body:
            raise ValueError
        return value
    except (ValueError, TypeError, UnicodeDecodeError):
        raise BrokerError("identity", "Invalid canonical request") from None


class _GatewayBackend(httpcore.AsyncNetworkBackend):
    """Scope TCP routing to one gateway while preserving original TLS SNI."""

    def __init__(self, gateway_origin: str, service_domain: str):
        gateway = urlsplit(https_origin(gateway_origin))
        self.host, self.port = gateway.hostname, gateway.port or 443
        self.service_domain = service_domain
        self.backend = httpcore.AnyIOBackend()

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        if not host.endswith("." + self.service_domain) or port != self.port:
            raise BrokerError("policy")
        return await self.backend.connect_tcp(
            self.host,
            self.port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(self, *args, **kwargs):
        raise BrokerError("policy")

    async def sleep(self, seconds):
        await self.backend.sleep(seconds)


class _ResponseStream(httpx.AsyncByteStream):
    def __init__(self, stream):
        self.stream = stream

    async def __aiter__(self):
        async for chunk in self.stream:
            yield chunk

    async def aclose(self):
        await self.stream.aclose()


class _GatewayTransport(httpx.AsyncBaseTransport):
    def __init__(self, context, gateway_origin, service_domain):
        self.pool = httpcore.AsyncConnectionPool(
            ssl_context=context,
            retries=0,
            network_backend=_GatewayBackend(gateway_origin, service_domain),
        )

    async def handle_async_request(self, request):
        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        response = await self.pool.handle_async_request(core_request)
        return httpx.Response(
            response.status,
            headers=response.headers,
            stream=_ResponseStream(response.stream),
            extensions=response.extensions,
        )

    async def aclose(self):
        await self.pool.aclose()


class JsonChannel:
    def __init__(
        self,
        *,
        ca_file: str | None = None,
        cert: tuple[str, str] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        gateway_origin: str | None = None,
        service_domain: str | None = None,
    ):
        context = ssl.create_default_context(cafile=ca_file)
        if cert:
            context.load_cert_chain(*cert)
        self.context = context
        if (gateway_origin is None) != (service_domain is None) or (gateway_origin and transport):
            raise BrokerError("policy")
        self.transport = transport
        self.gateway_origin, self.service_domain = gateway_origin, service_domain

    async def post(self, url: str, body: bytes, headers: dict[str, str], *, timeout: float = 30):
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment:
            raise BrokerError("policy")
        try:
            async with (
                asyncio.timeout(timeout),
                httpx.AsyncClient(
                    verify=self.context,
                    trust_env=False,
                    follow_redirects=False,
                    transport=(
                        _GatewayTransport(self.context, self.gateway_origin, self.service_domain)
                        if self.gateway_origin
                        else self.transport
                    ),
                ) as client,
                client.stream(
                    "POST",
                    url,
                    content=body,
                    headers={"Content-Type": "application/json", **headers},
                    timeout=timeout,
                ) as response,
            ):
                result = bytearray()
                async for chunk in response.aiter_bytes():
                    result.extend(chunk)
                    if len(result) > MAX_BODY_BYTES:
                        raise BrokerError("invalid_response")
                value = parse_body(bytes(result))
                if response.status_code != 200:
                    code = value.get("error")
                    if code not in {
                        "auth",
                        "policy",
                        "identity",
                        "budget",
                        "expired",
                        "conflict",
                        "pending",
                        "completion_unknown",
                        "unavailable",
                        "invalid_response",
                    }:
                        code = "unavailable"
                    raise BrokerError(code)
                return value
        except (
            httpx.HTTPError,
            httpcore.NetworkError,
            httpcore.TimeoutException,
            httpcore.ProtocolError,
            ssl.SSLError,
            OSError,
            TimeoutError,
        ) as error:
            report_transport_failure("json_channel", error)
            raise BrokerError("unavailable") from None


def serve(
    core, *, host: str, port: int, tls: ssl.SSLContext | None, loopback_executor: bool = False
) -> None:
    if tls is None and not (loopback_executor and host == "127.0.0.1"):
        raise BrokerError("policy", "TLS is mandatory outside native loopback service")
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    slots = threading.BoundedSemaphore(32)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            future = None
            try:
                if (
                    self.headers.get("Transfer-Encoding")
                    or len(self.headers.get_all("Content-Length", [])) != 1
                ):
                    raise BrokerError("identity")
                if any(
                    len(self.headers.get_all(name, [])) > 1
                    for name in ("Authorization", "X-Harness-Admission")
                ):
                    raise BrokerError("auth")
                length = int(self.headers["Content-Length"])
                if length <= 0 or length > MAX_BODY_BYTES:
                    raise BrokerError("identity")
                body = self.rfile.read(length)
                if len(body) != length:
                    raise BrokerError("identity")
                headers = dict(self.headers)
                future = asyncio.run_coroutine_threadsafe(
                    core.handle(self.path, body, headers), loop
                )
                response = future.result(timeout=SERVER_TIMEOUT_S)
                status = 200
            except BrokerError as exc:
                response = {"error": exc.code}
                status = {
                    "auth": 401,
                    "policy": 403,
                    "identity": 400,
                    "conflict": 409,
                    "pending": 409,
                    "completion_unknown": 409,
                    "expired": 410,
                }.get(exc.code, 503)
            except TimeoutError as error:
                if future is not None and not future.done():
                    future.cancel()
                report_transport_failure("server", error)
                response, status = {"error": "unavailable"}, 503
            except Exception:
                response, status = {"error": "unavailable"}, 503
            encoded = canonical_bytes(response)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    class Server(ThreadingHTTPServer):
        def process_request(self, request, address):
            request.settimeout(10)
            if not slots.acquire(blocking=False):
                self.shutdown_request(request)
                return
            try:
                super().process_request(request, address)
            except BaseException:
                slots.release()
                raise

        def process_request_thread(self, request, address):
            wrapped = request
            try:
                # TLS handshakes and header parsing share the bounded connection slots.
                if tls is not None:
                    wrapped = tls.wrap_socket(request, server_side=True)
                super().process_request_thread(wrapped, address)
            except (OSError, ssl.SSLError):
                self.shutdown_request(wrapped)
            finally:
                slots.release()

    server = Server((host, port), Handler)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=5)


def server_tls(cert: str, key: str, *, client_ca: str | None = None) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    if client_ca:
        context.load_verify_locations(client_ca)
        context.verify_mode = ssl.CERT_REQUIRED
    return context
