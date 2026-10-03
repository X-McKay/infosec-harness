"""Local/hosted connector contracts; no hosted services or real credentials."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from infosec_harness.services import temporal_connection_options
from infosec_harness.settings import Settings, get_settings


def settings(**values):
    return Settings(_env_file=None, **values)


def test_local_temporal_uses_sdk_plaintext_defaults():
    assert temporal_connection_options(settings()) == {}


def test_cloud_temporal_api_key_requires_verified_tls():
    with pytest.raises(ValidationError, match="TLS must be enabled"):
        settings(temporal_api_key="synthetic-private-key")
    s = settings(temporal_tls=True, temporal_api_key="synthetic-private-key")
    assert temporal_connection_options(s) == {"tls": True, "api_key": "synthetic-private-key"}
    assert "synthetic-private-key" not in repr(s)


def test_temporal_mtls_and_custom_ca(tmp_path):
    ca, cert, key = [tmp_path / name for name in ("ca.pem", "cert.pem", "key.pem")]
    for path in (ca, cert, key):
        path.write_bytes(path.name.encode())
    s = settings(temporal_tls=True, temporal_tls_ca_file=ca, temporal_tls_client_cert=cert,
                 temporal_tls_client_key=key, temporal_tls_server_name="temporal.example.invalid")
    tls = temporal_connection_options(s)["tls"]
    assert tls.server_root_ca_cert == b"ca.pem"
    assert tls.client_cert == b"cert.pem" and tls.client_private_key == b"key.pem"
    assert tls.domain == "temporal.example.invalid"


@pytest.mark.parametrize("prefix", ["database", "temporal"])
def test_partial_client_certificate_pair_fails_closed(prefix):
    with pytest.raises(ValidationError, match="configured together"):
        settings(**{prefix + "_tls": True, prefix + "_tls_client_cert": "cert.pem"})
    with pytest.raises(ValidationError, match="TLS must be enabled"):
        settings(**{prefix + "_tls_ca_file": "ca.pem"})


def test_mounted_temporal_key_is_required_and_never_falls_back(tmp_path):
    key = tmp_path / "api-key"
    s = settings(temporal_tls=True, temporal_api_key_file=key)
    with pytest.raises(FileNotFoundError):
        temporal_connection_options(s)
    key.write_text("\n")
    with pytest.raises(ValueError, match="empty"):
        temporal_connection_options(s)
    key.write_text("synthetic-mounted-key\n")
    assert temporal_connection_options(s)["api_key"] == "synthetic-mounted-key"
    with pytest.raises(ValidationError, match="one Temporal API key source"):
        settings(temporal_tls=True, temporal_api_key="other", temporal_api_key_file=key)


async def test_shared_temporal_connector_preserves_namespace_and_plugin(monkeypatch):
    from infosec_harness.workflows import worker
    s = settings(temporal_address="hosted.example.invalid:7233", temporal_namespace="triage.account",
                 temporal_tls=True, temporal_api_key="synthetic")
    monkeypatch.setattr(worker, "get_settings", lambda: s)
    connect = AsyncMock()
    monkeypatch.setattr(worker.Client, "connect", connect)
    await worker.connect()
    args, kwargs = connect.call_args
    assert args == ("hosted.example.invalid:7233",)
    assert kwargs["namespace"] == "triage.account"
    assert kwargs["api_key"] == "synthetic" and kwargs["tls"] is True
    assert len(kwargs["plugins"]) == 1


def test_environment_file_switch_and_environment_precedence(tmp_path, monkeypatch):
    local, hosted = tmp_path / "local.env", tmp_path / "hosted.env"
    local.write_text("HARNESS_TEMPORAL_ADDRESS=localhost:7233\n")
    hosted.write_text("HARNESS_TEMPORAL_ADDRESS=hosted.example.invalid:7233\nHARNESS_TEMPORAL_TLS=true\n")
    monkeypatch.delenv("HARNESS_TEMPORAL_ADDRESS", raising=False)
    try:
        monkeypatch.setenv("HARNESS_ENV_FILE", str(local))
        get_settings.cache_clear()
        assert get_settings().temporal_address == "localhost:7233"
        monkeypatch.setenv("HARNESS_ENV_FILE", str(hosted))
        get_settings.cache_clear()
        assert get_settings().temporal_tls is True
        monkeypatch.setenv("HARNESS_TEMPORAL_ADDRESS", "override.example.invalid:7233")
        get_settings.cache_clear()
        assert get_settings().temporal_address == "override.example.invalid:7233"
        monkeypatch.setenv("HARNESS_ENV_FILE", str(tmp_path / "absent.env"))
        get_settings.cache_clear()
        with pytest.raises(ValueError, match="existing environment file"):
            get_settings()
    finally:
        get_settings.cache_clear()


def test_authenticated_telemetry_requires_https():
    with pytest.raises(ValidationError, match="HTTPS"):
        settings(otel_exporter_otlp_endpoint="http://collector:4318",
                 otel_exporter_otlp_headers={"Authorization": "synthetic-private-header"})
    s = settings(otel_exporter_otlp_endpoint="https://collector.example.invalid",
                 otel_exporter_otlp_headers={"Authorization": "synthetic-private-header"})
    assert "synthetic-private-header" not in repr(s)


def test_hosted_telemetry_passes_trust_auth_and_mtls_to_exporter(monkeypatch, tmp_path):
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.http import trace_exporter
    from opentelemetry.sdk import trace as sdk_trace
    from opentelemetry.sdk.trace import export
    from pydantic_ai.agent import Agent

    from infosec_harness import telemetry

    s = settings(otel_exporter_otlp_endpoint="https://collector.example.invalid/",
                 otel_exporter_otlp_headers={"Authorization": "synthetic"},
                 otel_exporter_otlp_ca_file=tmp_path / "ca.pem",
                 otel_exporter_otlp_client_cert=tmp_path / "client.pem",
                 otel_exporter_otlp_client_key=tmp_path / "client.key")
    observed = []
    class Provider:
        def __init__(self, **_):
            pass
        def add_span_processor(self, _):
            pass
    monkeypatch.setattr(telemetry, "get_settings", lambda: s)
    monkeypatch.setattr(sdk_trace, "TracerProvider", Provider)
    monkeypatch.setattr(export, "BatchSpanProcessor", lambda obj: obj)
    monkeypatch.setattr(trace, "set_tracer_provider", lambda _: None)
    monkeypatch.setattr(Agent, "instrument_all", lambda _: None)
    monkeypatch.setattr(trace_exporter, "OTLPSpanExporter", lambda **kw: observed.append(kw))
    telemetry.configure.cache_clear()
    try:
        assert telemetry.configure("test")
        assert observed == [{"endpoint": "https://collector.example.invalid/v1/traces",
            "headers": {"Authorization": "synthetic"}, "certificate_file": str(tmp_path / "ca.pem"),
            "client_certificate_file": str(tmp_path / "client.pem"), "client_key_file": str(tmp_path / "client.key")}]
    finally:
        telemetry.configure.cache_clear()
