"""Service connection options shared by API/CLI and workers; never workflow history."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from infosec_harness.settings import Settings


def temporal_connection_options(settings: Settings) -> dict[str, Any]:
    from temporalio.service import TLSConfig

    options: dict[str, Any] = {}
    if settings.temporal_tls:
        if any((settings.temporal_tls_ca_file, settings.temporal_tls_client_cert,
                settings.temporal_tls_server_name)):
            options["tls"] = TLSConfig(
                server_root_ca_cert=settings.temporal_tls_ca_file.read_bytes() if settings.temporal_tls_ca_file else None,
                client_cert=settings.temporal_tls_client_cert.read_bytes() if settings.temporal_tls_client_cert else None,
                client_private_key=settings.temporal_tls_client_key.read_bytes() if settings.temporal_tls_client_key else None,
                domain=settings.temporal_tls_server_name,
            )
        else:
            options["tls"] = True
    key = settings.temporal_api_key
    if settings.temporal_api_key_file:
        key = settings.temporal_api_key_file.read_text().strip()
        if not key:
            raise ValueError("Temporal API key file is empty")
    if key:
        options["api_key"] = key
    return options
