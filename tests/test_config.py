"""Operator configuration: one process settings object, explicit TLS and key sources."""

import pytest
from pydantic import ValidationError

from infosec_harness import api, config
from infosec_harness.config import FileSettings, Settings
from infosec_harness.contracts import GENERATION


def test_generation_names_the_task_queue_and_run_prefix():
    assert GENERATION == "v11"
    assert Settings().task_queue == "investigate-v11"
    assert api.PREFIX == "investigate-v11-"


def test_settings_are_read_once_and_bind_once(tmp_path, monkeypatch):
    path = tmp_path / "settings.json"
    path.write_text('{"model_name": "from-file"}')
    config.reset_settings()
    bound = config.use_settings_file(path)
    assert config.get_settings() is bound and bound.model_name == "from-file"
    with pytest.raises(RuntimeError, match=f"refusing to rebind them to {path}"):
        config.use_settings_file(path)
    config.reset_settings()
    monkeypatch.setenv("HARNESS_MODEL_NAME", "from-env")
    first = config.get_settings()
    assert first.model_name == "from-env" and config.get_settings() is first
    with pytest.raises(RuntimeError, match="already in use"):
        config.use_settings_file(path)
    assert config.get_settings() is first


def test_file_settings_ignore_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("HARNESS_LOG_LEVEL", "DEBUG")
    assert FileSettings.model_validate_json("{}").log_level == "INFO"
    assert Settings().log_level == "DEBUG"
    with pytest.raises(ValidationError):
        Settings(log_level="verbose")


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"temporal_tls": True, "temporal_tls_client_cert": "c.pem"}, "configured together"),
        ({"temporal_tls": True, "temporal_tls_client_key": "k.pem"}, "configured together"),
        ({"temporal_tls_ca_file": "ca.pem"}, "require temporal_tls=true"),
        ({"temporal_tls_server_name": "temporal.example"}, "require temporal_tls=true"),
        ({"temporal_api_key": "a", "temporal_api_key_file": "key"}, "one Temporal API key source"),
    ],
)
def test_temporal_connection_settings_fail_closed(fields, message):
    with pytest.raises(ValidationError, match=message):
        Settings(**fields)


def test_temporal_tls_and_key_file_options(tmp_path):
    ca, key_file, empty = tmp_path / "ca.pem", tmp_path / "key", tmp_path / "empty"
    ca.write_bytes(b"ca")
    key_file.write_text("key-from-file\n")
    empty.write_text("\n")
    assert api.temporal_connection_options(Settings()) == {}
    assert api.temporal_connection_options(Settings(temporal_tls=True)) == {"tls": True}
    options = api.temporal_connection_options(
        Settings(temporal_tls=True, temporal_tls_ca_file=ca, temporal_api_key_file=key_file)
    )
    assert options["tls"].server_root_ca_cert == b"ca" and options["tls"].client_cert is None
    assert options["api_key"] == "key-from-file"
    with pytest.raises(ValueError, match="empty"):
        api.temporal_connection_options(Settings(temporal_api_key_file=empty))
