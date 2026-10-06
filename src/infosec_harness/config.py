"""Operator configuration. No model-selected permissions or automatic runtime fallback."""

from pathlib import Path
from typing import Literal, Self

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

from infosec_harness.contracts import GENERATION, Limits


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="HARNESS_", env_nested_delimiter="__", extra="ignore"
    )

    temporal_address: str = "localhost:7233"
    temporal_namespace: str = "default"
    task_queue: str = f"investigate-{GENERATION}"
    temporal_tls: bool = False
    temporal_tls_ca_file: Path | None = None
    temporal_tls_client_cert: Path | None = None
    temporal_tls_client_key: Path | None = None
    temporal_tls_server_name: str | None = None
    temporal_api_key: str | None = Field(default=None, repr=False)
    temporal_api_key_file: Path | None = None
    openshell_config: Path = Path(".harness/openshell/runtime.json")
    workspace_dir: Path = Path(".harness/workspace")
    # Qualification and evaluation reports; the API lists and serves them read-only.
    reports_dir: Path = Path(".harness/reports")
    local_repo_roots: list[Path] = Field(default_factory=list)
    # Operator-owned read-only command whose last stdout line is JSON with `retained`,
    # `quota` and `read_only: true`; `harness eval` refuses to start without headroom.
    native_occupancy_command: list[str] = Field(default_factory=list)
    model_name: str = "Qwen3.6-35B-A3B-NVFP4"
    model_provider: Literal["openai", "bedrock"] = "openai"
    model_base_url: str | None = None
    model_region: str = "us-east-1"
    limits: Limits = Field(default_factory=Limits)
    # Level of the one stderr handler that `harness worker`, `api` and `eval` install.
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    @model_validator(mode="after")
    def valid_tls(self) -> Self:
        if bool(self.temporal_tls_client_cert) != bool(self.temporal_tls_client_key):
            raise ValueError("Temporal client certificate and key must be configured together")
        if not self.temporal_tls and any(
            (
                self.temporal_tls_ca_file,
                self.temporal_tls_client_cert,
                self.temporal_tls_server_name,
            )
        ):
            raise ValueError("Temporal TLS files require temporal_tls=true")
        if self.temporal_api_key and self.temporal_api_key_file:
            raise ValueError("Configure one Temporal API key source")
        return self


class FileSettings(Settings):
    """One explicit JSON document: no environment, dotenv or secret sources; no unknown keys."""

    model_config = SettingsConfigDict(extra="forbid")

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        del settings_cls, env_settings, dotenv_settings, file_secret_settings
        return (init_settings,)


# The one process configuration. It is not frozen yet: tests still assign fields on it
# (tests/evals, tests/workflows); freezing it is a separate change with those tests.
_settings: Settings | None = None


def get_settings() -> Settings:
    """The bound settings file, else the environment as read on first use."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def use_settings_file(path: Path) -> Settings:
    """Bind one frozen configuration file. Environment variables are not merged into it.

    Refuses once settings exist, so one process never mixes two configurations.
    """
    global _settings
    if _settings is not None:
        raise RuntimeError(
            f"Settings are already in use; refusing to rebind them to {path}. "
            "Pass --settings once, before anything reads the configuration."
        )
    _settings = FileSettings.model_validate_json(path.read_bytes())
    return _settings


def reset_settings() -> None:
    """Forget the process settings so the next read starts fresh. Tests only."""
    global _settings
    _settings = None

