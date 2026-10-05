"""Operator configuration. No model-selected permissions or automatic runtime fallback."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from infosec_harness.models import Limits


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="HARNESS_", env_nested_delimiter="__", extra="ignore"
    )

    temporal_address: str = "localhost:7233"
    temporal_namespace: str = "default"
    task_queue: str = "investigate-v9"
    temporal_tls: bool = False
    temporal_tls_ca_file: Path | None = None
    temporal_tls_client_cert: Path | None = None
    temporal_tls_client_key: Path | None = None
    temporal_tls_server_name: str | None = None
    temporal_api_key: str | None = Field(default=None, repr=False)
    temporal_api_key_file: Path | None = None
    openshell_config: Path = Path(".harness/openshell/runtime.json")
    workspace_dir: Path = Path(".harness/workspace")
    local_repo_roots: list[Path] = Field(default_factory=list)
    model_name: str = "Qwen3.6-35B-A3B-NVFP4"
    model_provider: Literal["openai", "bedrock"] = "openai"
    model_base_url: str | None = None
    model_region: str = "us-east-1"
    limits: Limits = Field(default_factory=Limits)

    @model_validator(mode="after")
    def valid_tls(self):
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


@lru_cache
def get_settings() -> Settings:
    return Settings()
