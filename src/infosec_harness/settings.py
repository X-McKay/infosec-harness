"""Runtime configuration, read from the environment (``HARNESS_*``) or a ``.env`` file."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HARNESS_", env_file=".env", extra="ignore")

    # Persistence
    database_url: str = "postgresql+asyncpg://harness:harness@localhost:5432/harness"

    # Temporal
    temporal_address: str = "localhost:7233"
    temporal_namespace: str = "default"
    task_queue: str = "triage"
    sandbox_task_queue: str = "sandbox"

    # Artifacts (S3-compatible; MinIO locally). When ``s3_endpoint`` is empty the
    # filesystem store under ``workspace_dir/artifacts`` is used instead.
    s3_endpoint: str = ""
    s3_bucket: str = "harness-artifacts"
    s3_access_key: str = ""
    s3_secret_key: str = ""
    s3_region: str = "us-east-1"

    # Shared scratch space for repo snapshots and build contexts.
    workspace_dir: Path = Path(".harness/workspace")

    # Agents and models
    agents_dir: Path = REPO_ROOT / "agents"
    skills_dir: Path = REPO_ROOT / "skills"
    models_config: Path = REPO_ROOT / "config" / "models.yaml"
    # ``live`` resolves model tiers through config/models.yaml; ``stub`` uses
    # deterministic in-process models (tests, offline demos, CI).
    model_mode: Literal["live", "stub"] = "live"

    # Sandbox
    sandbox_runtime: str = "runsc"  # gVisor; set to "runc" only for local development without gVisor
    sandbox_probe_timeout_s: int = 300
    sandbox_build_timeout_s: int = 1800
    sandbox_memory: str = "2g"
    sandbox_cpus: str = "2"
    sandbox_pids_limit: int = 512

    # Budgets (D6)
    max_build_repairs: int = 6
    max_partial_build_attempts: int = 4
    max_probe_repairs: int = 3
    per_repo_concurrency: int = 4

    # Azure DevOps (D13: comment-only write-back)
    ado_org_url: str = ""
    ado_project: str = ""
    ado_pat: str = Field(default="", repr=False)
    ado_writeback_enabled: bool = False
    ado_field_map: dict[str, str] = {
        "repo_url": "Custom.Repository",
        "revision": "Custom.Revision",
        "file_path": "Custom.FilePath",
        "start_line": "Custom.StartLine",
        "cwe": "Custom.CWE",
        "severity": "Microsoft.VSTS.Common.Severity",
    }

    ui_base_url: str = "http://localhost:8080"

    # Observability (D4)
    otel_exporter_otlp_endpoint: str = ""
    service_name: str = "infosec-harness"


@lru_cache
def get_settings() -> Settings:
    return Settings()
