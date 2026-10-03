"""Runtime configuration, read from the environment (``HARNESS_*``) or a ``.env`` file."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from infosec_harness.resources import (
    agents_dir,
    models_config,
    package_root,
    skills_dir,
    source_checkout,
)

# The repository root when this runs from a checkout, and the package directory otherwise.
# Kept for the tooling that reads reviewable *project* files -- risk assessments, the eval
# corpus, the system spec -- which are deliberately not packaged. Runtime resources go through
# `infosec_harness.resources` instead, because those must resolve inside an installed wheel
# where no repository exists at all. See that module for the distinction.
REPO_ROOT = source_checkout() or package_root()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HARNESS_", env_file=".env", extra="ignore", hide_input_in_errors=True)

    # Persistence
    database_url: str = Field(default="postgresql+asyncpg://harness:harness@localhost:5432/harness", repr=False)
    database_tls: bool = False
    database_tls_ca_file: Path | None = None
    database_tls_client_cert: Path | None = None
    database_tls_client_key: Path | None = None

    # Temporal
    temporal_address: str = "localhost:7233"
    temporal_namespace: str = "default"
    temporal_tls: bool = False
    temporal_tls_ca_file: Path | None = None
    temporal_tls_client_cert: Path | None = None
    temporal_tls_client_key: Path | None = None
    temporal_tls_server_name: str | None = None
    temporal_api_key: str = Field(default="", repr=False)
    temporal_api_key_file: Path | None = None
    task_queue: str = "triage"

    # Artifacts: auto preserves endpoint-based local selection; explicit s3 also
    # supports AWS endpoints and workload identity without static credentials.
    artifact_backend: Literal["auto", "filesystem", "s3"] = "auto"
    s3_endpoint: str = ""
    s3_bucket: str = "harness-artifacts"
    s3_access_key: str = Field(default="", repr=False)
    s3_secret_key: str = Field(default="", repr=False)
    s3_session_token: str = Field(default="", repr=False)
    s3_ca_file: Path | None = None
    s3_addressing_style: Literal["auto", "path", "virtual"] = "auto"
    s3_create_bucket: bool = True
    s3_region: str = "us-east-1"

    # Shared scratch space for repo snapshots and build contexts.
    workspace_dir: Path = Path(".harness/workspace")

    # Local exports are separate from snapshots/build contexts and committed baselines.
    reports_dir: Path = Path(".harness/reports")

    # Agents and models
    # Packaged with the code (agent-playbook 02, Build and packaging), not read from the
    # working directory: an installed wheel has no repository root to look beside.
    agents_dir: Path = Field(default_factory=agents_dir)
    skills_dir: Path = Field(default_factory=skills_dir)
    models_config: Path = Field(default_factory=models_config)
    # ``live`` resolves model tiers through config/models.yaml; ``stub`` uses
    # deterministic in-process models (tests, offline demos, CI).
    model_mode: Literal["live", "stub"] = "live"
    # Opt-in operator-owned catalog. Direct mode never loads or contacts it.
    broker_config: Path | None = None

    # Sandbox
    sandbox_runtime: str = "runsc"  # gVisor; set to "runc" only for local development without gVisor
    sandbox_probe_timeout_s: int = 300
    # Ceiling on one agent run outside Temporal. A hung provider request has no natural
    # end: the client's own retries never fire because nothing failed, so a run can sit
    # forever. Under Temporal the activity's start_to_close_timeout does this instead.
    agent_run_timeout_s: int = 600
    sandbox_build_timeout_s: int = 1800
    sandbox_memory: str = "2g"
    sandbox_cpus: str = "2"
    sandbox_pids_limit: int = 512
    sandbox_read_only_root: bool = True  # read-only root fs; the probe workdir is a tmpfs (D2)
    # Fail closed: refuse to build/probe when the gVisor runtime is unavailable. Set true
    # only for local development on a host without runsc (weaker isolation).
    allow_insecure_runtime: bool = False
    # Build isolation (D2): a dedicated buildx builder whose buildkit runs under the sandbox
    # runtime, so untrusted install scripts are gVisor-contained like probes.
    buildx_builder: str = "harness-gvisor"
    use_buildx: bool = True
    # Build egress allowlist (D14): the egress proxy the build is pinned to, and the base
    # ecosystem registries allowed in addition to whatever the repo declares.
    build_egress_proxy: str = ""  # e.g. http://egress-proxy:3128; empty = no proxy wired
    # Static IPv4 of that proxy on the internal builder network. gVisor cannot use Docker's
    # embedded DNS on an Internal=true bridge, so secure builders use and verify the numeric
    # address for both controller pulls and Dockerfile RUN steps.
    build_egress_host_ip: str = ""
    # Pre-created Docker network marked Internal=true, with only the allowlisting proxy attached
    # to an external network as well. Build RUN steps join this network, so direct proxy bypass
    # has no route. Empty fails closed outside the explicit insecure-development mode.
    build_egress_network: str = ""
    default_registry_allowlist: list[str] = [
        "pypi.org", "files.pythonhosted.org",           # pip
        "registry.npmjs.org",                            # npm
        "repo.maven.apache.org", "repo1.maven.org",      # maven central
        "www.cpan.org", "cpan.metacpan.org", "cpan.org", # cpan
        "deb.debian.org", "security.debian.org",         # apt (debian base images)
    ]
    # Base-image allowlist (registries an EnvironmentSpec.base_image may be pulled from).
    allowed_base_registries: list[str] = ["docker.io/library", "docker.io", "public.ecr.aws"]
    # Manual, quiesced-maintenance target. Automatic eviction is unsafe until prepared images
    # have durable leases spanning build, smoke, and every finding probe.
    image_cache_max: int = 50

    # Deployment safety ceilings; provisional until calibrated on representative batches.
    root_max_requests: int = Field(default=10000, gt=0)
    root_max_tokens: int = Field(default=100_000_000, gt=0)
    root_max_cost_usd: float = Field(default=100.0, gt=0)

    root_max_tool_calls: int = Field(default=50000, gt=0)
    root_max_agent_runs: int = Field(default=1000, gt=0)
    # Aggregate reserved workload seconds at the configured per-container resource caps.
    # This includes retried build/probe/smoke activities and agent sandbox-tool allowances.
    root_max_execution_seconds: int = Field(default=1_000_000, gt=0)
    root_max_elapsed_seconds: int = Field(default=28800, gt=0)

    # Budgets (D6)
    max_build_repairs: int = 6
    max_partial_build_attempts: int = 4
    max_probe_repairs: int = 3
    # Environment re-plans triggered by a probe-time discovery (see graph.triage
    # RepairEnvironment). Deliberately 1, not 3: this loop rebuilds an image, so it is the most
    # expensive edge in the graph, and a genuine missing dependency is nearly always fixed by
    # one install. A second attempt usually means the diagnosis was wrong, not the spec.
    max_environment_repairs: int = 1
    # Reuse an EnvironmentSpec that already built for this *shape* of repository
    # (persistence.recipes). A hit skips the planner and an uncertain build; a miss costs one
    # build attempt and falls back to the normal path, so the downside is bounded and the entry
    # is evicted the moment it stops working.
    recipe_cache_enabled: bool = True
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

    # Observability (D4). The resource attributes the agent-playbook §8 requires on every
    # span: service identity, environment, and the build the span came from.
    otel_exporter_otlp_endpoint: str = ""
    otel_exporter_otlp_headers: dict[str, str] = Field(default_factory=dict, repr=False)
    otel_exporter_otlp_ca_file: Path | None = None
    otel_exporter_otlp_client_cert: Path | None = None
    otel_exporter_otlp_client_key: Path | None = None
    service_name: str = "infosec-harness"
    environment: str = "local"
    # Set these in the image/deployment; they make a trace attributable to a build.
    git_commit_sha: str = ""
    worker_build_id: str = ""


    @model_validator(mode="after")
    def validate_service_security(self) -> Settings:
        for prefix in ("database", "temporal"):
            cert = getattr(self, prefix + "_tls_client_cert")
            key = getattr(self, prefix + "_tls_client_key")
            if bool(cert) != bool(key):
                raise ValueError(prefix + " TLS client certificate and key must be configured together")
            configured = cert or getattr(self, prefix + "_tls_ca_file")
            if prefix == "temporal":
                configured = configured or self.temporal_tls_server_name or self.temporal_api_key or self.temporal_api_key_file
            if configured and not getattr(self, prefix + "_tls"):
                raise ValueError(prefix + " TLS must be enabled for configured authentication or certificates")
        if self.temporal_api_key and self.temporal_api_key_file:
            raise ValueError("Configure one Temporal API key source")
        if bool(self.s3_access_key) != bool(self.s3_secret_key):
            raise ValueError("S3 access key and secret key must be configured together")
        if self.s3_session_token and not self.s3_access_key:
            raise ValueError("Explicit S3 session token requires the access and secret key pair")
        if self.artifact_backend == "filesystem" and self.s3_endpoint:
            raise ValueError("Filesystem artifacts cannot also configure an S3 endpoint")
        if bool(self.otel_exporter_otlp_client_cert) != bool(self.otel_exporter_otlp_client_key):
            raise ValueError("OTLP client certificate and key must be configured together")
        if (self.otel_exporter_otlp_headers or self.otel_exporter_otlp_client_cert) and not self.otel_exporter_otlp_endpoint.startswith("https://"):
            raise ValueError("Authenticated OTLP export requires an HTTPS endpoint")
        return self


@lru_cache
def get_settings() -> Settings:
    profile = os.environ.get("HARNESS_ENV_FILE")
    if profile is not None:
        if not profile or not Path(profile).is_file():
            raise ValueError("HARNESS_ENV_FILE must identify an existing environment file")
        return Settings(_env_file=profile)
    return Settings()
