"""Runtime configuration, read from the environment (``HARNESS_*``) or a ``.env`` file."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
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
    # Packaged with the code (agent-playbook 02, Build and packaging), not read from the
    # working directory: an installed wheel has no repository root to look beside.
    agents_dir: Path = Field(default_factory=agents_dir)
    skills_dir: Path = Field(default_factory=skills_dir)
    models_config: Path = Field(default_factory=models_config)
    # ``live`` resolves model tiers through config/models.yaml; ``stub`` uses
    # deterministic in-process models (tests, offline demos, CI).
    model_mode: Literal["live", "stub"] = "live"

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
    default_registry_allowlist: list[str] = [
        "pypi.org", "files.pythonhosted.org",           # pip
        "registry.npmjs.org",                            # npm
        "repo.maven.apache.org", "repo1.maven.org",      # maven central
        "www.cpan.org", "cpan.metacpan.org", "cpan.org", # cpan
        "deb.debian.org", "security.debian.org",         # apt (debian base images)
    ]
    # Base-image allowlist (registries an EnvironmentSpec.base_image may be pulled from).
    allowed_base_registries: list[str] = ["docker.io/library", "docker.io", "public.ecr.aws"]
    # Image garbage collection: keep at most N cached target images, evicting oldest.
    image_cache_max: int = 50

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
    service_name: str = "infosec-harness"
    environment: str = "local"
    # Set these in the image/deployment; they make a trace attributable to a build.
    git_commit_sha: str = ""
    worker_build_id: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
