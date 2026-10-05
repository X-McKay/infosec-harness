"""Offline manifests and candidate configuration files for broker qualification runner tests."""
from __future__ import annotations

import hashlib
import subprocess
import sys
from contextlib import suppress
from pathlib import Path

import yaml

from infosec_harness.qualification.broker.validators import AGENTS_DIR, CASES, RealProviderManifest

ENDPOINT = "https://provider.test/v1"
MODEL = "qualification-model"
# Captured before any test monkeypatches the shared subprocess module.
_POPEN = subprocess.Popen
BOUNDS = {"max_requests": 5, "max_input_tokens": 50000, "max_output_tokens": 10000,
          "max_cost_usd": 0.5, "max_duration_seconds": 600.0}


def models_config(transport: str, *, endpoint: str = ENDPOINT, model: str = MODEL) -> dict:
    backend = {"kind": "openai_compatible", "transport": transport, "base_url": endpoint,
               "prices": {model: {"input_per_mtok": 0.0, "output_per_mtok": 0.0}}}
    return {"backends": {"gateway": backend}, "default_backend": "gateway",
            "model_catalog": {tier: {"gateway": model} for tier in ("sonnet", "opus", "haiku")}}


def broker_catalog(*, endpoint: str = ENDPOINT) -> dict:
    profile = {"backend_name": "gateway", "endpoint": endpoint, "provider_binding": "provider-v1",
               "provider_env": "QUALIFICATION_PROVIDER", "ledger_origin": "https://broker.test",
               "ledger_profile": "ledger-v1", "executor_image": "sha256:" + "1" * 64,
               "supervisor_image": "sha256:" + "2" * 64,
               "approved_policy": {"version": 1, "network_policies": {}}}
    return {"version": 1, "enabled": True,
            "controller": {"url": "https://broker.test", "hmac_env": "HARNESS_BROKER_WORKER_KEY",
                           "ca_file": "/etc/harness/broker-ca.pem"},
            "profiles": {"inference-only": profile}, "agent_profiles": dict.fromkeys(CASES, "inference-only"),
            "root_limits": BOUNDS, "agent_limits": dict.fromkeys(CASES, BOUNDS)}


def write_yaml(path: Path, value: dict) -> str:
    path.write_text(yaml.safe_dump(value))
    return str(path)


def manifest_values(tmp_path: Path, **overrides) -> dict:
    datasets = {}
    for agent, case in CASES.items():
        path = AGENTS_DIR / agent / "evals/dataset.yaml"
        datasets[agent] = {"path": str(path), "case": case, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                           "version": str(yaml.safe_load(path.read_text())["version"])}
    private = tmp_path / "database.env"
    private.write_text("HARNESS_DATABASE_URL=sqlite+aiosqlite:///:memory:\n")
    private.chmod(0o600)
    secret = tmp_path / "worker.key"
    secret.write_text("offline-test-key-never-in-workflow")
    secret.chmod(0o600)
    values = {
        "endpoint": ENDPOINT, "model": MODEL,
        "direct_models_config": write_yaml(tmp_path / "direct.yaml", models_config("direct")),
        "broker_models_config": write_yaml(tmp_path / "broker.yaml", models_config("brokered")),
        "broker_config": write_yaml(tmp_path / "catalog.yaml", broker_catalog()),
        "database_env_file": str(private), "worker_hmac_file": str(secret),
        "worker_hmac_env": "HARNESS_BROKER_WORKER_KEY", "report_directory": str(tmp_path),
        "datasets": datasets, "frozen_at": "2026-10-01", "source_commit": "0" * 40,
        "pricing": {"basis": "self-hosted", "input_per_mtok": 0.0, "output_per_mtok": 0.0},
        "hypothesis": "transport equivalence", "phases": ["direct", "native-local", "native-temporal"],
        "maximum_pilot_agent_trials": 33, "runtime_bounds": "unchanged", "abort_conditions": [],
        "acceptance": "existing scores unchanged", "rollout": "qualification only",
    }
    values.update(overrides)
    return values


def manifest(tmp_path: Path, **overrides) -> RealProviderManifest:
    return RealProviderManifest.model_validate(manifest_values(tmp_path, **overrides))


def sleeping_child(**options) -> subprocess.Popen:
    """A harmless owned child process standing in for a qualification worker."""
    return _POPEN([sys.executable, "-c", "import time; time.sleep(60)"], **options)


def reap(children: list[subprocess.Popen]) -> None:
    for child in children:
        if child.poll() is None:
            with suppress(ProcessLookupError):
                child.kill()
        child.wait(timeout=5)
