"""Pure checks for real-provider qualification manifests, sources, configuration and baselines.

Nothing in this module contacts a provider, Temporal or a database. Every rule raises its own
message so an operator (and a regression) can tell exactly which clause failed.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

ROOT = Path(__file__).resolve().parents[4]
AGENTS_DIR = Path(__file__).resolve().parents[2] / "agents"

# One frozen evaluation case per registered agent.
CASES = {
    "intake": "sql-injection-from-prose", "recon": "python-pytest",
    "env-planner": "python-pip-pytest", "build-repair": "missing-system-library",
    "partial-build": "narrow-after-repeated-full-build-failure", "context": "sqli-vulnerable",
    "probe-planner": "sqli-can-inspect-the-result", "probe-author": "sqli-marker-oracle",
    "probe-diagnosis": "positive", "probe-repair": "asserts-before-reaching-the-sink",
    "verdict": "valid_positive_sqli",
}
PHASES = ("direct", "native-local", "native-temporal")
# CLI selector -> declared manifest phase, and the runner selector of each declared phase.
PHASE_SELECTORS = {"direct": "direct", "local": "native-local", "temporal": "native-temporal"}
SELECTOR_FOR_PHASE = {phase: selector for selector, phase in PHASE_SELECTORS.items()}
WORKFLOW_NAME = "BrokerRealProviderQualificationWorkflow"
ROOT_PREFIX = "broker-real-"

# Model fields that must match between the direct baseline and the native candidate.
COMPARISON_MODEL_FIELDS = ("effective_settings", "provider_output_floor", "transport_retries",
    "resolved_model", "backend_kind", "pricing_status", "pricing_table", "endpoint")
TRANSPORT_FIELDS = ("durable", "broker_contract", "capability_profile", "credential_reference")


class FrozenDataset(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    case: str
    path: str
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    version: str


class FrozenPricing(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    basis: str
    input_per_mtok: float
    output_per_mtok: float


class RealProviderManifest(BaseModel):
    """An operator-reviewed, immutable qualification scope. Endpoint and model have no default."""

    model_config = ConfigDict(extra="forbid", strict=True)
    version: Literal[1] = 1
    endpoint: str = Field(min_length=1)
    model: str = Field(min_length=1)
    direct_models_config: str
    broker_models_config: str
    broker_config: str
    database_env_file: str
    worker_hmac_file: str
    worker_hmac_env: str = Field(pattern=r"^[A-Z][A-Z0-9_]+$")
    temporal_address: str = "127.0.0.1:7365"
    report_directory: str
    cases: dict[str, str] = Field(default_factory=lambda: dict(CASES))
    case_digests: dict[str, str] = Field(default_factory=dict)
    frozen_at: str
    source_commit: str = Field(pattern=r"^[a-f0-9]{40}$")
    datasets: dict[str, FrozenDataset]
    pricing: FrozenPricing
    hypothesis: str
    phases: list[str]
    maximum_pilot_agent_trials: int
    runtime_bounds: str
    abort_conditions: list[str]
    acceptance: str
    rollout: str
    max_concurrency: Literal[1] = 1
    root_duration_seconds: int = Field(default=7200, gt=0, le=7200)

    @model_validator(mode="after")
    def frozen_scope(self):
        if self.cases != CASES:
            raise ValueError("Manifest cases must be exactly one frozen case per registered agent")
        if set(self.datasets) != set(CASES):
            raise ValueError("Frozen datasets must cover every case")
        if self.case_digests and set(self.case_digests) != set(CASES):
            raise ValueError("Case digests must cover every frozen case")
        if not self.phases:
            raise ValueError("Manifest must declare at least one phase")
        if [phase for phase in PHASES if phase in self.phases] != self.phases:
            raise ValueError("Phases must be an ordered, duplicate-free subset of "
                             "direct, native-local, native-temporal")
        if self.maximum_pilot_agent_trials != len(CASES) * len(self.phases):
            raise ValueError("Maximum agent trials must equal one trial per case per phase")
        if self.pricing.input_per_mtok != 0:
            raise ValueError("Qualification input price must be zero")
        if self.pricing.output_per_mtok != 0:
            raise ValueError("Qualification output price must be zero")
        return self


def sha256_file(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def selected_phases(manifest: RealProviderManifest, phase: str) -> tuple[str, ...]:
    """Map a CLI selector to the declared manifest phases it authorizes."""
    if phase == "validate":
        return ()
    if phase == "all":
        return tuple(manifest.phases)
    if phase not in PHASE_SELECTORS:
        raise ValueError("Unknown qualification phase")
    declared = PHASE_SELECTORS[phase]
    if declared not in manifest.phases:
        raise ValueError(f"Phase {declared} is not declared by the manifest")
    return (declared,)


def claim_phase(report_directory: Path, manifest_sha256: str, phase: str) -> None:
    """A frozen manifest may dispatch each phase once, even if that attempt later fails."""
    if phase not in PHASES:
        raise ValueError("Unknown qualification phase")
    directory = report_directory / "execution-claims"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(directory / f"{manifest_sha256}-{phase}.started",
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def git_observation() -> tuple[str, bool]:
    """Observe the checkout HEAD and tracked-file cleanliness; never modifies Git."""
    def git(*args):
        return subprocess.run(["git", *args], cwd=ROOT, check=True,
            capture_output=True, text=True, timeout=10).stdout

    return git("rev-parse", "HEAD").strip(), not git("status", "--porcelain", "--untracked-files=no")


def verify_source(manifest: RealProviderManifest) -> None:
    head, clean = git_observation()
    if head != manifest.source_commit:
        raise ValueError("Manifest source commit differs from the checkout HEAD")
    if not clean:
        raise ValueError("Checkout has uncommitted tracked changes")


def _load_yaml(path: str):
    import yaml

    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise ValueError(f"Candidate configuration {path} must be a regular file")
    return yaml.safe_load(source.read_text())


def _same_endpoint(left: str | None, right: str) -> bool:
    return left is not None and left.rstrip("/") == right.rstrip("/")


def verify_configuration(manifest: RealProviderManifest) -> dict[str, dict[str, str]]:
    """Resolve every case's direct and native route from the frozen files; no client is built."""
    from infosec_harness.agents.models import ModelsConfig
    from infosec_harness.agents.registry import BINDINGS, load_spec
    from infosec_harness.inference.catalog.profiles import BrokerConfig

    configs = {"direct": ModelsConfig.model_validate(_load_yaml(manifest.direct_models_config)),
               "native": ModelsConfig.model_validate(_load_yaml(manifest.broker_models_config))}
    transports = {"direct": "direct", "native": "brokered"}
    catalog = BrokerConfig.model_validate(_load_yaml(manifest.broker_config)).require_agents(BINDINGS)
    if not catalog.enabled:
        raise ValueError("Broker catalog must be enabled for native phases")
    routes = {}
    for agent in manifest.cases:
        tier = load_spec(agent).model or "sonnet"
        names = {}
        for label, config in configs.items():
            # Ambient HARNESS_MODEL_BACKEND is deliberately ignored: only frozen files route.
            name = config.default_backend
            backend = config.backends.get(name)
            if backend is None:
                raise ValueError(f"{label} configuration has no backend {name!r} for {agent}")
            if backend.transport != transports[label]:
                raise ValueError(f"{label} backend {name!r} must use {transports[label]} transport")
            if not _same_endpoint(backend.base_url, manifest.endpoint):
                raise ValueError(f"{label} backend {name!r} endpoint differs from the manifest endpoint")
            try:
                model = config.model_id(tier, name)
            except KeyError:
                # An uncatalogued tier is a manifest that does not validate, not a crash.
                raise ValueError(f"{label} backend {name!r} has no catalogued model for {agent}'s "
                                 f"tier {tier!r}") from None
            if model != manifest.model:
                raise ValueError(f"{label} backend {name!r} resolves {agent} to a model other than "
                                 "the manifest model")
            names[label] = name
        if names["direct"] != names["native"]:
            raise ValueError(f"Direct and native routes for {agent} must use the same backend name")
        profile_name, profile = catalog.profile_for_agent(agent)
        if profile.backend_name != names["native"]:
            raise ValueError(f"Broker profile {profile_name!r} does not admit backend "
                             f"{names['native']!r} for {agent}")
        if not _same_endpoint(profile.endpoint, manifest.endpoint):
            raise ValueError(f"Broker profile {profile_name!r} endpoint differs from the manifest endpoint")
        routes[agent] = {"backend": names["native"], "profile": profile_name}
    return routes


def _require_direct_baseline(baseline: dict, cases: dict[str, str],
                             case_digests: dict[str, str]) -> dict[str, dict]:
    """A passed direct report covering every frozen case once, with the named case contents."""
    rows = baseline.get("cases", [])
    if baseline.get("phase") != "direct":
        raise ValueError("Baseline report is not a direct phase report")
    if baseline.get("status") != "passed":
        raise ValueError("Baseline direct phase did not pass")
    if sorted(row.get("agent") for row in rows) != sorted(cases):
        raise ValueError("Baseline report must cover every frozen case exactly once")
    by_agent = {row["agent"]: row for row in rows}
    for agent, case_digest in case_digests.items():
        if by_agent[agent].get("case") != cases[agent]:
            raise ValueError(f"Baseline case for {agent} differs from the manifest")
        if by_agent[agent].get("case_digest") != case_digest:
            raise ValueError(f"Baseline case content for {agent} differs")
    return by_agent


def verify_baseline_report(manifest: RealProviderManifest, manifest_sha256: str,
                           report_path: Path, case_digests: dict[str, str]) -> None:
    """A native phase compares against a passed direct phase of the same frozen manifest."""
    frozen = report_path.parent / "manifest.json"
    if not frozen.is_file() or sha256_file(frozen) != manifest_sha256:
        raise ValueError("Baseline report was not produced by this frozen manifest")
    _require_direct_baseline(json.loads(report_path.read_bytes()), manifest.cases, case_digests)


def _pricing_catalog_difference(previous: object, current: object) -> dict | None:
    """Native catalogs add profile bytes; only the catalog bytes component may differ."""
    if not isinstance(previous, str) or not isinstance(current, str):
        return None
    before, after = previous.split(";"), current.split(";")
    if (len(before) == len(after) == 4 and before[1].startswith("models:")
            and after[1].startswith("models:") and before[0::2] == after[0::2]
            and before[3] == after[3]):
        return {"direct": previous, "native": current,
                "difference": "models catalog bytes; exact provider and custom price inputs matched"}
    return None


def compare_baseline(agent: str, config: dict, case_digest: str, *,
                     cases: dict[str, str] = CASES) -> dict:
    """Require the native candidate to match its direct baseline except for transport fields."""
    path = os.environ.get("HARNESS_REAL_PROVIDER_BASELINE")
    if not path:
        raise ValueError("Native qualification requires a completed direct baseline")
    baseline = json.loads(Path(path).read_text())
    old = _require_direct_baseline(baseline, cases, {agent: case_digest})[agent]["config"]
    if old["model"].get("capability_profile") != config["model"].get("capability_profile"):
        raise ValueError("Baseline capability profile differs")
    if old["budget"] != config["budget"]:
        raise ValueError("Authored agent safety budget differs from baseline")
    pricing_provenance = None
    for name in COMPARISON_MODEL_FIELDS:
        previous_value, current_value = old["model"].get(name), config["model"].get(name)
        if previous_value == current_value:
            continue
        if name == "pricing_table":
            pricing_provenance = _pricing_catalog_difference(previous_value, current_value)
            if pricing_provenance is not None:
                continue
            raise ValueError("Baseline pricing differs")
        raise ValueError(f"Baseline model field {name} differs")
    return {"status": "passed", "baseline_sha256": sha256_file(path),
            "matched_model_fields": list(COMPARISON_MODEL_FIELDS), "authored_budget": "matched",
            "pricing_catalog_provenance": pricing_provenance,
            "intentional_transport_fields": {name: config["model"].get(name) for name in TRANSPORT_FIELDS}}
