"""Real-provider pilot support: no model mocks, prompt markers, or native lifecycle shims."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
import uuid
from collections import Counter
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

ROOT = Path(__file__).resolve().parents[2]
CASES = {
    "intake": "sql-injection-from-prose", "recon": "python-pytest",
    "env-planner": "python-pip-pytest", "build-repair": "missing-system-library",
    "partial-build": "narrow-after-repeated-full-build-failure", "context": "sqli-vulnerable",
    "probe-planner": "sqli-can-inspect-the-result", "probe-author": "sqli-marker-oracle",
    "probe-diagnosis": "positive", "probe-repair": "asserts-before-reaching-the-sink",
    "verdict": "valid_positive_sqli",
}


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


class CorrectedPilotAmendment(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    original_manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    baseline_report_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    failed_report_file: str
    failed_report_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    retained_unknown_request_ids: list[str]
    original_trials: int
    original_started_trials: int
    additional_trials: int
    cumulative_authorized_trials: int
    reason: str

    @model_validator(mode="after")
    def finite_correction(self):
        if (self.original_manifest_sha256 != "b41fb7a2bd695825bd2eff8b613f052e8c1319ad35bd053997c1a58cc1a20745"
                or (self.original_trials, self.original_started_trials, self.additional_trials,
                    self.cumulative_authorized_trials) != (33, 15, 22, 37)
                or len(self.retained_unknown_request_ids) != 4
                or len(set(self.retained_unknown_request_ids)) != 4
                or any(len(identity) != 64 or any(c not in "0123456789abcdef" for c in identity)
                       for identity in self.retained_unknown_request_ids)
                or self.reason != "known SDK reasoning usage counter codec correction; no unknown resend"):
            raise ValueError("Corrected pilot must explicitly retain unknowns and authorize only22 fresh trials")
        return self


# Frozen focused-trial terminal authority; historical review anchors remain unchanged.
# New trials must retain this exact request union and every budget row.
REVIEW7_RETAINED_COMPLETED_COUNT: int | None = 989
REVIEW7_TERMINAL_SEAL_SHA256: str | None = "d383a402ad1029af60d05a9c33537d5bba925ba80c8bdf138e047ddde1915698"


class NativeRerunAmendment(BaseModel):
    review_version: Literal[1, 2, 3, 4, 5, 6, 7, 8] = 1
    strict_closed_output_tools: bool = Field(default=False, strict=True, exclude_if=lambda value: value is False)
    intake_enable_thinking: bool | None = Field(default=None, strict=True, exclude_if=lambda value: value is None)
    retained_local_report_file: str | None = Field(default=None, exclude_if=lambda value: value is None)
    retained_local_report_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$", exclude_if=lambda value: value is None)
    retained_local_manifest_file: str | None = Field(default=None, exclude_if=lambda value: value is None)
    retained_local_manifest_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$", exclude_if=lambda value: value is None)
    retained_unknown_count: int | None = None
    retained_completed_count: int | None = None
    model_config = ConfigDict(extra="forbid", strict=True)
    original_manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    baseline_report_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    prior_reports: dict[str, str]
    candidate_files: dict[str, str]
    native_config_file: str = Field(min_length=1)
    ledger_proof_file: str
    ledger_proof_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    cause_resolution_file: str
    cause_resolution_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    retained_unknown_request_ids: list[str]
    retained_completed_request_ids: list[str]
    retained_terminal_seal_file: str | None = Field(default=None, min_length=1, exclude_if=lambda value: value is None)
    retained_terminal_seal_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$", exclude_if=lambda value: value is None)
    additional_trials: int = 22
    additional_graph_trials: int = 1
    reason: str

    @model_validator(mode="after")
    def finite_rerun(self):
        identities = self.retained_unknown_request_ids + self.retained_completed_request_ids
        counts = (10, 3) if self.review_version == 1 else (self.retained_unknown_count, self.retained_completed_count)
        reason = ("reviewed native generation correction; retain all outcomes; no unknown resend" if self.review_version == 1
                  else "reviewed native transport correction; retain all outcomes; no unknown resend" if self.review_version == 2
                  else "reviewed native deadlines and closed-output shaping correction; retain all outcomes; no unknown resend" if self.review_version == 3
                  else "reviewed case-scoped Temporal preflight correction; retain passed Local evidence and all outcomes; no unknown resend" if self.review_version == 4
                  else "reviewed intake non-thinking and bounded reference repair; retain all outcomes; no unknown resend" if self.review_version == 5
                  else "reviewed serial tool calls and targeted output guidance; retain all outcomes; no unknown resend" if self.review_version == 6
                  else "reviewed JVM class guidance and build non-thinking; retain all outcomes; no unknown resend" if self.review_version == 7
                  else "reviewed parent-prepared workload seccomp; retain all outcomes; no unknown resend")
        if (self.review_version == 1 and (self.retained_unknown_count is not None or self.retained_completed_count is not None)
                or self.review_version in (2, 3, 4, 5, 6, 7, 8) and (any(value is None or value < 0 for value in counts) or counts[0] == 0)):
            raise ValueError("New review must declare retained outcome counts; historical review counts stay fixed")
        if (self.review_version < 3 and self.strict_closed_output_tools
                or self.review_version == 3 and (not self.strict_closed_output_tools or counts != (15, 80)
                    or len(self.prior_reports) != 12
                    or self.baseline_report_sha256 != "78eac315f11c52b8e3202b4d5cc595c57888d1107a2e5d2a4f63a6d404bd4ce5")):
            raise ValueError("Review3 must declare closed output shaping and retain15unknown/80saved twelve-report evidence")
        local_link = (self.retained_local_report_file, self.retained_local_report_sha256,
                      self.retained_local_manifest_file, self.retained_local_manifest_sha256)
        if (self.review_version < 4 and any(value is not None for value in local_link)
                or self.review_version == 4 and (not all(local_link) or not self.strict_closed_output_tools
                    or counts != (15, 120) or len(self.prior_reports) != 14
                    or self.baseline_report_sha256 != "78eac315f11c52b8e3202b4d5cc595c57888d1107a2e5d2a4f63a6d404bd4ce5")):
            raise ValueError("Review4 must pin passed Local evidence and retain15unknown/120saved fourteen-report evidence")
        if (self.review_version < 5 and self.intake_enable_thinking is not None
                or self.review_version == 5 and (self.intake_enable_thinking is not False
                    or not self.strict_closed_output_tools or counts != (15, 162)
                    or len(self.prior_reports) != 18 or any(value is not None for value in local_link)
                    or self.baseline_report_sha256 != "78eac315f11c52b8e3202b4d5cc595c57888d1107a2e5d2a4f63a6d404bd4ce5")):
            raise ValueError("Review5 must declare intake non-thinking and retain15unknown/162saved eighteen-report evidence")
        if self.review_version == 6 and (self.intake_enable_thinking is not False
                or not self.strict_closed_output_tools or counts != (15, 822)
                or any(value is not None for value in local_link)
                or self.baseline_report_sha256 != "78eac315f11c52b8e3202b4d5cc595c57888d1107a2e5d2a4f63a6d404bd4ce5"):
            raise ValueError("Review6 must retain the sealed837 outcomes and exact original baseline")
        if self.review_version == 7 and (REVIEW7_RETAINED_COMPLETED_COUNT is None
                or REVIEW7_TERMINAL_SEAL_SHA256 is None
                or self.intake_enable_thinking is not False or not self.strict_closed_output_tools
                or counts != (15, REVIEW7_RETAINED_COMPLETED_COUNT)
                or any(value is not None for value in local_link)
                or self.baseline_report_sha256 != "78eac315f11c52b8e3202b4d5cc595c57888d1107a2e5d2a4f63a6d404bd4ce5"):
            raise ValueError("Review7 requires frozen focused terminal counts and whole-record/budget retention")
        if (self.review_version < 8 and (self.retained_terminal_seal_sha256 is not None or self.retained_terminal_seal_file is not None)
                or self.review_version == 8 and (self.retained_terminal_seal_sha256 is None or self.retained_terminal_seal_file is None
                    or self.intake_enable_thinking is not False or not self.strict_closed_output_tools
                    or any(value is not None for value in local_link)
                    or self.baseline_report_sha256 != "78eac315f11c52b8e3202b4d5cc595c57888d1107a2e5d2a4f63a6d404bd4ce5")):
            raise ValueError("Review8 requires a fresh terminal seal and unchanged reviewed model controls")
        if (self.original_manifest_sha256 != "b41fb7a2bd695825bd2eff8b613f052e8c1319ad35bd053997c1a58cc1a20745"
                or self.additional_trials != (11 if self.review_version == 4 else 22) or self.additional_graph_trials != 1
                or (len(self.retained_unknown_request_ids), len(self.retained_completed_request_ids)) != counts
                or len(set(identities)) != sum(counts) or not self.prior_reports or len(self.candidate_files) != 3
                or any(len(x) != 64 or any(c not in "0123456789abcdef" for c in x) for x in identities + list(self.prior_reports.values()) + list(self.candidate_files.values()))
                or self.reason != reason):
            raise ValueError("Native rerun must retain all explicitly reviewed outcomes and its finite agent/graph scope")
        return self


def verify_native_rerun(amendment: NativeRerunAmendment) -> None:
    def read(path, expected):
        data = Path(path).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError("Rerun retained evidence differs")
        return json.loads(data)

    for path, expected in amendment.candidate_files.items():
        if hashlib.sha256(Path(path).read_bytes()).hexdigest() != expected:
            raise ValueError("Native rerun candidate file changed")
    observed = {"completion_unknown": set(), "completed": set()}
    for path, expected in amendment.prior_reports.items():
        report = read(path, expected)
        rows = report.get("cases", [report])
        for row in rows:
            for request in row.get("ledger", {}).get("requests", []):
                if request.get("state") in observed:
                    observed[request["state"]].add(request["request_id"])
    wanted = {"completion_unknown": set(amendment.retained_unknown_request_ids),
              "completed": set(amendment.retained_completed_request_ids)}
    if observed != wanted:
        raise ValueError("Rerun must retain the exact prior request union")
    proof = read(amendment.ledger_proof_file, amendment.ledger_proof_sha256)
    proof_keys = {"status", "unknown_request_ids", "completed_request_ids", "unknown_holds_retained"}
    if amendment.review_version == 6:
        proof_keys |= {"baseline_seal_sha256", "all837_records_and_budget_states_unchanged"}
        if (proof.get("baseline_seal_sha256") != "667beac3be8c8569df0c981a4ad24f35ccdf7ea77148f120a89346a7bb935981"
                or proof.get("all837_records_and_budget_states_unchanged") is not True):
            raise ValueError("Review6 requires authoritative preservation of every sealed record and budget state")
    if amendment.review_version == 7:
        proof_keys |= {"baseline_seal_sha256", "all_records_and_all_budget_states_unchanged"}
        if (REVIEW7_TERMINAL_SEAL_SHA256 is None
                or proof.get("baseline_seal_sha256") != REVIEW7_TERMINAL_SEAL_SHA256
                or proof.get("all_records_and_all_budget_states_unchanged") is not True):
            raise ValueError("Review7 requires authoritative full focused terminal record and ALL budget preservation")
    if amendment.review_version == 8:
        seal_path = Path(amendment.retained_terminal_seal_file)
        if not seal_path.is_file() or seal_path.is_symlink():
            raise ValueError("Review8 requires a regular nonsymlink current terminal seal")
        seal = read(str(seal_path), amendment.retained_terminal_seal_sha256)
        requests, states, budgets = (seal.get(name) for name in ("requests", "states", "ledgers"))
        if (seal.get("status") != "passed" or seal.get("active_lease_count") != 0
                or seal.get("native_sandbox_count") != 0
                or not all(isinstance(value, dict) and value for value in (requests, states, budgets))
                or set(requests) != set(states)
                or any(not isinstance(value, str) or len(value) != 64
                    or any(c not in "0123456789abcdef" for c in value)
                    for value in [*requests.values(), *budgets.values()])
                or any(state not in ("completed", "completion_unknown") for state in states.values())
                or {rid for rid, state in states.items() if state == "completion_unknown"} != wanted["completion_unknown"]
                or any(states.get(rid) != state for state, identities in wanted.items() for rid in identities)):
            raise ValueError("Review8 retained report union must be included in the authoritative whole-state seal")
        proof_keys |= {"baseline_seal_sha256", "all_records_and_all_budget_states_unchanged"}
        if (proof.get("baseline_seal_sha256") != amendment.retained_terminal_seal_sha256
                or proof.get("all_records_and_all_budget_states_unchanged") is not True):
            raise ValueError("Review8 requires authoritative current whole-record and ALL budget retention")
    if (set(proof) != proof_keys
            or proof["status"] != "passed" or proof["unknown_holds_retained"] is not True
            or not isinstance(proof["unknown_request_ids"], list) or not isinstance(proof["completed_request_ids"], list)
            or len(proof["unknown_request_ids"]) != len(amendment.retained_unknown_request_ids)
            or len(proof["completed_request_ids"]) != len(amendment.retained_completed_request_ids)
            or set(proof["unknown_request_ids"]) != wanted["completion_unknown"]
            or set(proof["completed_request_ids"]) != wanted["completed"]):
        raise ValueError("Authoritative retained ledger proof differs")
    if amendment.review_version == 4:
        verify_retained_local(amendment, read)
    cause = read(amendment.cause_resolution_file, amendment.cause_resolution_sha256)
    if (set(cause) != {"status", "reviewed", "boundary", "evidence_sha256"}
            or cause["status"] != "passed" or cause["reviewed"] is not True
            or cause["boundary"] != {1: "native-policy-generation", 2: "native-response-acknowledgement",
                3: "native-inference-deadlines-and-output-shaping",
                4: "native-temporal-case-budget-preflight",
                5: "native-intake-nonthinking-and-reference-repair",
                6: "native-serial-tools-and-targeted-output-guidance",
                7: "native-jvm-class-guidance-and-build-nonthinking",
                8: "native-parent-prepared-workload-seccomp"}[amendment.review_version]
            or not isinstance(cause["evidence_sha256"], str) or len(cause["evidence_sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in cause["evidence_sha256"])):
        raise ValueError("Reviewed native cause resolution is required")


def verify_review5_configuration(manifest: RealProviderManifest) -> dict:
    """Resolve every v5 operator contract locally; never create a provider client."""
    if not manifest.rerun or manifest.rerun.review_version not in (5, 6, 7, 8):
        return {}
    import yaml
    from pydantic_ai.agent.spec import AgentSpec

    from infosec_harness.agents.models import ModelsConfig
    from infosec_harness.inference.compat import _apply_max_tokens_floor
    from infosec_harness.inference.profiles import BrokerConfig

    nonthinking = ({"intake", "probe-diagnosis", "verdict", "build-repair"} if manifest.rerun.review_version == 7
        else {"intake", "probe-diagnosis", "verdict"} if manifest.rerun.review_version in (6, 8) else {"intake"})
    models = ModelsConfig.model_validate(yaml.safe_load(Path(manifest.broker_models_config).read_text()))
    catalog = BrokerConfig.model_validate(yaml.safe_load(Path(manifest.broker_config).read_text()))
    reviewed_build = manifest.rerun.review_version == 8
    expected_backends = {"gateway", "gateway-intake"} | ({"gateway-build-repair"} if reviewed_build else set())
    expected_agents = {agent: {"backend": "gateway-intake"} for agent in nonthinking}
    if reviewed_build:
        expected_agents["build-repair"] = {"backend": "gateway-build-repair"}
    if (models.default_backend != "gateway" or set(models.backends) != expected_backends
            or models.agents != expected_agents):
        raise ValueError("Review5 requires the exact isolated intake backend routing")
    base, intake = models.backends["gateway"], models.backends["gateway-intake"]
    if (base.enable_thinking is not None or intake.enable_thinking is not False
            or base.model_dump(mode="json", exclude={"enable_thinking"})
                != intake.model_dump(mode="json", exclude={"enable_thinking"})
            or base.transport != "brokered" or base.kind != "openai_compatible"
            or base.base_url != manifest.endpoint or not base.strict_closed_output_tools):
        raise ValueError("Review5 intake backend must be an exact clone except thinking control")
    if any(mapping.get("gateway-intake") != manifest.model or mapping.get("gateway") != manifest.model
           for mapping in models.model_catalog.values()):
        raise ValueError("Review5 model aliases must preserve the exact provider model")
    if reviewed_build:
        build = models.backends["gateway-build-repair"]
        if (base.thinking_token_budget is not None or intake.thinking_token_budget is not None
                or build.enable_thinking is not None or build.thinking_token_budget != 4000
                or build.model_dump(mode="json", exclude={"thinking_token_budget"})
                    != base.model_dump(mode="json", exclude={"thinking_token_budget"})
                or any(mapping.get("gateway-build-repair") != manifest.model
                    for mapping in models.model_catalog.values())):
            raise ValueError("Review8 requires the exact build-repair backend clone with thinking cap4000")
    contracts = {}
    for agent in CASES:
        backend_name = ("gateway-build-repair" if reviewed_build and agent == "build-repair"
            else "gateway-intake" if agent in nonthinking else "gateway")
        backend = models.backends[backend_name]
        profile_name, profile = catalog.profile_for_agent(agent)
        if (profile.enable_thinking is not (False if agent in nonthinking else None)
                or profile.backend_name != backend_name):
            raise ValueError("Review5 operator thinking policy or backend differs")
        spec = AgentSpec.from_file(ROOT / "src/infosec_harness/agents" / agent / "agent.yaml")
        if (manifest.rerun.review_version in (6, 7, 8)
                and spec.model_settings.get("parallel_tool_calls") is not
                    (False if agent in {"env-planner", "build-repair", "partial-build"} else None)):
            raise ValueError("Review6 requires exactly the declared serial tool settings")
        model = models.model_id(spec.model or "sonnet", backend_name)
        if model != manifest.model:
            raise ValueError("Review5 agent resolves a different provider model")
        settings = _apply_max_tokens_floor(dict(spec.model_settings or {}), backend.min_max_tokens)
        contract = catalog.resolve_contract(agent, backend_name, model, settings,
            backend_endpoint=backend.base_url, atomic_intake=agent == "intake",
            merge_system_messages=backend.merge_system_messages, min_max_tokens=backend.min_max_tokens,
            strict_closed_output_tools=backend.strict_closed_output_tools, enable_thinking=backend.enable_thinking,
            thinking_token_budget=backend.thinking_token_budget if reviewed_build else None)
        contracts[agent] = {"backend": backend_name, "profile": profile_name,
            "enable_thinking": contract.enable_thinking, "contract_digest": contract.digest,
            **({"thinking_token_budget": contract.thinking_token_budget} if reviewed_build else {})}
    return contracts


def verify_retained_local(amendment: NativeRerunAmendment, read) -> None:
    """Reuse only the pinned successful Local trial; keep its failed Temporal checkpoint."""
    path = amendment.retained_local_report_file
    if amendment.prior_reports.get(path) != amendment.retained_local_report_sha256:
        raise ValueError("Passed Local report must be part of the retained report union")
    report = read(path, amendment.retained_local_report_sha256)
    previous = RealProviderManifest.model_validate(read(amendment.retained_local_manifest_file,
                                                        amendment.retained_local_manifest_sha256))
    if (previous.rerun is None or previous.rerun.review_version != 3
            or previous.rerun.original_manifest_sha256 != amendment.original_manifest_sha256
            or previous.rerun.baseline_report_sha256 != amendment.baseline_report_sha256
            or previous.rerun.candidate_files != amendment.candidate_files):
        raise ValueError("Passed Local manifest must be the unchanged reviewed v3 candidate")
    rows = report.get("cases", [])
    if (report.get("phase") != "local" or report.get("status") != "passed"
            or report.get("execution_status") != "passed" or report.get("semantic_status") != "passed"
            or len(rows) != 11 or {row.get("agent") for row in rows} != set(CASES)
            or any(row.get("execution") != "passed" or row.get("semantic_score") != "passed"
                   or row.get("cleanup") != "passed" or row.get("case") != CASES[row["agent"]]
                   or row.get("case_digest") != prepare_case(row["agent"], previous)[3] for row in rows)):
        raise ValueError("Retained Local trial must pass every unchanged case and cleanup gate")
    failed_path = str(Path(path).with_name("temporal.json"))
    if failed_path not in amendment.prior_reports:
        raise ValueError("Failed empty Temporal checkpoint must remain retained")
    failed = read(failed_path, amendment.prior_reports[failed_path])
    if (failed.get("status") != "failed" or failed.get("failure_type") != "ValueError"
            or failed.get("cases", []) or failed.get("ledger") or failed.get("task_queue") or failed.get("worker_pid")):
        raise ValueError("Retained Temporal checkpoint must be the pre-submission failure")


def selected_phases(manifest: RealProviderManifest, phase: str) -> tuple[str, ...]:
    if manifest.rerun and manifest.rerun.review_version in (5, 6, 7, 8) and phase == "direct":
        raise ValueError("Review5 authorizes only fresh native Local and Temporal phases")
    if manifest.rerun and manifest.rerun.review_version == 4:
        if phase not in {"validate", "all", "temporal"}:
            raise ValueError("Review4 authorizes only a fresh Temporal phase")
        return () if phase == "validate" else ("temporal",)
    if phase == "all":
        return ("local", "temporal") if manifest.rerun or manifest.amendment else ("direct", "local", "temporal")
    return () if phase == "validate" else (phase,)


def claim_phase(report_directory: Path, manifest_sha256: str, phase: str) -> None:
    if phase not in {"direct", "local", "temporal"}:
        raise ValueError("Unknown qualification phase")
    directory = report_directory / "execution-claims"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(directory / f"{manifest_sha256}-{phase}.started", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class RealProviderManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    version: int = 1
    endpoint: str = "https://llm.almckay.io/v1"
    model: str = "Qwen3.6-35B-A3B-NVFP4"
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
    max_concurrency: int = 1
    root_duration_seconds: int = 7200
    graph_repo: str = "eval-corpus/python/sqli/vulnerable"
    amendment: CorrectedPilotAmendment | None = None
    rerun: NativeRerunAmendment | None = None

    @model_validator(mode="after")
    def frozen_scope(self):
        if (self.version != 1 or self.endpoint != "https://llm.almckay.io/v1"
                or self.model != "Qwen3.6-35B-A3B-NVFP4" or self.cases != CASES
                or self.max_concurrency != 1 or self.root_duration_seconds != 7200):
            raise ValueError("Real-provider pilot differs from the frozen scope")
        if self.amendment and self.rerun:
            raise ValueError("Historical correction and fresh rerun cannot be combined")
        temporal_only = self.rerun is not None and self.rerun.review_version == 4
        expected_trials = 11 if temporal_only else 22 if self.amendment or self.rerun else 33
        expected_phases = (["native-temporal"] if temporal_only else ["native-local", "native-temporal"]
                           if self.amendment or self.rerun else ["direct", "native-local", "native-temporal"])
        if (set(self.datasets) != set(CASES) or self.maximum_pilot_agent_trials != expected_trials
                or self.phases != expected_phases
                or self.pricing.input_per_mtok != 0 or self.pricing.output_per_mtok != 0):
            raise ValueError("Frozen provenance or zero-price policy differs")
        if self.rerun and set(self.rerun.candidate_files) != {
                self.broker_models_config, self.broker_config, self.rerun.native_config_file}:
            raise ValueError("Rerun must freeze exactly the declared model, broker and native config files")
        if self.case_digests and set(self.case_digests) != set(CASES):
            raise ValueError("Case digests must cover every frozen agent")
        return self


def private_write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")
    temporary.replace(path)


def read_private_environment(path: str) -> dict[str, str]:
    import shlex
    source = Path(path)
    if source.stat().st_mode & 0o077:
        raise ValueError("Credential reference must be owner-only")
    result = {}
    for line in source.read_text().splitlines():
        if line.strip() and not line.lstrip().startswith("#") and "=" in line:
            name, value = line.split("=", 1)
            parts = shlex.split(value)
            if len(parts) == 1:
                result[name.strip()] = parts[0]
    return result


def verify_retained_failure(amendment: CorrectedPilotAmendment) -> None:
    failed_bytes = Path(amendment.failed_report_file).read_bytes()
    if hashlib.sha256(failed_bytes).hexdigest() != amendment.failed_report_sha256:
        raise ValueError("Retained failed report differs")
    failed = json.loads(failed_bytes)
    requests = [request for row in failed.get("cases", [])
        for request in row.get("ledger", {}).get("requests", [])]
    unknowns = {request["request_id"] for request in requests if request["state"] == "completion_unknown"}
    if (failed.get("status") != "failed" or len(failed.get("cases", [])) != 4
            or len(requests) != 4 or unknowns != set(amendment.retained_unknown_request_ids)):
        raise ValueError("Retained failure must preserve the exact four unknown requests")


def phase_environment(manifest: RealProviderManifest, phase: str) -> dict[str, str]:
    values = dict(os.environ)
    values.pop(manifest.worker_hmac_env, None)
    for name in ("HARNESS_BROKER_CONFIG", "HARNESS_MODEL_BACKEND", "HARNESS_BROKER_SERVICE_MANIFEST",
                 "HARNESS_NATIVE_TEMPORAL_CONFIG", "HARNESS_OPENAI_API_KEY", "HARNESS_BROKER_NATIVE_CONFIG",
                 "HARNESS_REAL_PROVIDER_STRICT_CLOSED_OUTPUT_TOOLS",
                 "OPENAI_API_KEY", "AWS_ACCESS_KEY_ID",
                 "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        values.pop(name, None)
    managed = ROOT / ".harness/dev.env"
    if managed.exists():
        runtime = read_private_environment(str(managed))
        for name, value in runtime.items():
            if name.startswith(("HARNESS_SANDBOX_", "HARNESS_BUILD_")) or name == "HARNESS_BUILDX_BUILDER":
                values[name] = value
    values["HARNESS_ALLOW_INSECURE_RUNTIME"] = "false"
    values["HARNESS_SANDBOX_RUNTIME"] = "runsc"
    values["PATH"] = os.pathsep.join((str(ROOT / ".harness/bin"), str(ROOT / ".venv/bin"), values.get("PATH", "")))
    database_url = "sqlite+aiosqlite:///:memory:"
    if phase != "direct":
        private = read_private_environment(manifest.database_env_file)
        if "HARNESS_DATABASE_URL" not in private:
            raise ValueError("Private database reference must define HARNESS_DATABASE_URL")
        database_url = private["HARNESS_DATABASE_URL"]
    values.update(HARNESS_MODEL_MODE="live", HARNESS_DATABASE_URL=database_url,
        HARNESS_MODELS_CONFIG=manifest.direct_models_config if phase == "direct" else manifest.broker_models_config,
        HARNESS_AGENT_RUN_TIMEOUT_S="600", PYDANTIC_AI_NO_BANNER="1",
        PYTHONPATH=os.pathsep.join((str(ROOT / "src"), str(ROOT / "tests/runtime"))))
    if phase != "direct":
        key_path = Path(manifest.worker_hmac_file)
        if key_path.stat().st_mode & 0o077:
            raise ValueError("Worker HMAC reference must be owner-only")
        secret = key_path.read_text().strip()
        if not secret or len(secret) > 4096:
            raise ValueError("Invalid worker credential reference")
        values[manifest.worker_hmac_env] = secret
        values["HARNESS_BROKER_CONFIG"] = manifest.broker_config
        if manifest.rerun and manifest.rerun.review_version in (3, 4, 5, 6, 7, 8):
            values["HARNESS_REAL_PROVIDER_STRICT_CLOSED_OUTPUT_TOOLS"] = "true"
    return values


def prepare_case(agent: str, manifest: RealProviderManifest):
    import yaml

    from infosec_harness.agents.intake_contracts import render_intake_prompt
    from infosec_harness.agents.registry import load_spec
    from infosec_harness.agents.render import render_prompt
    from infosec_harness.evals.adapters import ADAPTERS
    from infosec_harness.inference.protocol import digest
    path = ROOT / "src/infosec_harness/agents" / agent / "evals/dataset.yaml"
    frozen = manifest.datasets[agent]
    if (Path(frozen.path).resolve() != path.resolve() or frozen.case != manifest.cases[agent]
            or hashlib.sha256(path.read_bytes()).hexdigest() != frozen.sha256):
        raise ValueError("Frozen dataset provenance changed")
    dataset = yaml.safe_load(path.read_text())
    if str(dataset["version"]) != frozen.version:
        raise ValueError("Frozen dataset version changed")
    matching = [case for case in dataset["cases"] if case["name"] == manifest.cases[agent]]
    if len(matching) != 1:
        raise ValueError("Frozen case is absent or ambiguous")
    case = matching[0]
    case_digest = digest(case)
    if manifest.case_digests and case_digest != manifest.case_digests[agent]:
        raise ValueError("Frozen case content changed")
    task, payload, deps, predict, expected = ADAPTERS[agent](case)
    protocol = ((load_spec(agent).metadata or {}).get("intake_output") or {}).get("protocol")
    prompt = render_intake_prompt(task, payload, protocol=protocol) if agent == "intake" else render_prompt(task, payload)
    # Expected labels and scorer callbacks remain host-only, never in the workflow input.
    return {"agent": agent, "prompt": prompt, "deps": deps}, predict, expected, case_digest


def output_class(agent: str):
    from infosec_harness.agents.outputs import (
        ContextOutput,
        InconclusiveOutput,
        PartialEnvironmentOutput,
        PlannedEnvironmentOutput,
    )
    from infosec_harness.agents.registry import AGENT_BINDINGS
    if agent == "verdict":
        return InconclusiveOutput
    return {"env-planner": PlannedEnvironmentOutput, "context": ContextOutput,
            "partial-build": PartialEnvironmentOutput}.get(agent, AGENT_BINDINGS[agent])


def score_output(agent: str, output, predict, expected) -> dict:
    from pydantic import BaseModel

    from infosec_harness.agents.outputs import InconclusiveOutput, NegativeOutput, PositiveOutput
    expected_type = output_class(agent)
    valid = isinstance(output, (InconclusiveOutput, NegativeOutput, PositiveOutput)) if agent == "verdict" else type(output) is expected_type
    if not valid or not isinstance(output, BaseModel):
        raise ValueError("Registered output type differs from the current contract")
    predicted = predict(output)
    return {"output_type": type(output).__name__, "typed_output": output.model_dump(mode="json"),
            "predicted": predicted, "expected": expected, "semantic_score": "passed" if predicted == expected else "failed"}


COMPARISON_MODEL_FIELDS = ("effective_settings", "provider_output_floor", "transport_retries",
    "resolved_model", "backend_kind", "pricing_status", "pricing_table", "endpoint")


def compare_baseline(agent: str, config: dict, case_digest: str, *,
                     reviewed_strict_closed_output_tools: bool = False) -> dict:
    path = os.environ.get("HARNESS_REAL_PROVIDER_BASELINE")
    if not path:
        raise ValueError("Native qualification requires a completed direct baseline")
    baseline = json.loads(Path(path).read_text())
    rows = baseline.get("cases", [])
    if (baseline.get("phase") != "direct" or baseline.get("status") != "passed"
            or len(rows) != 11 or {row["agent"] for row in rows} != set(CASES)):
        raise ValueError("Direct baseline does not cover the exact frozen cases")
    previous = next(row for row in rows if row["agent"] == agent)
    if previous.get("case") != CASES[agent] or previous.get("case_digest") != case_digest:
        raise ValueError("Baseline case content differs")
    old = previous["config"]
    old_capability = dict(old["model"].get("capability_profile", {}))
    current_capability = dict(config["model"].get("capability_profile", {}))
    previous_strict = old_capability.pop("strict_closed_output_tools", False)
    current_strict = current_capability.pop("strict_closed_output_tools", False)
    if old_capability != current_capability:
        raise ValueError("Baseline capability profile differs")
    if (previous_strict is not False or current_strict is not reviewed_strict_closed_output_tools
            or type(reviewed_strict_closed_output_tools) is not bool):
        raise ValueError("Only explicitly reviewed closed-output shaping may differ")
    output_change = None
    if reviewed_strict_closed_output_tools:
        if (not isinstance(config["model"].get("broker_contract"), dict)
                or config["model"]["broker_contract"].get("strict_closed_output_tools") is not True):
            raise ValueError("Reviewed shaping requires the exact opted-in native contract")
        intentional = {"durable", "broker_contract", "credential_reference", "capability_profile", "pricing_table"}
        if ({key: value for key, value in old["model"].items() if key not in intentional}
                != {key: value for key, value in config["model"].items() if key not in intentional}):
            raise ValueError("Other baseline model metadata differs")
        if old["budget"] != config["budget"]:
            raise ValueError("Authored agent safety budget differs from baseline")
        output_change = {"review_version": 3, "field": "strict_closed_output_tools", "direct": False, "native": True,
                         "scope": "closed model output tools only; typed output contracts, scorer and expected outcome unchanged"}
    pricing_provenance = None
    for name in COMPARISON_MODEL_FIELDS:
        previous_value, current_value = old["model"].get(name), config["model"].get(name)
        if previous_value != current_value:
            if name == "pricing_table" and isinstance(previous_value, str) and isinstance(current_value, str):
                # Catalog bytes differ when native profiles are added; price inputs must match.
                previous_parts, current_parts = previous_value.split(";"), current_value.split(";")
                if (len(previous_parts) == len(current_parts) == 4
                        and previous_parts[1].startswith("models:")
                        and current_parts[1].startswith("models:")
                        and previous_parts[0::2] == current_parts[0::2]
                        and previous_parts[3] == current_parts[3]):
                    pricing_provenance = {"direct": previous_value, "native": current_value,
                        "difference": "models catalog bytes; exact provider and custom price inputs matched"}
                    continue
            raise ValueError("Baseline model settings or pricing differ")
    if old["budget"]["requested"] != config["budget"]["requested"]:
        raise ValueError("Authored agent safety budget differs from baseline")
    result = {"status": "passed", "baseline_sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest(),
            "matched_model_fields": list(COMPARISON_MODEL_FIELDS), "authored_budget": "matched",
            "pricing_catalog_provenance": pricing_provenance,
            "intentional_transport_fields": {name: config["model"].get(name)
                for name in ("durable", "broker_contract", "capability_profile", "credential_reference")}}
    if output_change is not None:
        result["declared_output_shaping_difference"] = output_change
    return result


def compare_review6_baseline(agent: str, config: dict, case_digest: str, *, review_version: int = 6) -> dict:
    from copy import deepcopy

    previous = next(row["config"]["model"] for row in
        json.loads(Path(os.environ["HARNESS_REAL_PROVIDER_BASELINE"]).read_text())["cases"] if row["agent"] == agent)
    model = config["model"]
    contract = model.get("broker_contract", {})
    if review_version not in (6, 7, 8):
        raise ValueError("Unsupported serial-tools reviewed comparison")
    nonthinking = agent in ({"intake", "probe-diagnosis", "verdict", "build-repair"}
        if review_version == 7 else {"intake", "probe-diagnosis", "verdict"})
    reviewed_build = review_version == 8 and agent == "build-repair"
    backend = "gateway-build-repair" if reviewed_build else "gateway-intake" if nonthinking else "gateway"
    if (model.get("backend_name") != backend or contract.get("backend") != backend
            or model.get("capability_profile", {}).get("enable_thinking") is not (False if nonthinking else None)
            or contract.get("enable_thinking") is not (False if nonthinking else None)
            or contract.get("model_settings") != model.get("effective_settings")
            or previous.get("backend_name") != "gateway"
            or previous.get("capability_profile", {}).get("enable_thinking") is not None
            or not previous["resolved_model"].startswith("gateway:")
            or model.get("resolved_model") != backend + ":" + previous["resolved_model"].split(":", 1)[1]
            or contract.get("model") != previous["resolved_model"].split(":", 1)[1]):
        raise ValueError("Review6 requires exact declared backend, thinking and contract settings")
    if review_version == 8 and (
            model.get("capability_profile", {}).get("thinking_token_budget") != (4000 if reviewed_build else None)
            or contract.get("thinking_token_budget") != (4000 if reviewed_build else None)):
        raise ValueError("Review8 permits thinking cap4000 only for build-repair")
    normalized = deepcopy(config)
    normalized_model = normalized["model"]
    if reviewed_build:
        normalized_model["capability_profile"].pop("thinking_token_budget", None)
    if nonthinking or reviewed_build:
        if nonthinking:
            normalized_model["capability_profile"].pop("enable_thinking")
        normalized_model["backend_name"] = "gateway"
        normalized_model["resolved_model"] = previous["resolved_model"]
        old_prices, new_prices = previous["pricing_table"].split(";"), model["pricing_table"].split(";")
        if len(old_prices) != 4 or len(new_prices) != 4 or old_prices[2] != "backend:gateway" or new_prices[2] != "backend:" + backend:
            raise ValueError("Review6 pricing backend provenance differs")
        new_prices[2] = old_prices[2]
        normalized_model["pricing_table"] = ";".join(new_prices)
    serial = agent in {"env-planner", "build-repair", "partial-build"}
    for key in ("requested_settings", "effective_settings"):
        if serial:
            if (model[key].get("parallel_tool_calls") is not False
                    or "parallel_tool_calls" in previous[key]):
                raise ValueError("Review6 permits only the declared serial tool setting addition")
            normalized_model[key].pop("parallel_tool_calls")
    budget_change = None
    if review_version == 8 and agent == "intake":
        old_budget = next(row["config"]["budget"] for row in
            json.loads(Path(os.environ["HARNESS_REAL_PROVIDER_BASELINE"]).read_text())["cases"]
            if row["agent"] == agent)
        for section in ("requested", "scaled", "effective"):
            before, after = old_budget[section], normalized["budget"][section]
            if (before.get("max_input_tokens") != 80000
                    or before.get("max_input_tokens_per_request") != 20000
                    or after.get("max_input_tokens") != 128000
                    or after.get("max_input_tokens_per_request") != 32000
                    or before.get("max_requests") != 4 or after.get("max_requests") != 4
                    or before.get("max_output_tokens") != 64000 or after.get("max_output_tokens") != 64000):
                raise ValueError("Review8 permits only the approved intake input budget128k/per-request32k")
            after["max_input_tokens"] = before["max_input_tokens"]
            after["max_input_tokens_per_request"] = before["max_input_tokens_per_request"]
        budget_change = {"agent": "intake", "sections": ["requested", "scaled", "effective"],
            "direct": {"max_input_tokens": 80000, "max_input_tokens_per_request": 20000},
            "native": {"max_input_tokens": 128000, "max_input_tokens_per_request": 32000},
            "max_requests": 4, "max_output_tokens": 64000,
            "scope": "exact approved intake input budget; every other authored and resolved budget field matched"}
    result = compare_baseline(agent, normalized, case_digest, reviewed_strict_closed_output_tools=True)
    if budget_change is not None:
        result["declared_intake_input_budget_difference"] = budget_change
    result["declared_output_shaping_difference"]["review_version"] = review_version
    result[f"declared_review{review_version}_difference"] = {"enable_thinking": False if nonthinking else None,
        "parallel_tool_calls": False if serial else None,
        "scope": ("source-pinned output guidance; original cases, scores and prices unchanged; exact declared intake input limits"
            if review_version == 8 else "source-pinned output guidance; original cases, scores, prices and full budgets unchanged"),
        **({"thinking_token_budget": 4000 if reviewed_build else None} if review_version == 8 else {})}
    result["intentional_transport_fields"] = {name: model.get(name) for name in
        ("durable", "broker_contract", "capability_profile", "credential_reference")}
    return result


def compare_manifest_baseline(manifest: RealProviderManifest, agent: str, config: dict, case_digest: str) -> dict:
    if manifest.rerun and manifest.rerun.review_version in (6, 7, 8):
        return compare_review6_baseline(agent, config, case_digest, review_version=manifest.rerun.review_version)
    if manifest.rerun and manifest.rerun.review_version in (3, 4, 5):
        if manifest.rerun.review_version == 5 and agent == "intake":
            from broker_thinking_diagnostic_fixture import compare_intake_nonthinking

            result = compare_intake_nonthinking(config, case_digest)
            result["declared_reasoning_difference"]["review_version"] = 5
            result["declared_reasoning_difference"]["scope"] = "full frozen native qualification; acceptance pending execution and semantic gates"
        else:
            if (manifest.rerun.review_version == 5 and
                    (config["model"].get("capability_profile", {}).get("enable_thinking") is not None
                     or config["model"].get("broker_contract", {}).get("enable_thinking") is not None)):
                raise ValueError("Review5 permits thinking control only for intake")
            result = compare_baseline(agent, config, case_digest, reviewed_strict_closed_output_tools=True)
        result["declared_output_shaping_difference"]["review_version"] = manifest.rerun.review_version
        return result
    return compare_baseline(agent, config, case_digest)


def workflow_input(inputs: dict) -> dict:
    from pydantic_ai.messages import CachePoint
    content = []
    for part in inputs["prompt"]:
        if isinstance(part, str):
            content.append(part)
        elif type(part) is CachePoint:
            content.append({"kind": "cache-point", "ttl": part.ttl})
        else:
            raise ValueError("Unexpected public prompt content")
    result = {"agent": inputs["agent"], "prompt": content,
              "deps": inputs["deps"].model_dump(mode="json")}
    if inputs["agent"] == "intake":
        result["intake_source_guidance"] = True
    return result


async def ledger_snapshot(root_id: str) -> dict:
    from sqlalchemy import select

    from infosec_harness.persistence import db
    async with db.session() as session:
        root = await session.get(db.BudgetLedger, root_id)
        records = (await session.execute(select(db.InferenceRequestRecord).where(
            db.InferenceRequestRecord.root_id == root_id))).scalars().all()
        return {"root_id": root_id, "root_state": root.state if root else None,
            "requests": [{"request_id": row.request_id, "agent": row.request["binding"]["agent"],
                          "state": row.state, "allocation": row.allocation, "overrun": row.overrun,
                          "result_usage": row.result.get("usage") if row.result else None,
                          "payload_digest": row.request["payload_digest"]} for row in records],
            "request_states": dict(Counter(row.state for row in records))}


async def run_local_case(manifest: RealProviderManifest, phase: str, agent: str,
                         checkpoint: Callable[[dict], None] | None = None,
                         validate_config: Callable[[object], None] | None = None,
                         compare_config: Callable[[dict, str], dict] | None = None) -> dict:
    """One unchanged production case; callers own their explicit finite scope."""
    from pydantic_ai import capture_run_messages

    from infosec_harness.agents.registry import load_spec, resolve_agent_config
    from infosec_harness.graph.ops import LocalOps
    from infosec_harness.inference.protocol import digest

    inputs, predict, expected, case_digest = prepare_case(agent, manifest)
    ops = LocalOps(sandbox=True, recipe_cache=False)
    row = {"agent": agent, "case": manifest.cases[agent], "case_digest": case_digest,
           "execution": "failed", "cleanup": "not_checked"}
    started = time.monotonic()
    messages = []
    try:
        config = resolve_agent_config(agent, load_spec(agent), source_files=inputs["deps"].source_files, durable=False)
        if validate_config is not None:
            validate_config(config)
        row["config"] = config.model_dump(mode="json")
        if config.model.endpoint != manifest.endpoint:
            raise ValueError("Resolved model endpoint differs from the frozen manifest")
        if phase != "direct":
            row["baseline_comparison"] = (compare_config(row["config"], case_digest) if compare_config is not None
                else compare_manifest_baseline(manifest, agent, row["config"], case_digest))
        with capture_run_messages() as messages:
            outcome = await ops.run_agent(agent, inputs["prompt"], inputs["deps"])
        row.update(score_output(agent, outcome.output, predict, expected))
        row.update(execution="passed", requests=outcome.requests, input_tokens=outcome.input_tokens,
            output_tokens=outcome.output_tokens, tools_called=outcome.tools_called,
            effective_config=outcome.effective_config)
    except asyncio.CancelledError:
        row["failure_type"] = "CancelledError"
        raise
    except Exception as error:
        from infosec_harness.evals.errors import failure_diagnostic
        from infosec_harness.evals.intake_fields import intake_field_summary
        from infosec_harness.evals.output_retries import output_retry_summary
        metadata = row.get("config", {}).get("effective_spec", {}).get("metadata", {})
        protocol = (metadata.get("intake_output") or {}).get("protocol")
        row["failure_diagnostic"] = failure_diagnostic(error)
        row["output_retry_summary"] = output_retry_summary(messages, agent=agent)
        row["intake_field_summary"] = intake_field_summary(
            messages, report=getattr(inputs["deps"], "report_text", None), agent=agent, protocol=protocol)
        row["failure_type"] = type(error).__name__
        row["broker_error_code"] = getattr(error, "code", None)
    finally:
        try:
            await ops.close()
            row["cleanup"] = "passed"
        except Exception as error:
            row["cleanup"] = "failed"
            row["cleanup_failure_type"] = type(error).__name__
        if phase != "direct":
            row["ledger"] = await ledger_snapshot(digest({"local_run": ops._broker_run_id}))
        row["elapsed_seconds"] = round(time.monotonic() - started, 3)
        if checkpoint is not None:
            checkpoint(row)
    return row


async def run_local(manifest: RealProviderManifest, phase: str, report_path: Path) -> dict:
    from infosec_harness.agents.registry import AGENT_BINDINGS
    if set(CASES) != set(AGENT_BINDINGS):
        raise ValueError("Every registered agent must have a frozen case")
    report = {"phase": phase, "status": "running", "provider": manifest.endpoint,
              "model": manifest.model, "cases": [], "accuracy_scope": "eleven frozen cases; not a release-quality accuracy gate"}
    private_write(report_path, report)
    def checkpoint(row):
        report["cases"].append(row)
        private_write(report_path, report)
    for agent in CASES:
        await run_local_case(manifest, phase, agent, checkpoint=checkpoint)
    report["execution_status"] = "passed" if len(report["cases"]) == 11 and all(row["execution"] == row["cleanup"] == "passed" for row in report["cases"]) else "failed"
    report["semantic_status"] = "passed" if len(report["cases"]) == 11 and all(row.get("semantic_score") == "passed" for row in report["cases"]) else "failed"
    report["status"] = "passed" if report["execution_status"] == report["semantic_status"] == "passed" else "failed"
    private_write(report_path, report)
    return report


async def seed_root(root_id: str, manifest: RealProviderManifest) -> None:
    from infosec_harness.agents.durable import CONFIGS
    from infosec_harness.agents.registry import ACTIVITY_MAX_ATTEMPTS
    from infosec_harness.persistence import budgets, db
    # Derive the existing RootAccounting retry envelope from the exact accepted configs.
    totals = dict.fromkeys(("requests", "tokens", "cost_usd", "tool_calls", "agent_runs", "execution_seconds"), 0)
    for config in CONFIGS.values():
        bounds = config.budget.effective
        factor = ACTIVITY_MAX_ATTEMPTS * (config.model.transport_retries + 1)
        totals["requests"] += bounds.max_requests * factor
        totals["tokens"] += (bounds.max_input_tokens + bounds.max_output_tokens) * factor
        totals["tool_calls"] += bounds.max_tool_calls * factor
        totals["agent_runs"] += 1
        totals["execution_seconds"] += bounds.max_tool_calls * 300 * ACTIVITY_MAX_ATTEMPTS
        totals["cost_usd"] += 0 if config.model.pricing_status == "known_zero" else bounds.max_cost_usd * factor
    state = budgets.initial_state(totals, elapsed_seconds=manifest.root_duration_seconds)
    state["agent_config_digests"] = {name: config.digest for name, config in CONFIGS.items()}
    async with db.session() as session:
        if await session.get(db.BudgetLedger, root_id) is not None:
            raise ValueError("Qualification root already exists")
        session.add(db.BudgetLedger(root_id=root_id, state=state))
        await session.commit()


async def recover_owned_submission(client, workflow_id: str, queue: str):
    """Recover a submitted run only after checking its declared ownership scope."""
    description = await asyncio.wait_for(client.get_workflow_handle(workflow_id).describe(), 10)
    if (description.id != workflow_id or description.task_queue != queue
            or description.workflow_type != "BrokerRealProviderQualificationWorkflow" or not description.run_id):
        raise ValueError("Submitted workflow ownership differs")
    return client.get_workflow_handle(workflow_id, run_id=description.run_id,
                                      first_execution_run_id=description.run_id)


def temporal_case_config(agent: str, inputs: dict):
    """Match the production per-run repository-size budget resolution."""
    from infosec_harness.agents.durable import CONFIGS
    return CONFIGS[agent].for_source_files(inputs["deps"].source_files)


async def run_temporal(manifest: RealProviderManifest, report_path: Path) -> dict:
    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from temporalio.client import Client
    from temporalio.worker import Replayer
    from test_broker_real_provider_temporal import RealProviderWorkflow

    from infosec_harness.agents.durable import CONFIGS
    from infosec_harness.agents.outputs import InconclusiveOutput, NegativeOutput, PositiveOutput
    from infosec_harness.inference import invocations
    from infosec_harness.inference.transport import BrokerModel
    for agent in CASES:
        if CONFIGS[agent].model.endpoint != manifest.endpoint:
            raise ValueError("Resolved model endpoint differs from the frozen manifest")
        inputs, _predict, _expected, case_digest = prepare_case(agent, manifest)
        compare_manifest_baseline(manifest, agent, temporal_case_config(agent, inputs).model_dump(mode="json"), case_digest)
    suffix = uuid.uuid4().hex
    queue = "broker-real-provider-" + suffix
    log_path = report_path.with_suffix(".worker.log")
    with log_path.open("ab") as log:
        process = subprocess.Popen([sys.executable, __file__, "worker", "--manifest", os.environ["HARNESS_REAL_PROVIDER_MANIFEST"],
            "--queue", queue], stdout=log, stderr=log)
    report = {"phase": "temporal", "status": "running", "task_queue": queue, "worker_pid": process.pid,
              "worker_cleanup": "not_checked", "cases": []}
    private_write(report_path, report)
    try:
        client = await Client.connect(manifest.temporal_address, plugins=[PydanticAIPlugin()])
        for agent in CASES:
            inputs, predict, expected, case_digest = prepare_case(agent, manifest)
            root_id = "broker-real-" + uuid.uuid4().hex
            await seed_root(root_id, manifest)
            row = {"agent": agent, "case": manifest.cases[agent], "case_digest": case_digest,
                   "execution": "failed", "history_replay": "not_checked"}
            started = time.monotonic()
            row["config"] = temporal_case_config(agent, inputs).model_dump(mode="json")
            row["baseline_comparison"] = compare_manifest_baseline(manifest, agent, row["config"], case_digest)
            handle = None
            workflow_id = "batch:" + root_id
            row["workflow_id"] = workflow_id
            try:
                handle = await client.start_workflow(RealProviderWorkflow.run, workflow_input(inputs),
                    id=workflow_id, task_queue=queue)
                result = await asyncio.wait_for(handle.result(), 1200)
                output_type = output_class(agent)
                if agent == "verdict":
                    output_type = {"InconclusiveOutput": InconclusiveOutput, "PositiveOutput": PositiveOutput,
                                   "NegativeOutput": NegativeOutput}[result["output_type"]]
                output = output_type.model_validate(result["output"])
                row.update(score_output(agent, output, predict, expected))
                row.update(execution="passed", requests=result["requests"], input_tokens=result["input_tokens"],
                           output_tokens=result["output_tokens"], tools_called=result["tools_called"])
            except (Exception, asyncio.CancelledError) as error:
                row["failure_type"] = type(error).__name__
                if handle is None:
                    try:
                        handle = await recover_owned_submission(client, workflow_id, queue)
                        row["submission_recovery"] = "passed"
                    except Exception as recovery_error:
                        row["submission_recovery"] = "failed"
                        row["submission_recovery_failure_type"] = type(recovery_error).__name__
                if handle is not None:
                    with suppress(Exception):
                        await handle.terminate("Bounded real-provider qualification ended")
                if isinstance(error, asyncio.CancelledError):
                    raise
            finally:
                row["elapsed_seconds"] = round(time.monotonic() - started, 3)
                if handle is None:
                    row["ledger"] = await ledger_snapshot(root_id)
                else:
                    try:
                        # Termination skips workflow finally; close only a proven owned binding.
                        snapshot = await ledger_snapshot(root_id)
                        owned = [operation for operation in (snapshot["root_state"] or {}).get("operations", {}).values()
                                 if operation.get("broker_binding", {}).get("run_id") == handle.first_execution_run_id]
                        if owned:
                            await invocations.close_run(handle.first_execution_run_id, root_id)
                            row["cleanup"] = "passed"
                        else:
                            row["cleanup"] = "not_applicable"
                        history = await handle.fetch_history()
                        private_write(report_path.parent / f"{root_id}.history.json", json.loads(history.to_json()))
                        before = await ledger_snapshot(root_id)
                        original_request, original_issue = BrokerModel.request, invocations.request_invocation
                        async def forbidden(*_args, **_kwargs):
                            raise AssertionError("History replay attempted broker I/O")
                        BrokerModel.request, invocations.request_invocation = forbidden, forbidden
                        try:
                            await Replayer(workflows=[RealProviderWorkflow], plugins=[PydanticAIPlugin()]).replay_workflow(history)
                            after = await ledger_snapshot(root_id)
                            if after != before:
                                raise AssertionError("History replay changed durable ledger")
                            row["history_replay"] = "passed"
                        finally:
                            BrokerModel.request, invocations.request_invocation = original_request, original_issue
                        row.update(ledger=before, history_events=len(history.events), workflow_id=handle.id)
                    except Exception as error:
                        row["history_replay"] = "failed"
                        row["replay_failure_type"] = type(error).__name__
                        row["ledger"] = await ledger_snapshot(root_id)
                report["cases"].append(row)
                private_write(report_path, report)
    except (Exception, asyncio.CancelledError) as error:
        report["failure_type"] = type(error).__name__
        report["interrupted"] = isinstance(error, asyncio.CancelledError)
        report["status"] = "failed"
    finally:
        with suppress(ProcessLookupError):
            process.terminate()
        try:
            await asyncio.to_thread(process.wait, 10)
        except subprocess.TimeoutExpired:
            process.kill()
            await asyncio.to_thread(process.wait, 5)
        report["worker_cleanup"] = "passed" if process.poll() is not None else "failed"
        private_write(report_path, report)
    report["execution_status"] = "passed" if len(report["cases"]) == 11 and all(row["execution"] == row["history_replay"] == "passed" for row in report["cases"]) else "failed"
    report["semantic_status"] = "passed" if len(report["cases"]) == 11 and all(row.get("semantic_score") == "passed" for row in report["cases"]) else "failed"
    report["status"] = "passed" if report["execution_status"] == report["semantic_status"] == report["worker_cleanup"] == "passed" else "failed"
    private_write(report_path, report)
    return report


async def serve_worker(manifest: RealProviderManifest, queue: str):
    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from temporalio.client import Client
    from temporalio.worker import Worker
    from test_broker_real_provider_temporal import RealProviderWorkflow

    from infosec_harness.workflows.activities import ALL_ACTIVITIES
    client = await Client.connect(manifest.temporal_address, plugins=[PydanticAIPlugin()])
    await Worker(client, task_queue=queue, workflows=[RealProviderWorkflow], activities=ALL_ACTIVITIES).run()


async def phase_main(manifest, args):
    verify_review5_configuration(manifest)
    if args.phase != "worker":
        selected_phases(manifest, args.phase)
    task = asyncio.current_task()
    for termination_signal in (signal.SIGTERM, signal.SIGINT):
        asyncio.get_running_loop().add_signal_handler(termination_signal, task.cancel)
    if args.phase == "worker":
        await serve_worker(manifest, args.queue)
        return None
    return await (run_temporal(manifest, args.report) if args.phase == "temporal"
                  else run_local(manifest, args.phase, args.report))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("direct", "local", "temporal", "worker"))
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--queue")
    args = parser.parse_args()
    manifest = RealProviderManifest.model_validate_json(args.manifest.read_text())
    if args.phase != "worker":
        try:
            selected_phases(manifest, args.phase)
        except ValueError as error:
            parser.error(str(error))
    if args.phase == "worker":
        asyncio.run(phase_main(manifest, args))
        return 0
    try:
        result = asyncio.run(phase_main(manifest, args))
    except (Exception, asyncio.CancelledError) as error:
        report = json.loads(args.report.read_text()) if args.report.exists() else {"phase": args.phase}
        report.update(status="failed", failure_type=type(error).__name__)
        private_write(args.report, report)
        return 1
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
