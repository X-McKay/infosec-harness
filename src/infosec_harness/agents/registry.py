"""Agent loader (§6, D17): every agent is one pydantic-ai Agent Spec ``agents/<name>/agent.yaml``.

What stays in code: typed I/O bindings, the capability allowlist, the tier -> model
resolver, and output validators. Everything else (prompt, model tier, model settings,
retries, skills, tools) is data in the spec.
"""

from __future__ import annotations

import copy
import hashlib
import os
from collections.abc import Mapping
from datetime import timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from pydantic_ai import Agent
from pydantic_ai.agent.spec import AgentSpec
from pydantic_ai.capabilities import PrepareOutputTools, ResolveModelId
from pydantic_ai.durable_exec.temporal import TemporalDurability
from pydantic_ai_harness.compaction import ClearToolResults
from pydantic_ai_harness.repair_tool_arguments import RepairToolArguments
from pydantic_ai_harness.skills import Skills
from pydantic_ai_harness.warn_on_cache_busts import WarnOnCacheBusts
from temporalio.common import RetryPolicy
from temporalio.workflow import ActivityConfig

from infosec_harness.agents import models as model_factory
from infosec_harness.agents.budgets import (
    BudgetResolution,
    resolve_budget,
    resolve_declared_budget,
)
from infosec_harness.agents.capabilities import CUSTOM_CAPABILITIES
from infosec_harness.agents.deps import AgentDeps
from infosec_harness.agents.governance import GovernanceError, assert_governed
from infosec_harness.agents.intake_claims import (
    WIRE_VERSION,
    AtomicFinding,
    ReferenceError,
    reconstruct,
)
from infosec_harness.agents.intake_contracts import (
    ATOMIC_EXECUTION_NAME,
    QUOTED_EXECUTION_NAME,
    retained_intake_spec,
)
from infosec_harness.agents.intake_evidence import INTAKE_EVIDENCE_POLICY_VERSION
from infosec_harness.agents.outputs import (
    VERDICT_OUTPUTS,
    ContextOutput,
    PartialEnvironmentOutput,
    prepare_verdict_tools,
    verdict_contract_instructions,
)
from infosec_harness.agents.planning_window import PlanningWindow, PlanningWindowTelemetry
from infosec_harness.agents.replay_only import ReplayOnlyModel
from infosec_harness.agents.validators import (
    OUTPUT_VALIDATORS,
    bind_install_source_validator,
    validate_intake_evidence,
)
from infosec_harness.domain.models import (
    EnvironmentSpec,
    ExtractedFinding,
    FindingContext,
    ProbeDiagnosis,
    ProbePlan,
    ProbeSource,
    RepoProfile,
    Verdict,
    canonical_json,
)
from infosec_harness.resources import package_root
from infosec_harness.sandbox.install_sources import install_source_policy
from infosec_harness.settings import get_settings

os.environ.setdefault("PYDANTIC_AI_NO_BANNER", "1")

# name -> output type. Every agents/<name>/agent.yaml must appear here and vice versa.
AGENT_BINDINGS: dict[str, type[BaseModel]] = {
    "intake": ExtractedFinding,
    "recon": RepoProfile,
    "env-planner": EnvironmentSpec,
    "build-repair": EnvironmentSpec,
    "partial-build": EnvironmentSpec,
    "context": FindingContext,
    "probe-planner": ProbePlan,
    "probe-author": ProbeSource,
    "probe-diagnosis": ProbeDiagnosis,
    "probe-repair": ProbeSource,
    "verdict": Verdict,
}

# Only these capability types may be named in a spec (cf. pydantic-ai #5473/#8426).
# Skills and WarnOnCacheBusts are directly-decorated dataclasses, so the spec loader
# accepts them as custom types. RepairToolArguments and ClearToolResults inherit their
# dataclass fields (the loader's stricter check rejects them) and carry no accuracy-
# relevant config, so they are attached in code below rather than named in YAML.
# ToolOutputLimits (not Temporal-safe yet) and PromptInjectionDefender (needs an extra
# dependency) are intentionally absent.
ALLOWED_CAPABILITIES = (*CUSTOM_CAPABILITIES, Skills, WarnOnCacheBusts)

# Retries exist at four layers and their product is what actually runs (agent-playbook
# §6 "Retry ownership": every layer MUST have a calculated combined upper bound).
#
#   1. pydantic-ai semantic correction   -> spec `retries` (output 3-4, tools 2)
#   2. provider transport                -> BackendConfig.max_retries, reduced to
#                                           max_retries_under_temporal when durable
#   3. Temporal activity                 -> the policies below
#   4. workflow business retries         -> max_probe_repairs, handled in the graph
#
# Layers 1-3 for one durable agent run are bounded at
# ACTIVITY_MAX_ATTEMPTS * (max_retries_under_temporal + 1) * (spec output retries + 1).
# With the committed values that is 3 * 2 * 5 = 30 provider calls worst case. Leaving
# layer 3 unset — as this did — means Temporal's *default* policy, which is unlimited
# attempts: a deterministic failure then retries forever and the workflow hangs.
ACTIVITY_MAX_ATTEMPTS = 3
# Retrying these cannot change the outcome: permanent provider rejections, a semantic
# failure pydantic-ai has already exhausted its own retries on, and programming errors.
NON_RETRYABLE_ERRORS = [
    "AuthenticationError",
    "PermissionDeniedError",
    "BadRequestError",
    "NotFoundError",
    "UnprocessableEntityError",
    "UnexpectedModelBehavior",
    "ValidationError",
    "TypeError",
    "ValueError",
    "KeyError",
    "AttributeError",
    "BrokerError",
]
ACTIVITY_RETRY = RetryPolicy(
    maximum_attempts=ACTIVITY_MAX_ATTEMPTS, non_retryable_error_types=NON_RETRYABLE_ERRORS
)

# Model calls can be slow; tool calls are fast except the sandbox shell.
MODEL_ACTIVITY = ActivityConfig(
    start_to_close_timeout=timedelta(minutes=10), retry_policy=ACTIVITY_RETRY
)
TOOL_ACTIVITY = {
    "sandbox_shell": ActivityConfig(
        start_to_close_timeout=timedelta(minutes=5), retry_policy=ACTIVITY_RETRY
    )
}

# History size (estimated tokens) at which `ClearToolResults` starts blanking the oldest tool
# results, for an agent whose spec sets `metadata.clear_tool_results`. This is a *shape*
# control rather than a budget: every request resends the whole conversation, so without it
# per-request input grows with the turn count and any ceiling is eventually reached by an
# agent that merely keeps working. Bounding the history is what makes
# `budgets.max_input_tokens_per_request` a ceiling a healthy long run stays under instead of
# drifting into. Named here so the specs, the capability and tests/agents/test_budgets.py read one
# number; a spec may override it with `metadata.clear_tool_tokens`.
DEFAULT_CLEAR_TOOL_TOKENS = 40_000


class ResolvedAgentConfig(BaseModel):
    """Effective, secret-free invocation contract shared by production and evals."""

    model_config = {"frozen": True}

    agent_name: str
    effective_spec: dict[str, Any]
    skills_digest: str
    model: model_factory.ResolvedModelConfig
    budget: BudgetResolution

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json(self.model_dump(mode="json")).encode()).hexdigest()[
            :16
        ]

    @property
    def effective_digest(self) -> str:
        """Identity of behavior after provider and budget normalization.

        The full :attr:`digest` retains requested values for audit provenance. Calibration uses
        this projection to collapse candidates which differ only in a request that a provider
        floor or another effective limit normalizes to the same invocation contract.
        """
        spec = copy.deepcopy(self.effective_spec)
        spec.pop("model", None)
        spec.pop("model_settings", None)
        metadata = spec.get("metadata")
        if isinstance(metadata, dict):
            metadata.pop("budgets", None)
            # Routing policy is provenance for the requested tier; the resolved model below is
            # the behavior. Two policies resolving to the same concrete model are equivalent.
            metadata.pop("model_policy", None)
        model = self.model.model_dump(
            mode="json", exclude={"requested_model", "requested_settings"}
        )
        budget = {
            "agent_name": self.budget.agent_name,
            "source_files": self.budget.source_files,
            "formula_version": self.budget.formula_version,
            "size_factor": self.budget.size_factor,
            "rounding": self.budget.rounding,
            "effective": self.budget.effective.model_dump(mode="json"),
            "provider_output_floor": self.budget.provider_output_floor,
        }
        payload = {
            "agent_name": self.agent_name,
            "effective_spec": spec,
            "skills_digest": self.skills_digest,
            "model": model,
            "budget": budget,
        }
        return hashlib.sha256(canonical_json(payload).encode()).hexdigest()[:16]

    def for_source_files(self, source_files: int | None) -> ResolvedAgentConfig:
        """Replay-safe per-run variant with repository-size scaling applied."""
        budget = resolve_declared_budget(
            self.agent_name,
            self.budget.requested,
            source_files=source_files,
            provider_output_floor=self.model.provider_output_floor,
        )
        return self.model_copy(update={"budget": budget})


def spec_path(name: str) -> Path:
    return get_settings().agents_dir / name / "agent.yaml"


def deep_merge(base: Any, overlay: Any) -> Any:
    """Overlay semantics for experiments: dicts merge recursively, everything else replaces."""
    if isinstance(base, Mapping) and isinstance(overlay, Mapping):
        out = dict(base)
        for k, v in overlay.items():
            out[k] = deep_merge(base.get(k), v) if k in base else copy.deepcopy(v)
        return out
    return copy.deepcopy(overlay)


def load_spec(
    name: str,
    overlay: Mapping[str, Any] | None = None,
    *,
    spec_override: AgentSpec | None = None,
) -> AgentSpec:
    if spec_override is not None and overlay is not None:
        raise ValueError("A complete spec override cannot be combined with an overlay")
    spec = spec_override or AgentSpec.from_file(spec_path(name))
    if overlay:
        merged = deep_merge(spec.model_dump(by_alias=True, exclude_none=True, mode="json"), overlay)
        spec = AgentSpec.from_dict(merged)
    return spec


def _skills_hash(spec: AgentSpec) -> str:
    """Content hash of every skill directory the spec can load."""
    h = hashlib.sha256()
    for cap in spec.capabilities:
        if cap.name != "Skills":
            continue
        args = dict(cap.kwargs or {})
        dirs = args.get("directories") or (cap.args[0] if cap.args else "skills")
        include = set(args.get("include") or [])
        for d in [dirs] if isinstance(dirs, str) else dirs:
            root = _abs(d)
            for skill_md in sorted(root.glob("*/SKILL.md")):
                if include and skill_md.parent.name not in include:
                    continue
                for f in sorted(skill_md.parent.rglob("*")):
                    if f.is_file():
                        h.update(str(f.relative_to(root)).encode())
                        h.update(f.read_bytes())
    return h.hexdigest()


def _abs(path: str | Path) -> Path:
    """Resolve a spec-relative resource path against the package, never the working directory.

    ``skills`` is the shared library's name in every spec, so it resolves to the configured
    ``skills_dir`` -- which keeps ``HARNESS_SKILLS_DIR`` meaningful instead of quietly ignored.
    Anything else is taken as a path under the package root.
    """
    p = Path(path)
    if p.is_absolute():
        return p
    if str(p) == "skills":
        return get_settings().skills_dir
    return package_root() / p


def resolve_agent_config(
    name: str,
    spec: AgentSpec,
    *,
    source_files: int | None = None,
    durable: bool = False,
    replay_only: bool = False,
) -> ResolvedAgentConfig:
    """Resolve the same effective settings and limits an invocation will receive."""
    effective = _apply_backend_token_floor(name, spec)
    tier = effective.model or "sonnet"
    model = model_factory.resolve_config(
        name,
        tier,
        model_settings=dict(spec.model_settings or {}),
        durable=durable,
        replay_only=replay_only,
        atomic_intake=name == "intake" and ((spec.metadata or {}).get("intake_output") or {}).get("protocol") == WIRE_VERSION,
    )
    budget = resolve_budget(
        name,
        effective.metadata,
        source_files=source_files,
        provider_output_floor=model.provider_output_floor,
    )
    effective_spec = effective.model_dump(by_alias=True, exclude_none=True, mode="json")
    if name == "intake":
        metadata = effective_spec.setdefault("metadata", {})
        intake_output = metadata.get("intake_output") or {}
        metadata["output_validation"] = {
            "version": INTAKE_EVIDENCE_POLICY_VERSION,
            **({"wire_version": intake_output["protocol"]}
               if intake_output.get("protocol") == WIRE_VERSION else {}),
        }
    if name == "build-repair":
        # Operator configuration is resolved on the host, never from repository content.
        effective_spec.setdefault("metadata", {})["output_validation"] = install_source_policy(
            get_settings().default_registry_allowlist
        )
    return ResolvedAgentConfig(
        agent_name=name,
        effective_spec=effective_spec,
        skills_digest=_skills_hash(effective),
        model=model,
        budget=budget,
    )


def config_hash(
    name: str,
    spec: AgentSpec,
    *,
    source_files: int | None = None,
    durable: bool = False,
) -> str:
    """Agent config identity (§6): effective spec + skill contents + resolved model."""
    return resolve_agent_config(name, spec, source_files=source_files, durable=durable).digest


def _absolutize_skill_dirs(spec: AgentSpec) -> AgentSpec:
    """Resolve a spec's skill directories against the package, not the working directory.

    ``agent.yaml`` writes ``directories: skills`` because a spec should name the library, not
    the deployment's filesystem. Left relative, ``load_skill_libraries`` resolves it against
    the process CWD -- so the agents loaded their skills only when something happened to
    launch the worker from the repository root, and raised ``Skill library directory does not
    exist: skills`` from anywhere else. That is exactly the working-directory assumption
    agent-playbook 02 rules out, and an installed wheel is where it surfaces.

    The shape matters: ``model_dump(by_alias=True)`` renders a capability as
    ``{"name": "Skills", "arguments": {...}}``, never as the ``{"Skills": {...}}`` shorthand
    that appears in the YAML source. An earlier version of this function looked only for the
    shorthand, matched nothing, and silently rewrote no spec at all.
    """
    data = spec.model_dump(by_alias=True, exclude_none=True, mode="json")
    for cap in data.get("capabilities", []):
        if not isinstance(cap, dict):
            continue
        # Both renderings, so this keeps working whichever one a caller hands us.
        if cap.get("name") == "Skills":
            arguments = cap.setdefault("arguments", {})
        elif isinstance(cap.get("Skills"), dict):
            arguments = cap["Skills"]
        else:
            continue
        dirs = arguments.get("directories", "skills")
        arguments["directories"] = (
            str(_abs(dirs)) if isinstance(dirs, str) else [str(_abs(d)) for d in dirs]
        )
    return AgentSpec.from_dict(data)


def _apply_backend_token_floor(name: str, spec: AgentSpec) -> AgentSpec:
    """Raise the spec's per-call ``max_tokens`` to the serving backend's floor.

    The backend-level half of this lives in ``_CompatOpenAIChatModel.prepare_request``, which
    raises the cap on the outgoing payload. That is not enough on its own: pydantic-ai copies
    ``model_settings['max_tokens']`` into ``GraphAgentState.last_max_tokens`` when it builds
    the request, *before* the model's ``prepare_request`` runs, and that copy is the number
    reported by "Model token limit (N) exceeded before any response was generated". Applying
    the floor here as well keeps the two in agreement, so a diagnostic names the cap that was
    actually sent instead of the spec value that was superseded.

    A zero floor (Bedrock, where thinking has its own budget) is a no-op, so this changes
    nothing for the default backend. See :func:`models.max_tokens_floor`.
    """
    floored = model_factory._apply_max_tokens_floor(
        dict(spec.model_settings or {}), model_factory.max_tokens_floor(name)
    )
    if floored == (spec.model_settings or {}):
        return spec
    return spec.model_copy(update={"model_settings": floored})


def effective_spec(name: str, spec: AgentSpec) -> AgentSpec:
    """Apply backend adjustments visible to PydanticAI before building an agent."""
    return _apply_backend_token_floor(name, spec)


def _assert_execution_class_covers_tools(name: str, metadata: Mapping[str, Any] | None) -> None:
    """An agent's execution class must be at least what its most consequential tool requires.

    This is the rule that makes an execution class mean something: `sandbox-shell` executes
    code, so any agent enabling it is at least `durable`. Declaring a stronger class is fine;
    declaring a weaker one is not.
    """
    from infosec_harness.tools.policies import EXECUTION_CLASS_ORDER, required_execution_class

    meta = metadata or {}
    declared = meta.get("execution_class")
    required = required_execution_class(list(meta.get("enabled_toolsets") or []))
    if EXECUTION_CLASS_ORDER.index(declared) < EXECUTION_CLASS_ORDER.index(required):
        raise GovernanceError(
            f"Agent {name!r} declares execution_class {declared!r} but its enabled toolsets "
            f"require at least {required!r}"
        )


def _assert_tools_are_declared(name: str, spec: AgentSpec) -> None:
    """Every repo tool an agent can call must appear in the toolset's own policy.

    The policy in `tools/repo-read-only/tool.yaml` is what `required_execution_class` reads and
    what a reviewer reads; a tool reachable from a spec but absent from it is governed by
    nothing. This is checked against the spec rather than against the code's default surface,
    because `RepoReadOnly(tools=[...])` lets a spec name a subset -- and a typo in that list
    would otherwise silently narrow the agent's tools instead of failing.
    """
    from infosec_harness.agents.capabilities import DEFAULT_REPO_RO_TOOLS, REPO_RO_TOOLS
    from infosec_harness.tools.policies import load_policies

    declared = {t.name for t in load_policies()["repo-read-only"].tools}
    for cap in spec.capabilities:
        if cap.name != "RepoReadOnly":
            continue
        selected = (cap.kwargs or {}).get("tools") or DEFAULT_REPO_RO_TOOLS
        unknown = sorted(set(selected) - set(REPO_RO_TOOLS))
        if unknown:
            raise GovernanceError(
                f"Agent {name!r} selects repo tools that do not exist: {unknown}. "
                f"Available: {sorted(REPO_RO_TOOLS)}"
            )
        undeclared = sorted(set(selected) - declared)
        if undeclared:
            raise GovernanceError(
                f"Agent {name!r} can call repo tools that tools/repo-read-only/tool.yaml does "
                f"not declare: {undeclared}"
            )


def _resolve_agent_model(
    name: str,
    tier: str,
    *,
    durable: bool,
    atomic_intake: bool,
    replay_only: bool,
    deps: AgentDeps | None = None,
):
    if replay_only and durable and model_factory.get_settings().model_mode == "live":
        cfg = model_factory.load_models_config()
        backend = cfg.backends[cfg.backend_for(name)]
        if backend.transport == "brokered":
            # Retained generations have no current broker contract or dispatch authority.
            # Build only their static SDK profile so recorded history can decode.
            from infosec_harness.inference.unbound import UnboundBrokerModel
            return ReplayOnlyModel(UnboundBrokerModel(
                cfg.model_id(tier, cfg.backend_for(name)), atomic_intake=atomic_intake))
    model = (
        model_factory.resolve_intake_atomic(name, tier, durable=durable,
            **({"broker_binding": deps.broker_binding, "broker_contract": deps.broker_contract}
               if deps and deps.broker_binding else {}))
        if atomic_intake
        else model_factory.resolve(name, tier, durable=durable,
            **({"broker_binding": deps.broker_binding, "broker_contract": deps.broker_contract}
               if deps and deps.broker_binding else {}))
    )
    if replay_only and durable:
        return ReplayOnlyModel(model)
    return model


INTAKE_REFERENCE_REPAIR_VERSION = "intake-reference-repair-v1"
INTAKE_LITERAL_LINE_REPAIR_VERSION = "intake-literal-line-repair-v1"
_INTAKE_LITERAL_LINE_REPAIR = (
    "\nFix only unsupported start_line or end_line claims: report source IDs and report-line "
    "positions are not code line numbers. A retained code line claim needs its number "
    "literally stated in the referenced report text. Otherwise set the whole unsupported "
    "start_line or end_line claim to null, including its value, source and confidence. "
    "Keep other supported claims unchanged; do not invent a code line or supporting text."
)
INTAKE_UNSUPPORTED_CLAIM_REPAIR_VERSION = "intake-unsupported-claim-repair-v1"
_UNSUPPORTED_CLAIM_EVIDENCE_ERRORS = frozenset({
    "A literal location value is absent from its evidence quote.",
    "Every nonempty extraction field requires positive grounded evidence.",
})
_UNSUPPORTED_CLAIM_REPAIR = (
    "\nFix only unsupported claims: for symbol or file_path, the referenced report source "
    "must literally contain the claimed value. Cite actual supporting source lines with "
    "positive confidence, or set the whole unsupported claim field to null. "
    "Do not null only its value, source, or confidence: a retained claim requires all three. "
    "Confidence=0 cannot justify retaining an unsupported nonempty value. "
    "Keep supported claims unchanged and do not invent support."
)


def _targeted_reference_repair(version: str = INTAKE_REFERENCE_REPAIR_VERSION) -> bool:
    """New histories use bounded feedback; old histories retain their retry bytes."""
    from temporalio import workflow

    return not workflow.in_workflow() or workflow.patched(version)


def _validate_atomic_intake(ctx: Any, output: AtomicFinding) -> ExtractedFinding:
    try:
        finding = reconstruct(ctx.deps.report_text, output)
    except ReferenceError as error:
        rule = error.rule if error.rule in {
            "source_unavailable", "unknown_source_id", "reversed_source_range"
        } else "invalid_reference"
        from pydantic_ai import ModelRetry

        feedback = f"Source reference violates its contract: {rule}"
        if (rule == "reversed_source_range" and type(error.field) is str
                and error.field in AtomicFinding.model_fields
                and _targeted_reference_repair()):
            feedback += (
                f". Fix only the source reference for claim '{error.field}': "
                "end_id must be at or after start_id in report source-line order. "
                "For a single source line, use end_id=null or end_id=start_id. "
                "Keep the supported claim value and confidence unchanged."
            )
        raise ModelRetry("Extraction violates its evidence contract:\n- " + feedback) from None
    from pydantic_ai import ModelRetry

    try:
        return validate_intake_evidence(ctx, finding)
    except ModelRetry as error:
        # Each new repair policy has its own marker; retained marker bytes stay intact.
        if ("\n- A literal line number is absent from its evidence quote." in error.message
                and _targeted_reference_repair(INTAKE_LITERAL_LINE_REPAIR_VERSION)):
            raise ModelRetry(error.message + _INTAKE_LITERAL_LINE_REPAIR) from None
        # The existing guard emits closed diagnostics; never interpolate claim/report data.
        if (any(f"\n- {problem}" in error.message for problem in _UNSUPPORTED_CLAIM_EVIDENCE_ERRORS)
                and _targeted_reference_repair(INTAKE_UNSUPPORTED_CLAIM_REPAIR_VERSION)):
            raise ModelRetry(error.message + _UNSUPPORTED_CLAIM_REPAIR) from None
        raise


def build_agent(
    name: str,
    overlay: Mapping[str, Any] | None = None,
    *,
    durable: bool = True,
    production_transport: bool | None = None,
    legacy_output_contract: bool = False,
    execution_name: str | None = None,
    spec_override: AgentSpec | None = None,
    atomic_output: bool | None = None,
    replay_only_model: bool = False,
) -> Agent[AgentDeps, Any]:
    """Build an agent with independently selected execution and transport layers.

    Evals execute outside Temporal, but their provider request contract must match production.
    ``production_transport=True`` selects production's reduced provider retry profile without
    attaching Temporal activities. Ordinary callers leave it unset, preserving the existing
    rule that durable execution owns transport retries.
    """
    if name not in AGENT_BINDINGS:
        raise KeyError(f"Unknown agent {name!r}")
    if name == "intake" and legacy_output_contract and spec_override is None:
        spec_override = retained_intake_spec()
    spec = load_spec(name, overlay, spec_override=spec_override)
    metadata = spec.metadata or {}
    intake_output = metadata.get("intake_output") or {}
    declared_atomic = name == "intake" and intake_output.get("protocol") == WIRE_VERSION
    use_atomic_output = declared_atomic if atomic_output is None else atomic_output
    if name == "intake" and use_atomic_output != declared_atomic:
        raise ValueError("Intake output mode must match the full spec's declared protocol")
    # A spec that cannot be governed must not become a running agent: owner, execution class,
    # risk tier, risk assessment, model policy, budget, skills, and toolsets are all required,
    # and the spec's risk tier must match its assessment's governance tier (§3).
    assert_governed(name, spec.metadata)
    _assert_execution_class_covers_tools(name, spec.metadata)
    _assert_tools_are_declared(name, spec)
    spec = _absolutize_skill_dirs(effective_spec(name, spec))
    transport = durable if production_transport is None else production_transport
    capabilities: list[Any] = [
        ResolveModelId(
            lambda ctx, model_id, _n=name, _d=transport, _a=use_atomic_output,
                   _r=replay_only_model: _resolve_agent_model(
                       _n, model_id, durable=_d, atomic_intake=_a, replay_only=_r, deps=ctx.deps
                   )
        )
    ]
    if model_factory.get_settings().model_mode == "live":
        cfg = model_factory.load_models_config()
        if cfg.backends[cfg.backend_for(name)].transport == "brokered":
            from infosec_harness.inference.identity import BrokerRequestIdentity
            capabilities.append(BrokerRequestIdentity())
    # Cross-cutting robustness, attached in code (see ALLOWED_CAPABILITIES note).
    if any(cap.name in {"RepoReadOnly", "SandboxShell"} for cap in spec.capabilities):
        capabilities.append(RepairToolArguments())
    metadata = spec.metadata or {}
    if name == "build-repair" and not legacy_output_contract:
        planning = PlanningWindow.from_metadata(metadata)
        if planning is None:
            raise ValueError("Current build repair requires its frozen planning window")
        capabilities.extend([planning.capability(), PlanningWindowTelemetry(planning)])
    if metadata.get("clear_tool_results"):
        capabilities.append(
            ClearToolResults(
                max_tokens=metadata.get("clear_tool_tokens", DEFAULT_CLEAR_TOOL_TOKENS)
            )
        )
    if durable:
        capabilities.append(
            TemporalDurability(
                model_activity_config=MODEL_ACTIVITY, toolset_activity_config=TOOL_ACTIVITY
            )
        )
    output_type = AtomicFinding if use_atomic_output else AGENT_BINDINGS[name]
    if not legacy_output_contract:
        if name == "partial-build":
            output_type = PartialEnvironmentOutput
        elif name == "context":
            output_type = ContextOutput
        elif name == "verdict":
            output_type = VERDICT_OUTPUTS
            capabilities.append(PrepareOutputTools(prepare_verdict_tools))
    agent = Agent.from_spec(
        spec,
        deps_type=AgentDeps,
        output_type=output_type,
        custom_capability_types=ALLOWED_CAPABILITIES,
        capabilities=capabilities,
        # Temporal derives model/tool activity identities from this name. Output-contract
        # revisions therefore need a distinct execution name; the logical name above still
        # owns model routing, governance, budgets, telemetry and persisted AgentOutcome data.
        name=execution_name or name,
        defer_model_check=True,
    )
    from infosec_harness.telemetry import private_instrumentation

    agent.instrument = private_instrumentation()
    if name == "verdict" and not legacy_output_contract:
        agent.instructions(verdict_contract_instructions)
    if name == "build-repair" and not legacy_output_contract:
        policy = resolve_agent_config(name, spec, durable=transport).effective_spec[
            "metadata"
        ]["output_validation"]
        agent.output_validator(bind_install_source_validator(tuple(policy["approved_hosts"])))
    if name == "intake" and not legacy_output_contract:
        if use_atomic_output:
            agent.output_validator(_validate_atomic_intake)
        else:
            agent.output_validator(validate_intake_evidence)
    for validator in OUTPUT_VALIDATORS.get(name, ()):
        agent.output_validator(validator)
    return agent


@lru_cache
def durable_agents() -> dict[str, Agent[AgentDeps, Any]]:
    """Current agents, with distinct Temporal identities for revised output contracts."""
    revised = {"partial-build", "context", "verdict", "build-repair", "intake"}
    return {
        name: build_agent(
            name,
            execution_name=(ATOMIC_EXECUTION_NAME if name == "intake" else
                            f"{name}-output-v2" if name in revised else None),
        )
        for name in AGENT_BINDINGS
    }


def quoted_intake_agent(*, durable: bool = True) -> Agent[AgentDeps, Any]:
    """Build retained 1.0.2 quote output with the v2 Temporal identity."""
    return build_agent(
        "intake", durable=durable, spec_override=retained_intake_spec(),
        atomic_output=False, replay_only_model=durable, execution_name=QUOTED_EXECUTION_NAME,
    )


@lru_cache
def legacy_output_agents() -> dict[str, Agent[AgentDeps, Any]]:
    """Original Temporal identities and parsers retained solely for history replay."""
    return {
        name: build_agent(
            name, legacy_output_contract=True,
            spec_override=retained_intake_spec() if name == "intake" else None,
            replay_only_model=(name == "intake"),
        )
        for name in ("partial-build", "context", "verdict", "build-repair", "intake")
    }


@lru_cache
def agent_usage_limits() -> dict[str, Any]:
    """Each agent's run budget as UsageLimits, resolved once on the host.

    TemporalOps needs these inside a workflow, where reading a spec from disk would be
    nondeterministic I/O, so they are computed at import like the config hashes.
    """
    from infosec_harness.agents.budgets import usage_limits_for

    return {name: usage_limits_for(name, load_spec(name).metadata) for name in AGENT_BINDINGS}


@lru_cache
def agent_config_hashes() -> dict[str, str]:
    return {name: config.digest for name, config in resolved_agent_configs().items()}


@lru_cache
def resolved_agent_configs() -> dict[str, ResolvedAgentConfig]:
    """Durable base configs loaded outside workflow execution."""
    return {
        name: resolve_agent_config(name, load_spec(name), durable=True) for name in AGENT_BINDINGS
    }


@lru_cache
def resolved_model_names() -> dict[str, str]:
    """Precomputed name per agent, so workflows avoid disk/config I/O at run time."""
    return {
        name: model_factory.resolved_model_name(name, load_spec(name).model or "sonnet")
        for name in AGENT_BINDINGS
    }


def spec_names_on_disk() -> set[str]:
    return {p.parent.name for p in get_settings().agents_dir.glob("*/agent.yaml")}


def validate_all() -> list[str]:
    """CI gate (`just agents-validate`): bindings <-> specs, allowlist, cache-safe prompts."""
    problems: list[str] = []
    on_disk = spec_names_on_disk()
    for missing in sorted(set(AGENT_BINDINGS) - on_disk):
        problems.append(f"{missing}: binding has no agents/{missing}/agent.yaml")
    for extra in sorted(on_disk - set(AGENT_BINDINGS)):
        problems.append(f"{extra}: agent.yaml has no binding in AGENT_BINDINGS")
    for name in sorted(on_disk & set(AGENT_BINDINGS)):
        try:
            spec = load_spec(name)
            instructions = (
                spec.instructions
                if isinstance(spec.instructions, list)
                else [spec.instructions or ""]
            )
            if any("{{" in str(i) for i in instructions):
                problems.append(
                    f"{name}: instructions must be static (no Handlebars templates, §6.2)"
                )
            if not spec.model:
                problems.append(f"{name}: spec must name a model tier")
            build_agent(name, durable=True)
        except Exception as e:  # noqa: BLE001 - report every broken spec
            problems.append(f"{name}: {type(e).__name__}: {e}")
    return problems


def json_schema() -> dict[str, Any]:
    return AgentSpec.model_json_schema_with_capabilities(ALLOWED_CAPABILITIES)
