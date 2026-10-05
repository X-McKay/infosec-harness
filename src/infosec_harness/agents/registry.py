"""Agent loader (§6, D17): every agent is one pydantic-ai Agent Spec ``agents/<name>/agent.yaml``.

What stays in code: typed I/O bindings, the capability allowlist, the tier -> model
resolver, and output validators. Everything else (prompt, model tier, model settings,
retries, skills, tools) is data in the spec.
"""

from __future__ import annotations

import copy
import hashlib
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
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

from infosec_harness.agents import governance
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
from infosec_harness.agents.intake_evidence import INTAKE_EVIDENCE_POLICY_VERSION
from infosec_harness.agents.outputs import (
    VERDICT_OUTPUTS,
    ContextOutput,
    PartialEnvironmentOutput,
    PlannedEnvironmentOutput,
    prepare_verdict_tools,
    verdict_contract_instructions,
)
from infosec_harness.agents.planning_window import PlanningWindow, PlanningWindowTelemetry
from infosec_harness.agents.validators import (
    OutputValidator,
    bind_install_source_validator,
    validate_environment_spec,
    validate_intake_evidence,
    validate_partial_build_scope,
    validate_probe,
    validate_verdict,
)
from infosec_harness.domain.canonical import digest as canonical_digest
from infosec_harness.domain.models import (
    EnvironmentSpec,
    ExtractedFinding,
    FindingContext,
    ProbeDiagnosis,
    ProbePlan,
    ProbeSource,
    RepoProfile,
    Verdict,
)
from infosec_harness.resources import package_root
from infosec_harness.sandbox.install_sources import install_source_policy
from infosec_harness.settings import get_settings

os.environ.setdefault("PYDANTIC_AI_NO_BANNER", "1")

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
        return canonical_digest(self.model_dump(mode="json"))[:16]

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
        return canonical_digest(payload)[:16]

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


def load_spec(name: str, overlay: Mapping[str, Any] | None = None) -> AgentSpec:
    spec = AgentSpec.from_file(spec_path(name))
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



def _spec_tier(name: str, spec: AgentSpec) -> str:
    """The model tier a spec runs. There is no default: an unnamed tier is a broken spec."""
    if not spec.model:
        raise GovernanceError(f"Agent {name!r} spec must name a model tier")
    return str(spec.model)


def resolve_agent_config(
    name: str,
    spec: AgentSpec,
    *,
    source_files: int | None = None,
    durable: bool = False,
) -> ResolvedAgentConfig:
    """Resolve the same effective settings and limits an invocation will receive."""
    binding = binding_for(name)
    effective = _apply_backend_token_floor(name, spec)
    model = model_factory.resolve_config(
        name,
        _spec_tier(name, effective),
        model_settings=dict(spec.model_settings or {}),
        durable=durable,
        atomic_intake=binding.atomic_intake,
    )
    budget = resolve_budget(
        name,
        effective.metadata,
        source_files=source_files,
        provider_output_floor=model.provider_output_floor,
    )
    effective_spec = effective.model_dump(by_alias=True, exclude_none=True, mode="json")
    if binding.output_validation is not None:
        # Host-resolved acceptance policy, recorded in the digest it governs.
        effective_spec.setdefault("metadata", {})["output_validation"] = binding.output_validation()
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

    The backend-level half of this lives in ``CompatOpenAIChatModel.prepare_request``, which
    raises the cap on the outgoing payload. That is not enough on its own: pydantic-ai copies
    ``model_settings['max_tokens']`` into ``GraphAgentState.last_max_tokens`` when it builds
    the request, *before* the model's ``prepare_request`` runs, and that copy is the number
    reported by "Model token limit (N) exceeded before any response was generated". Applying
    the floor here as well keeps the two in agreement, so a diagnostic names the cap that was
    actually sent instead of the spec value that was superseded.

    A zero floor (Bedrock, where thinking has its own budget) is a no-op, so this changes
    nothing for the default backend. See :func:`models.max_tokens_floor`.
    """
    floored = model_factory.apply_max_tokens_floor(
        dict(spec.model_settings or {}), model_factory.max_tokens_floor(name)
    )
    if floored == (spec.model_settings or {}):
        return spec
    return spec.model_copy(update={"model_settings": floored})


def effective_spec(name: str, spec: AgentSpec) -> AgentSpec:
    """Apply backend adjustments visible to PydanticAI before building an agent."""
    return _apply_backend_token_floor(name, spec)



# Capability name -> the toolset policy (tools/<id>/tool.yaml) that governs it.
TOOLSET_CAPABILITIES: dict[str, str] = {
    "RepoReadOnly": "repo-read-only",
    "SandboxShell": "sandbox-shell",
}


def _capability_toolsets(spec: AgentSpec) -> list[str]:
    return [TOOLSET_CAPABILITIES[cap.name] for cap in spec.capabilities
            if cap.name in TOOLSET_CAPABILITIES]


def _capability_skills(spec: AgentSpec) -> set[str]:
    """The skill names a spec's Skills capabilities can load."""
    names: set[str] = set()
    for cap in spec.capabilities:
        if cap.name != "Skills":
            continue
        args = dict(cap.kwargs or {})
        include = args.get("include")
        if include:
            names.update(include)
            continue
        dirs = args.get("directories") or (cap.args[0] if cap.args else "skills")
        for d in [dirs] if isinstance(dirs, str) else dirs:
            names.update(p.parent.name for p in _abs(d).glob("*/SKILL.md"))
    return names


def _resolve_agent_model(
    name: str, tier: str, *, durable: bool, atomic_intake: bool, deps: AgentDeps | None = None,
):
    broker = ({"broker_binding": deps.broker_binding, "broker_contract": deps.broker_contract}
              if deps is not None and deps.broker_binding else {})
    resolver = model_factory.resolve_intake_atomic if atomic_intake else model_factory.resolve
    return resolver(name, tier, durable=durable, **broker)


_INTAKE_LITERAL_LINE_REPAIR = (
    "\nFix only unsupported start_line or end_line claims: report source IDs and report-line "
    "positions are not code line numbers. A retained code line claim needs its number "
    "literally stated in the referenced report text. Otherwise set the whole unsupported "
    "start_line or end_line claim to null, including its value, source and confidence. "
    "Keep other supported claims unchanged; do not invent a code line or supporting text."
)
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


def _reference_feedback(error: ReferenceError) -> str:
    """Closed repair feedback: authored field names and rule names only, never report data."""
    if len(error.failures) > 1:
        failures = ", ".join(f"{field}={problem}" for field, problem in error.failures)
        return (
            "Extraction violates its evidence contract:\n- Source references violate "
            f"their contract: {failures}. Fix only these source references: "
            "end_id must be at or after start_id in report source-line order; "
            "for one source line use end_id=null or end_id=start_id. "
            "For unknown_source_id, cite an existing report source ID. "
            "Keep supported claim values and confidence unchanged; do not invent support."
        )
    feedback = f"Source reference violates its contract: {error.rule}"
    if error.rule == "reversed_source_range" and error.field is not None:
        feedback += (
            f". Fix only the source reference for claim '{error.field}': "
            "end_id must be at or after start_id in report source-line order. "
            "For a single source line, use end_id=null or end_id=start_id. "
            "Keep the supported claim value and confidence unchanged."
        )
    return "Extraction violates its evidence contract:\n- " + feedback


def _validate_atomic_intake(ctx: Any, output: AtomicFinding) -> ExtractedFinding:
    from pydantic_ai import ModelRetry

    try:
        finding = reconstruct(ctx.deps.report_text, output)
    except ReferenceError as error:
        raise ModelRetry(_reference_feedback(error)) from None
    try:
        return validate_intake_evidence(ctx, finding)
    except ModelRetry as error:
        # The guard emits closed diagnostics; never interpolate claim/report data here.
        if "\n- A literal line number is absent from its evidence quote." in error.message:
            raise ModelRetry(error.message + _INTAKE_LITERAL_LINE_REPAIR) from None
        if any(f"\n- {problem}" in error.message for problem in _UNSUPPORTED_CLAIM_EVIDENCE_ERRORS):
            raise ModelRetry(error.message + _UNSUPPORTED_CLAIM_REPAIR) from None
        raise


def _install_source_validator(config: ResolvedAgentConfig) -> OutputValidator:
    policy = config.effective_spec["metadata"]["output_validation"]
    return bind_install_source_validator(tuple(policy["approved_hosts"]))


def _planning_window(spec: AgentSpec) -> list[Any]:
    planning = PlanningWindow.from_metadata(spec.metadata or {})
    if planning is None:
        raise ValueError("Build repair requires its frozen planning window")
    return [planning.capability(), PlanningWindowTelemetry(planning)]


def _intake_output_validation() -> dict[str, str]:
    return {"version": INTAKE_EVIDENCE_POLICY_VERSION, "wire_version": WIRE_VERSION}


def _install_source_policy() -> dict[str, Any]:
    # Operator configuration is resolved on the host, never from repository content.
    return install_source_policy(get_settings().default_registry_allowlist)


@dataclass(frozen=True)
class AgentBinding:
    """Everything about one agent that stays in code rather than in its spec.

    ``domain_type`` is what the graph consumes and persistence records; ``output_type`` is what
    the model is asked to emit when the two differ (a narrower or union wire contract that a
    validator converts). Hooks are declarative so ``build_agent`` has no per-name branches.
    """

    domain_type: type[BaseModel]
    output_type: Any = None
    validators: tuple[OutputValidator, ...] = ()
    config_validators: tuple[Callable[[ResolvedAgentConfig], OutputValidator], ...] = ()
    instructions: tuple[Callable[..., str], ...] = ()
    capabilities: Callable[[AgentSpec], list[Any]] | None = None
    output_validation: Callable[[], dict[str, Any]] | None = None
    atomic_intake: bool = False

    @property
    def model_output_type(self) -> Any:
        return self.domain_type if self.output_type is None else self.output_type


BINDINGS: dict[str, AgentBinding] = {
    "intake": AgentBinding(
        ExtractedFinding, output_type=AtomicFinding, validators=(_validate_atomic_intake,),
        output_validation=_intake_output_validation, atomic_intake=True),
    "recon": AgentBinding(RepoProfile),
    "env-planner": AgentBinding(
        EnvironmentSpec, output_type=PlannedEnvironmentOutput,
        validators=(validate_environment_spec,)),
    "build-repair": AgentBinding(
        EnvironmentSpec, validators=(validate_environment_spec,),
        config_validators=(_install_source_validator,), capabilities=_planning_window,
        output_validation=_install_source_policy),
    "partial-build": AgentBinding(
        EnvironmentSpec, output_type=PartialEnvironmentOutput,
        validators=(validate_environment_spec, validate_partial_build_scope)),
    "context": AgentBinding(FindingContext, output_type=ContextOutput),
    "probe-planner": AgentBinding(ProbePlan),
    "probe-author": AgentBinding(ProbeSource, validators=(validate_probe,)),
    "probe-diagnosis": AgentBinding(ProbeDiagnosis),
    "probe-repair": AgentBinding(ProbeSource, validators=(validate_probe,)),
    "verdict": AgentBinding(
        Verdict, output_type=VERDICT_OUTPUTS, validators=(validate_verdict,),
        instructions=(verdict_contract_instructions,),
        capabilities=lambda _spec: [PrepareOutputTools(prepare_verdict_tools)]),
}

# name -> domain output type. Every agents/<name>/agent.yaml must appear here and vice versa.
AGENT_BINDINGS: dict[str, type[BaseModel]] = {name: b.domain_type for name, b in BINDINGS.items()}

# Temporal derives model/tool activity identities from the agent's name. Bumping this retires
# every recorded activity identity at once: histories from an earlier generation are not
# replayable by design and must be retried as new workflows.
EXECUTION_GENERATION = "v6"


def binding_for(name: str) -> AgentBinding:
    try:
        return BINDINGS[name]
    except KeyError:
        raise KeyError(f"Unknown agent {name!r}") from None


def execution_name(name: str) -> str:
    """The durable (Temporal activity) identity of an agent in this execution generation."""
    binding_for(name)
    return f"{name}-{EXECUTION_GENERATION}"


def _assert_intake_protocol(name: str, spec: AgentSpec) -> None:
    """The intake spec must declare exactly the one wire protocol and identity this code runs."""
    intake_output = (spec.metadata or {}).get("intake_output") or {}
    if intake_output.get("protocol") != WIRE_VERSION:
        raise GovernanceError(f"Agent {name!r} must declare intake_output.protocol {WIRE_VERSION}")
    if intake_output.get("execution") != execution_name(name):
        raise GovernanceError(
            f"Agent {name!r} intake_output.execution must be {execution_name(name)!r}")


def build_agent(
    name: str,
    overlay: Mapping[str, Any] | None = None,
    *,
    durable: bool = True,
    production_transport: bool | None = None,
) -> Agent[AgentDeps, Any]:
    """Build an agent with independently selected execution and transport layers.

    Evals execute outside Temporal, but their provider request contract must match production.
    ``production_transport=True`` selects production's reduced provider retry profile without
    attaching Temporal activities. Ordinary callers leave it unset, preserving the existing
    rule that durable execution owns transport retries.
    """
    binding = binding_for(name)
    spec = load_spec(name, overlay)
    # A spec that cannot be governed must not become a running agent: owner, execution class,
    # risk tier, risk assessment, model policy, budget, skills, and toolsets are all required,
    # and the spec's risk tier must match its assessment's governance tier (§3).
    assert_governed(name, spec.metadata)
    governance.assert_tools_are_declared(
        name, [(cap.kwargs or {}).get("tools") for cap in spec.capabilities
               if cap.name == "RepoReadOnly"])
    toolsets = _capability_toolsets(spec)
    governance.assert_capabilities_match_metadata(
        name, spec.metadata, toolsets=toolsets, skills=_capability_skills(spec))
    governance.assert_execution_class_covers_tools(name, spec.metadata, toolsets)
    if overlay is None:
        governance.assert_model_policy(name, spec.metadata, _spec_tier(name, spec))
    if binding.atomic_intake:
        _assert_intake_protocol(name, spec)
    spec = _absolutize_skill_dirs(effective_spec(name, spec))
    transport = durable if production_transport is None else production_transport
    capabilities: list[Any] = [
        ResolveModelId(
            lambda ctx, model_id, _n=name, _d=transport, _a=binding.atomic_intake:
                _resolve_agent_model(_n, model_id, durable=_d, atomic_intake=_a, deps=ctx.deps)
        )
    ]
    if model_factory.get_settings().model_mode == "live":
        cfg = model_factory.load_models_config()
        if cfg.backends[cfg.backend_for(name)].transport == "brokered":
            from infosec_harness.inference.identity import BrokerRequestIdentity
            capabilities.append(BrokerRequestIdentity())
    # Cross-cutting robustness, attached in code (see ALLOWED_CAPABILITIES note).
    if _capability_toolsets(spec):
        capabilities.append(RepairToolArguments())
    if binding.capabilities is not None:
        capabilities.extend(binding.capabilities(spec))
    metadata = spec.metadata or {}
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
    agent = Agent.from_spec(
        spec,
        deps_type=AgentDeps,
        output_type=binding.model_output_type,
        custom_capability_types=ALLOWED_CAPABILITIES,
        capabilities=capabilities,
        # The logical name still owns model routing, governance, budgets, telemetry and the
        # persisted AgentOutcome; only the durable activity identity carries the generation.
        name=execution_name(name) if durable else name,
        defer_model_check=True,
    )
    from infosec_harness.telemetry import private_instrumentation

    agent.instrument = private_instrumentation()
    for instructions in binding.instructions:
        agent.instructions(instructions)
    if binding.config_validators:
        config = resolve_agent_config(name, spec, durable=transport)
        for factory in binding.config_validators:
            agent.output_validator(factory(config))
    for validator in binding.validators:
        agent.output_validator(validator)
    return agent


@lru_cache
def durable_agents() -> dict[str, Agent[AgentDeps, Any]]:
    """Every current agent, built once with its durable execution identity."""
    return {name: build_agent(name) for name in BINDINGS}


@lru_cache
def agent_usage_limits() -> dict[str, Any]:
    """Each agent's run budget as UsageLimits, resolved once on the host."""
    from infosec_harness.agents.budgets import usage_limits_for

    return {name: usage_limits_for(name, load_spec(name).metadata) for name in BINDINGS}


@lru_cache
def agent_config_hashes() -> dict[str, str]:
    return {name: config.digest for name, config in resolved_agent_configs().items()}


@lru_cache
def resolved_agent_configs() -> dict[str, ResolvedAgentConfig]:
    """Durable base configs loaded outside workflow execution."""
    return {name: resolve_agent_config(name, load_spec(name), durable=True) for name in BINDINGS}


@lru_cache
def resolved_model_names() -> dict[str, str]:
    """The concrete model each agent resolves to, from its resolved configuration."""
    return {name: config.model.resolved_model for name, config in resolved_agent_configs().items()}


def spec_names_on_disk() -> set[str]:
    return {p.parent.name for p in get_settings().agents_dir.glob("*/agent.yaml")}


def validate_all() -> list[str]:
    """CI gate (`just agents-validate`): bindings <-> specs, allowlist, cache-safe prompts."""
    problems: list[str] = []
    on_disk = spec_names_on_disk()
    for missing in sorted(set(BINDINGS) - on_disk):
        problems.append(f"{missing}: binding has no agents/{missing}/agent.yaml")
    for extra in sorted(on_disk - set(BINDINGS)):
        problems.append(f"{extra}: agent.yaml has no binding in BINDINGS")
    for name in sorted(on_disk & set(BINDINGS)):
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
            build_agent(name, durable=True)
        except Exception as e:  # noqa: BLE001 - report every broken spec
            problems.append(f"{name}: {type(e).__name__}: {e}")
    return problems


def json_schema() -> dict[str, Any]:
    return AgentSpec.model_json_schema_with_capabilities(ALLOWED_CAPABILITIES)
