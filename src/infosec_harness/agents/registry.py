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
from pydantic_ai.capabilities import ResolveModelId
from pydantic_ai.durable_exec.temporal import TemporalDurability
from pydantic_ai_harness.compaction import ClearToolResults
from pydantic_ai_harness.repair_tool_arguments import RepairToolArguments
from pydantic_ai_harness.skills import Skills
from pydantic_ai_harness.warn_on_cache_busts import WarnOnCacheBusts
from temporalio.workflow import ActivityConfig

from infosec_harness.agents import models as model_factory
from infosec_harness.agents.capabilities import CUSTOM_CAPABILITIES
from infosec_harness.agents.deps import AgentDeps
from infosec_harness.agents.validators import OUTPUT_VALIDATORS
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
from infosec_harness.settings import get_settings

os.environ.setdefault("PYDANTIC_AI_NO_BANNER", "1")

# name -> output type. Every agents/<name>/agent.yaml must appear here and vice versa.
AGENT_BINDINGS: dict[str, type[BaseModel]] = {
    "intake": ExtractedFinding,
    "recon": RepoProfile,
    "env_planner": EnvironmentSpec,
    "build_repair": EnvironmentSpec,
    "partial_build": EnvironmentSpec,
    "context": FindingContext,
    "probe_planner": ProbePlan,
    "probe_author": ProbeSource,
    "probe_diagnosis": ProbeDiagnosis,
    "probe_repair": ProbeSource,
    "verdict": Verdict,
}

# Only these capability types may be named in a spec (cf. pydantic-ai #5473/#8426).
# Harness capabilities that aren't Temporal-safe yet (ToolOutputLimits) or need extra
# dependencies (PromptInjectionDefender) are intentionally absent.
ALLOWED_CAPABILITIES = (*CUSTOM_CAPABILITIES, Skills, WarnOnCacheBusts, RepairToolArguments, ClearToolResults)

# Model calls can be slow; tool calls are fast except the sandbox shell.
MODEL_ACTIVITY = ActivityConfig(start_to_close_timeout=timedelta(minutes=10))
TOOL_ACTIVITY = {"sandbox_shell": ActivityConfig(start_to_close_timeout=timedelta(minutes=5))}


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
    p = Path(path)
    return p if p.is_absolute() else (get_settings().agents_dir.parent / p)


def config_hash(name: str, spec: AgentSpec) -> str:
    """Agent config identity (§6): effective spec + skill contents + resolved model."""
    tier = spec.model or "sonnet"
    payload = {
        "spec": spec.model_dump(by_alias=True, exclude_none=True, mode="json"),
        "skills": _skills_hash(spec),
        "model": model_factory.resolved_model_name(name, tier),
    }
    return hashlib.sha256(canonical_json(payload).encode()).hexdigest()[:16]


def _absolutize_skill_dirs(spec: AgentSpec) -> AgentSpec:
    """Skill directories in specs are repo-relative; make them absolute for the worker."""
    data = spec.model_dump(by_alias=True, exclude_none=True, mode="json")
    for cap in data.get("capabilities", []):
        if isinstance(cap, dict) and "Skills" in cap and isinstance(cap["Skills"], dict):
            dirs = cap["Skills"].get("directories", "skills")
            cap["Skills"]["directories"] = (
                str(_abs(dirs)) if isinstance(dirs, str) else [str(_abs(d)) for d in dirs]
            )
    return AgentSpec.from_dict(data)


def build_agent(name: str, overlay: Mapping[str, Any] | None = None, *, durable: bool = True) -> Agent[AgentDeps, Any]:
    if name not in AGENT_BINDINGS:
        raise KeyError(f"Unknown agent {name!r}")
    spec = _absolutize_skill_dirs(load_spec(name, overlay))
    capabilities: list[Any] = [ResolveModelId(lambda ctx, model_id, _n=name: model_factory.resolve(_n, model_id))]
    if durable:
        capabilities.append(TemporalDurability(model_activity_config=MODEL_ACTIVITY,
                                               toolset_activity_config=TOOL_ACTIVITY))
    agent = Agent.from_spec(
        spec,
        deps_type=AgentDeps,
        output_type=AGENT_BINDINGS[name],
        custom_capability_types=ALLOWED_CAPABILITIES,
        capabilities=capabilities,
        name=name,
        defer_model_check=True,
    )
    for validator in OUTPUT_VALIDATORS.get(name, ()):
        agent.output_validator(validator)
    return agent


@lru_cache
def durable_agents() -> dict[str, Agent[AgentDeps, Any]]:
    """Baseline agents, built once at worker import and registered with Temporal."""
    return {name: build_agent(name) for name in AGENT_BINDINGS}


@lru_cache
def agent_config_hashes() -> dict[str, str]:
    return {name: config_hash(name, load_spec(name)) for name in AGENT_BINDINGS}


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
            instructions = spec.instructions if isinstance(spec.instructions, list) else [spec.instructions or ""]
            if any("{{" in str(i) for i in instructions):
                problems.append(f"{name}: instructions must be static (no Handlebars templates, §6.2)")
            if not spec.model:
                problems.append(f"{name}: spec must name a model tier")
            build_agent(name, durable=True)
        except Exception as e:  # noqa: BLE001 - report every broken spec
            problems.append(f"{name}: {type(e).__name__}: {e}")
    return problems


def json_schema() -> dict[str, Any]:
    return AgentSpec.model_json_schema_with_capabilities(ALLOWED_CAPABILITIES)
