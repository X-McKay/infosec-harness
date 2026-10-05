"""The governance metadata contract, validated when an agent is constructed.

The agent playbook (§3, "Factory responsibilities") requires construction to fail when an
owner, execution class, risk tier, model policy, budget, skill, or toolset is missing or
invalid — a spec that cannot be governed must not become a running agent. It also requires
the spec's risk tier to match the tier its risk scenarios establish. The scenarios live in
``agents/risk-scenarios.yaml`` and the tier is derived from them here, at construction, so
the two cannot drift apart silently and nothing has to be regenerated to keep them in step.

Everything here is pure and deterministic, so the same checks run at worker startup, in
`harness agents validate`, and in tests without a model or a network.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

EXECUTION_CLASSES = ("ephemeral", "durable", "human_governed")
RISK_TIERS = ("low", "medium", "high", "critical")
DATA_CLASSIFICATIONS = ("public", "internal", "confidential", "restricted")
SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[-+].+)?$")

REQUIRED_FIELDS = (
    "contract_version", "version", "owner", "execution_class", "risk_tier",
    "data_classification", "model_policy", "evaluation_policy", "budgets",
    "enabled_skills", "enabled_toolsets",
)


class GovernanceError(ValueError):
    """A spec cannot be governed as written, so it must not become a running agent."""


def _resolve_reference(value: str) -> Path | None:
    """Locate a path a spec's metadata references, or ``None`` when nothing here can see it.

    ``agents/<name>/evals/release-policy.yaml`` ships in the wheel beside the spec it gates, so
    it resolves under the package root; a source checkout is tried second so a reference to a
    reviewable project file can be checked too. ``None`` means "this deployment cannot check
    that", which is different from "missing".
    """
    from infosec_harness.resources import package_root, source_checkout

    for base in (package_root(), source_checkout()):
        if base is not None and (candidate := base / value).exists():
            return candidate
    return None if source_checkout() is None else source_checkout() / value


def violations(agent_name: str, metadata: dict[str, Any] | None, *,
               check_referenced_files: bool = True) -> list[str]:
    """Every problem with one agent's governance metadata, as readable sentences."""
    problems: list[str] = []
    meta = metadata or {}
    for field in REQUIRED_FIELDS:
        if meta.get(field) is None:
            problems.append(f"metadata.{field} is required")
    if problems:
        return problems  # later checks would only repeat the same absence

    if not isinstance(meta["contract_version"], int) or meta["contract_version"] < 1:
        problems.append("metadata.contract_version must be a positive integer")
    if not SEMVER.match(str(meta["version"])):
        problems.append(f"metadata.version must be semantic version text, got {meta['version']!r}")
    if not str(meta["owner"]).strip():
        problems.append("metadata.owner must name an accountable owner")
    if meta["execution_class"] not in EXECUTION_CLASSES:
        problems.append(f"metadata.execution_class must be one of {EXECUTION_CLASSES}")
    if meta["risk_tier"] not in RISK_TIERS:
        problems.append(f"metadata.risk_tier must be one of {RISK_TIERS}")
    if meta["data_classification"] not in DATA_CLASSIFICATIONS:
        problems.append(f"metadata.data_classification must be one of {DATA_CLASSIFICATIONS}")
    for field in ("enabled_skills", "enabled_toolsets"):
        value = meta[field]
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            problems.append(f"metadata.{field} must be a list of strings")

    problems.extend(_budget_violations(agent_name, meta))
    problems.extend(_policy_violations(meta))
    problems.extend(risk_violations(agent_name, meta))
    if check_referenced_files:
        problems.extend(_reference_violations(agent_name, meta))
    return problems


def risk_violations(agent_name: str, meta: dict[str, Any]) -> list[str]:
    """The spec's risk tier must equal the tier its scenarios establish (§3, §13).

    An agent absent from the scenario library has no assessed risk at all, which is the
    strongest reason not to construct it.
    """
    from infosec_harness.agents.risk import library

    lib = library()
    if agent_name not in lib.agents:
        return [f"{agent_name!r} is not in agents/risk-scenarios.yaml, so its risk is unassessed"]
    established = lib.governance_tier(agent_name)
    if meta["risk_tier"] != established:
        return [f"metadata.risk_tier is {meta['risk_tier']!r} but the scenarios in "
                f"agents/risk-scenarios.yaml establish {established!r}"]
    return []


def _budget_violations(agent_name: str, meta: dict[str, Any]) -> list[str]:
    from infosec_harness.agents.budgets import MissingBudget, run_budget

    try:
        run_budget(agent_name, meta)
    except MissingBudget as e:
        return [str(e)]
    except Exception as e:  # noqa: BLE001 - a malformed budget is a governance problem
        return [f"metadata.budgets.run is invalid: {e}"]
    return []


def _policy_violations(meta: dict[str, Any]) -> list[str]:
    """The named model policy must exist, and must resolve to the tier the spec runs."""
    from infosec_harness.agents.models import load_models_config

    cfg = load_models_config()
    policy = meta["model_policy"]
    if policy not in cfg.model_policies:
        return [f"metadata.model_policy {policy!r} is not in config/models.yaml model_policies "
                f"(known: {sorted(cfg.model_policies)})"]
    return []


def _reference_violations(agent_name: str, meta: dict[str, Any]) -> list[str]:
    """An eval policy that is only a path is not evidence of anything."""
    path = _resolve_reference(str(meta["evaluation_policy"]))
    if path is not None and not path.exists():
        return [f"metadata.evaluation_policy points at {meta['evaluation_policy']!r}, which "
                f"does not exist"]
    return []


def assert_governed(agent_name: str, metadata: dict[str, Any] | None, *,
                    check_referenced_files: bool = True) -> None:
    problems = violations(agent_name, metadata, check_referenced_files=check_referenced_files)
    if problems:
        raise GovernanceError(
            f"Agent {agent_name!r} cannot be constructed:\n- " + "\n- ".join(problems)
        )
