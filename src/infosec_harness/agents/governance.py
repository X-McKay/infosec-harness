"""The governance metadata contract, validated when an agent is constructed.

The agent playbook (§3, "Factory responsibilities") requires construction to fail when an
owner, execution class, risk tier, risk assessment, model policy, budget, skill, or toolset
is missing or invalid — a spec that cannot be governed must not become a running agent. It
also requires the spec's risk tier to match the tier recorded in its risk assessment, so
the two artifacts cannot drift apart silently.

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
    "risk_assessment", "data_classification", "model_policy", "evaluation_policy", "budgets",
    "enabled_skills", "enabled_toolsets",
)


class GovernanceError(ValueError):
    """A spec cannot be governed as written, so it must not become a running agent."""


def _resolve_reference(value: str) -> Path | None:
    """Locate a path a spec's metadata references, or ``None`` when nothing here can see it.

    Two bases are legitimate, and which one holds a given reference is a packaging decision
    rather than something the spec should have to spell out:

    * ``agents/<name>/evals/release-policy.yaml`` ships in the wheel beside the spec it gates,
      so it resolves under the package root.
    * ``docs/risk-assessments/<name>.yaml`` is a reviewable project file that is deliberately
      not packaged, so it resolves only in a source checkout.

    ``None`` means "this deployment cannot check that", which is different from "missing". On
    an installed wheel the docs tree is absent by design; treating that as a governance
    violation would make every agent unconstructible in production for a reason that is purely
    an artifact of where reviewers keep their files.
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
    if check_referenced_files:
        problems.extend(_reference_violations(agent_name, meta))
    return problems


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
    """A risk assessment or eval policy that is only a path is not evidence of anything."""
    problems = []
    for field in ("risk_assessment", "evaluation_policy"):
        path = _resolve_reference(str(meta[field]))
        if path is not None and not path.exists():
            problems.append(f"metadata.{field} points at {meta[field]!r}, which does not exist")
    return problems


def assert_governed(agent_name: str, metadata: dict[str, Any] | None, *,
                    check_referenced_files: bool = True) -> None:
    problems = violations(agent_name, metadata, check_referenced_files=check_referenced_files)
    if problems:
        raise GovernanceError(
            f"Agent {agent_name!r} cannot be constructed:\n- " + "\n- ".join(problems)
        )


def tier_matches_assessment(agent_name: str, metadata: dict[str, Any]) -> list[str]:
    """The spec's risk tier must equal the governance tier its assessment records."""
    import yaml

    path = _resolve_reference(str(metadata["risk_assessment"]))
    if path is None:
        return [f"risk assessment {metadata['risk_assessment']!r} cannot be read here: risk "
                f"assessments are project files and are not packaged, so this check needs a "
                f"source checkout"]
    if not path.exists():
        return [f"risk assessment {metadata['risk_assessment']!r} does not exist"]
    assessment = yaml.safe_load(path.read_text()) or {}
    classification = assessment.get("classification") or {}
    declared = classification.get("governance_tier")
    if declared is None:
        return [f"risk assessment {path.name} records no classification.governance_tier"]
    if declared != metadata["risk_tier"]:
        return [f"metadata.risk_tier is {metadata['risk_tier']!r} but "
                f"{path.name} records governance_tier {declared!r}"]
    subject = (assessment.get("assessment") or {}).get("agent")
    if subject not in (None, agent_name):
        return [f"risk assessment {path.name} is for {subject!r}, not {agent_name!r}"]
    return []
