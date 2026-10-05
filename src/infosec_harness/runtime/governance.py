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
from collections.abc import Collection, Iterable
from typing import Any

from infosec_harness.runtime.risk import TIER_ORDER as RISK_TIERS
from infosec_harness.tools.policies import EXECUTION_CLASS_ORDER as EXECUTION_CLASSES

DATA_CLASSIFICATIONS = ("public", "internal", "confidential", "restricted")
SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[-+].+)?$")

REQUIRED_FIELDS = (
    "contract_version", "version", "owner", "execution_class", "risk_tier",
    "data_classification", "model_policy", "evaluation_policy", "budgets",
    "enabled_skills", "enabled_toolsets",
)


class GovernanceError(ValueError):
    """A spec cannot be governed as written, so it must not become a running agent."""


def violations(agent_name: str, metadata: dict[str, Any] | None, *,
               tier: str | None) -> list[str]:
    """Every problem with one agent's governance metadata, as readable sentences.

    ``tier`` is the model tier the committed spec runs, which its model policy must resolve to.
    None only for an experiment overlay, which may substitute a model (that is what a model
    sweep is) and is recorded as overlay provenance; the policy must still exist.
    """
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
    problems.extend(_policy_violations(meta, tier))
    problems.extend(risk_violations(agent_name, meta))
    problems.extend(_reference_violations(meta))
    return problems


def risk_violations(agent_name: str, meta: dict[str, Any]) -> list[str]:
    """The spec's risk tier must equal the tier its scenarios establish (§3, §13).

    An agent absent from the scenario library has no assessed risk at all, which is the
    strongest reason not to construct it.
    """
    from infosec_harness.runtime.risk import library

    lib = library()
    if agent_name not in lib.agents:
        return [f"{agent_name!r} is not in agents/risk-scenarios.yaml, so its risk is unassessed"]
    established = lib.governance_tier(agent_name)
    if meta["risk_tier"] != established:
        return [f"metadata.risk_tier is {meta['risk_tier']!r} but the scenarios in "
                f"agents/risk-scenarios.yaml establish {established!r}"]
    return []


def _budget_violations(agent_name: str, meta: dict[str, Any]) -> list[str]:
    from infosec_harness.runtime.budgets import MissingBudget, run_budget

    try:
        run_budget(agent_name, meta)
    except MissingBudget as e:
        return [str(e)]
    except Exception as e:  # noqa: BLE001 - a malformed budget is a governance problem
        return [f"metadata.budgets.run is invalid: {e}"]
    return []


def _policy_violations(meta: dict[str, Any], tier: str | None) -> list[str]:
    """The named model policy must exist and, for a committed spec, resolve to its tier."""
    from infosec_harness.inference.models import load_models_config

    policies = load_models_config().model_policies
    policy = meta["model_policy"]
    if policy not in policies:
        return [f"metadata.model_policy {policy!r} is not in config/models.yaml model_policies "
                f"(known: {sorted(policies)})"]
    if tier is not None and policies[policy] != tier:
        return [f"metadata.model_policy {policy!r} resolves to {policies[policy]!r}, not the "
                f"spec's model tier {tier!r}"]
    return []


def _reference_violations(meta: dict[str, Any]) -> list[str]:
    """The release policy ships in the package beside the spec it gates, so it must be there.

    Resolved against the package root only, and confined to it: a reference this deployment
    cannot see is a missing policy, never a check skipped.
    """
    from infosec_harness.resources import package_root

    reference = str(meta["evaluation_policy"])
    root = package_root().resolve()
    candidate = (root / reference).resolve()
    if not candidate.is_relative_to(root) or not candidate.is_file():
        return [f"metadata.evaluation_policy points at {reference!r}, which is not a file in "
                f"the package"]
    return []


def assert_capabilities_match_metadata(name: str, metadata: dict[str, Any] | None, *,
                                       toolsets: Collection[str],
                                       skills: Collection[str]) -> None:
    """Governance metadata must describe the capabilities the agent actually has.

    ``enabled_toolsets`` and ``enabled_skills`` are what a reviewer reads and what the execution
    class is judged against; a capability reachable from the spec but absent from them is
    governed by nothing. Every toolset name must have a declared policy.
    """
    from infosec_harness.tools.policies import load_policies

    meta = metadata or {}
    policies = load_policies()
    declared_toolsets = list(meta.get("enabled_toolsets") or [])
    unknown = sorted(set(declared_toolsets) - set(policies))
    if unknown:
        raise GovernanceError(
            f"Agent {name!r} enables toolsets with no declared policy: {unknown}; "
            f"known: {sorted(policies)}")
    if set(declared_toolsets) != set(toolsets):
        raise GovernanceError(
            f"Agent {name!r} metadata.enabled_toolsets {sorted(declared_toolsets)} does not match "
            f"its capabilities {sorted(toolsets)}")
    declared_skills = set(meta.get("enabled_skills") or [])
    if declared_skills != set(skills):
        raise GovernanceError(
            f"Agent {name!r} metadata.enabled_skills {sorted(declared_skills)} does not match "
            f"its Skills capabilities {sorted(skills)}")


def assert_execution_class_covers_tools(name: str, metadata: dict[str, Any] | None,
                                        toolsets: Collection[str]) -> None:
    """An agent's execution class must be at least what its most consequential tool requires.

    This is the rule that makes an execution class mean something: `sandbox-shell` executes
    code, so any agent enabling it is at least `durable`. The requirement is derived from the
    capabilities the spec actually attaches, not from what its metadata claims. Declaring a
    stronger class is fine; declaring a weaker one is not.
    """
    from infosec_harness.tools.policies import required_execution_class

    declared = (metadata or {}).get("execution_class")
    required = required_execution_class(list(toolsets))
    if EXECUTION_CLASSES.index(declared) < EXECUTION_CLASSES.index(required):
        raise GovernanceError(
            f"Agent {name!r} declares execution_class {declared!r} but its capabilities "
            f"require at least {required!r}"
        )


def assert_tools_are_declared(name: str, selections: Iterable[Collection[str] | None]) -> None:
    """Every repo tool an agent can call must appear in the toolset's own policy.

    The policy in `tools/repo-read-only/tool.yaml` is what the execution class is judged
    against and what a reviewer reads; a tool reachable from a spec but absent from it is
    governed by nothing. ``selections`` are the spec's `RepoReadOnly(tools=[...])` arguments
    (None: the default surface); an unknown name fails in ``selected_repo_tools``, the one
    place the selection is validated.
    """
    from infosec_harness.runtime.capabilities import selected_repo_tools
    from infosec_harness.tools.policies import load_policies

    declared = {t.name for t in load_policies()["repo-read-only"].tools}
    for tools in selections:
        try:
            selected = selected_repo_tools(tools)
        except ValueError as e:
            raise GovernanceError(f"Agent {name!r}: {e}") from None
        undeclared = sorted(set(selected) - declared)
        if undeclared:
            raise GovernanceError(
                f"Agent {name!r} can call repo tools that tools/repo-read-only/tool.yaml does "
                f"not declare: {undeclared}"
            )


def assert_governed(agent_name: str, metadata: dict[str, Any] | None, *,
                    tier: str | None) -> None:
    problems = violations(agent_name, metadata, tier=tier)
    if problems:
        raise GovernanceError(
            f"Agent {agent_name!r} cannot be constructed:\n- " + "\n- ".join(problems)
        )
