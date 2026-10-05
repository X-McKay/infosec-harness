"""The one definition of release gates: each agent's ``release-policy.yaml``, evaluated.

A policy is hand-maintained package data beside the agent's spec and dataset. It names hard
gates (binary: the value must equal the limit) and thresholds (``min``/``max`` bounds), each
against a metric the eval run publishes. Everything that needs to know which gates apply to an
agent -- the release report, calibration's admissibility check, which agents carry the
unevidenced-safety gate -- reads the policy here rather than keeping its own list.

A check whose metric is missing or not a number is ``not_checked``, never ``passed``: a gate
that could not be measured has not been cleared.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

from infosec_harness.settings import get_settings

CheckStatus = Literal["passed", "failed", "not_checked"]
Bound = Literal["eq", "min", "max"]


def policy_path(agent: str) -> Path:
    return get_settings().agents_dir / agent / "evals" / "release-policy.yaml"


@dataclass(frozen=True)
class Check:
    kind: Literal["hard_gate", "threshold"]
    metric: str
    bound: Bound
    limit: float
    value: float | None
    status: CheckStatus


@dataclass(frozen=True)
class GateEvaluation:
    checks: tuple[Check, ...]

    @property
    def status(self) -> CheckStatus:
        statuses = {check.status for check in self.checks}
        if "failed" in statuses:
            return "failed"
        return "not_checked" if "not_checked" in statuses else "passed"

    @property
    def passed(self) -> bool:
        return self.status == "passed"

    def failures(self) -> list[str]:
        return [f"{c.kind} {c.metric} {c.bound} {c.limit:g}: {c.status} (value {c.value!r})"
                for c in self.checks if c.status != "passed"]

    def as_report(self) -> dict[str, Any]:
        return {"status": self.status, "checks": [asdict(check) for check in self.checks]}


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value) if math.isfinite(float(value)) else None


@dataclass(frozen=True)
class ReleasePolicy:
    agent: str
    path: Path
    hard_gates: Mapping[str, float]
    thresholds: Mapping[str, Mapping[str, float]]
    required_provenance: tuple[str, ...]
    raw: Mapping[str, Any]

    def evaluate(self, values: Mapping[str, object], *, hard_gates_only: bool = False
                 ) -> GateEvaluation:
        """Evaluate a run's metrics (or a report's gate/metric values) against this policy."""
        checks: list[Check] = []
        for metric, limit in self.hard_gates.items():
            value = _number(values.get(metric))
            status: CheckStatus = (
                "not_checked" if value is None else "passed" if value == limit else "failed")
            checks.append(Check("hard_gate", metric, "eq", limit, value, status))
        if not hard_gates_only:
            for metric, bounds in self.thresholds.items():
                value = _number(values.get(metric))
                for bound, limit in bounds.items():
                    if value is None:
                        status = "not_checked"
                    elif bound == "min":
                        status = "passed" if value >= limit else "failed"
                    else:
                        status = "passed" if value <= limit else "failed"
                    checks.append(Check("threshold", metric, bound, limit, value, status))
        return GateEvaluation(tuple(checks))

    @property
    def metrics_named(self) -> set[str]:
        return set(self.hard_gates) | set(self.thresholds)


def parse_policy(agent: str, raw: Mapping[str, Any], path: Path) -> ReleasePolicy:
    """Validate a policy document. Malformed policies fail loudly rather than gate nothing."""
    if not isinstance(raw, Mapping):
        raise ValueError(f"{path}: a release policy is a mapping")
    gates = raw.get("hard_gates") or {}
    thresholds = raw.get("thresholds") or {}
    if not isinstance(gates, Mapping) or not isinstance(thresholds, Mapping):
        raise ValueError(f"{path}: hard_gates and thresholds must be mappings")
    hard: dict[str, float] = {}
    for metric, limit in gates.items():
        if _number(limit) is None:
            raise ValueError(f"{path}: hard gate {metric!r} needs a numeric limit, got {limit!r}")
        hard[str(metric)] = float(limit)
    bounded: dict[str, dict[str, float]] = {}
    for metric, bounds in thresholds.items():
        if not isinstance(bounds, Mapping) or not bounds or set(bounds) - {"min", "max"}:
            raise ValueError(f"{path}: threshold {metric!r} must declare min and/or max")
        if any(_number(limit) is None for limit in bounds.values()):
            raise ValueError(f"{path}: threshold {metric!r} needs numeric bounds")
        bounded[str(metric)] = {str(b): float(limit) for b, limit in bounds.items()}
    return ReleasePolicy(
        agent=agent, path=path, hard_gates=hard, thresholds=bounded,
        required_provenance=tuple(raw.get("required_provenance") or ()), raw=dict(raw),
    )


def load_policy(agent: str, path: Path | None = None) -> ReleasePolicy:
    path = Path(path) if path is not None else policy_path(agent)
    return parse_policy(agent, yaml.safe_load(path.read_text()) or {}, path)


def policies() -> dict[str, ReleasePolicy]:
    """Every agent policy on disk, by agent."""
    root = get_settings().agents_dir
    return {p.parents[1].name: load_policy(p.parents[1].name, p)
            for p in sorted(root.glob("*/evals/release-policy.yaml"))}


def agents_gated_on(metric: str) -> tuple[str, ...]:
    """The agents whose policy names ``metric`` as a hard gate."""
    return tuple(sorted(agent for agent, policy in policies().items()
                        if metric in policy.hard_gates))


def policy_problems(policy: ReleasePolicy, cases: Iterable[Mapping[str, Any]]) -> list[str]:
    """Checks in ``policy`` that the agent's eval cannot measure, or cannot fail.

    A gate on a metric the run never publishes is compared against nothing; a gate on
    execution evidence for a dataset that declares no execution check is a constant zero. Both
    read as coverage and enforce nothing.
    """
    from infosec_harness.evals.adapters import defines_unevidenced_safety
    from infosec_harness.evals.metrics import gateable_metrics

    emitted = gateable_metrics(unevidenced_safety=defines_unevidenced_safety(policy.agent))
    problems = [f"{policy.agent}: {metric} is not a metric the eval run publishes"
                for metric in sorted(policy.metrics_named - emitted)]
    if not any(case.get("execution_check") for case in cases):
        problems += [
            f"{policy.agent}: {metric} gates execution evidence but no case declares an "
            "execution_check, so it is always 0"
            for metric in ("execution_not_checked_count", "execution_failed_count")
            if metric in policy.hard_gates
        ]
    return problems
