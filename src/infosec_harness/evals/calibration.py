"""Bounded, grouped calibration experiments built on the normal agent eval runner."""

from __future__ import annotations

import asyncio
import json
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from infosec_harness._io import write_json
from infosec_harness.evals.coverage import scenario_coverage
from infosec_harness.evals.dataset import Case, case_group, load_dataset
from infosec_harness.evals.gates import ReleasePolicy, load_policy
from infosec_harness.evals.provenance import CodeVersion, code_version
from infosec_harness.evals.run import load_experiment, run_experiment, run_with_timeout
from infosec_harness.inference import models as model_factory
from infosec_harness.runtime.budgets import MAX_SIZE_FACTOR, run_budget
from infosec_harness.runtime.registry import (
    config_hash,
    deep_merge,
    load_spec,
    resolve_agent_config,
)

_SAFE_VARIABLE_PREFIXES = (
    "model",
    "model_settings.",
    "metadata.budgets.",
    "metadata.clear_tool_tokens",
)


class DatasetSplit(BaseModel):
    calibration: list[str] = Field(min_length=1)
    held_out: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def groups_are_disjoint(self) -> DatasetSplit:
        overlap = set(self.calibration) & set(self.held_out)
        if overlap:
            raise ValueError(f"calibration and held-out groups overlap: {sorted(overlap)}")
        return self


class ExperimentLimits(BaseModel):
    maximum_trials: int = Field(gt=0, le=32)
    maximum_duration_seconds: float = Field(gt=0, le=86_400)
    maximum_model_requests: int = Field(gt=0)
    maximum_cost_usd: float | None = Field(default=None, gt=0)
    minimum_task_success_rate: float = Field(ge=0, le=1)


class CalibrationSpec(BaseModel):
    version: Literal["1"] = "1"
    experiment: str = Field(min_length=1)
    subject: str = Field(min_length=1)
    hypothesis: str = Field(min_length=1)
    baseline_manifest: str | None = None
    backend_profile: str | None = None
    variable: str
    candidates: list[int | float | str | bool] = Field(min_length=2, max_length=32)
    repetitions: int = Field(gt=0, le=20)
    dataset: DatasetSplit
    constraints: ExperimentLimits
    model: str | None = None
    overlay: dict[str, Any] = Field(default_factory=dict)
    promotion: Literal["review_required"] = "review_required"

    @field_validator("variable")
    @classmethod
    def variable_is_operational(cls, value: str) -> str:
        value = f"metadata.{value}" if value.startswith("budgets.") else value
        if value == "model" or any(value.startswith(prefix) for prefix in _SAFE_VARIABLE_PREFIXES):
            return value
        raise ValueError(
            "variable must be a model, model setting, budget, or compaction threshold; "
            "safety permissions and evidence/isolation controls are not calibration variables"
        )

    @model_validator(mode="after")
    def candidates_are_distinct(self) -> CalibrationSpec:
        encoded = [json.dumps(v, sort_keys=True) for v in self.candidates]
        if len(set(encoded)) != len(encoded):
            raise ValueError("candidate values must be distinct")
        if len(self.candidates) > self.constraints.maximum_trials:
            raise ValueError(
                f"{len(self.candidates)} candidates exceeds maximum_trials="
                f"{self.constraints.maximum_trials}"
            )
        return self


class TrialResult(BaseModel):
    candidate: int | float | str | bool
    effective_config_digest: str
    status: Literal["complete", "failed", "duplicate_effective"]
    experiment_id: str | None = None
    duplicate_of: int | float | str | bool | None = None
    metrics: dict[str, Any] | None = None
    error: str | None = None


class CalibrationReport(BaseModel):
    schema_version: Literal[1] = 1
    experiment: str
    subject: str
    hypothesis: str
    variable: str
    baseline_config_digest: str
    declared_baseline_manifest: str | None
    backend_profile: str
    code_identity: dict[str, Any]
    thresholds: dict[str, int | float]
    repetitions: int
    calibration_groups: list[str]
    held_out_groups: list[str]
    planned_model_request_ceiling: int
    planned_cost_ceiling_usd: float | None
    elapsed_seconds: float
    trials: list[TrialResult]
    selected_candidate: int | float | str | bool | None
    held_out_experiment_id: str | None
    held_out_metrics: dict[str, Any] | None
    promotion_eligible: bool
    promotion: Literal["review_required"] = "review_required"
    limitations: list[str] = Field(default_factory=list)


def load_calibration(path: Path) -> CalibrationSpec:
    data = yaml.safe_load(path.read_text())
    if not isinstance(data, dict):
        raise ValueError("calibration file must contain a YAML mapping")
    return CalibrationSpec.model_validate(data)


def _set_path(data: dict[str, Any], dotted: str, value: object) -> None:
    parts = dotted.split(".")
    target = data
    for part in parts[:-1]:
        child = target.setdefault(part, {})
        if not isinstance(child, dict):
            raise ValueError(f"cannot set {dotted!r}: {part!r} is not a mapping")
        target = child
    target[parts[-1]] = value


def _agent_overlay(spec: CalibrationSpec, candidate: object) -> dict[str, Any]:
    overlay = deepcopy(spec.overlay)
    current = dict(overlay.get(spec.subject) or {})
    _set_path(current, spec.variable, candidate)
    if spec.model:
        current["model"] = spec.model
    overlay[spec.subject] = current
    return overlay


def _validate_groups(
    spec: CalibrationSpec, cases: tuple[Case, ...], policy: ReleasePolicy
) -> tuple[int, int]:
    available = {case_group(case) for case in cases}
    requested = set(spec.dataset.calibration) | set(spec.dataset.held_out)
    if missing := sorted(requested - available):
        raise ValueError(f"dataset groups do not exist for {spec.subject}: {missing}")
    selections = {
        "calibration": [c for c in cases if case_group(c) in set(spec.dataset.calibration)],
        "held_out": [c for c in cases if case_group(c) in set(spec.dataset.held_out)],
    }
    if "uncovered_material_scenarios" in policy.hard_gates:
        for name, selected in selections.items():
            uncovered = scenario_coverage(spec.subject, selected).uncovered_material
            if uncovered:
                # Every run of these groups would fail the policy's coverage gate, so no
                # candidate could ever be admissible; refuse before spending anything.
                raise ValueError(
                    f"{name} groups leave material risk scenarios uncovered: {uncovered}; "
                    f"{spec.subject}'s release policy gates on uncovered_material_scenarios")
    return len(selections["calibration"]), len(selections["held_out"])


class CalibrationDeadline(TimeoutError):
    """The experiment's own wall-clock budget ran out."""

    def __init__(self) -> None:
        super().__init__("calibration experiment deadline exhausted")


def _candidate_spec(spec: CalibrationSpec, base: Any, candidate: object) -> Any:
    """The subject's spec with one candidate value applied, exactly as its trial will run it."""
    overlay = _agent_overlay(spec, candidate)[spec.subject]
    merged = deep_merge(base.model_dump(by_alias=True, exclude_none=True, mode="json"), overlay)
    return type(base).from_dict(merged)


def _request_ceiling(spec: CalibrationSpec, base: Any, calibration_n: int, held_out_n: int) -> int:
    candidate_limits = [
        run_budget(spec.subject, _candidate_spec(spec, base, candidate).metadata).max_requests
        for candidate in spec.candidates
    ]
    # All calibration candidates run; only the selected candidate reaches held-out data.
    return int(
        spec.repetitions
        * MAX_SIZE_FACTOR
        * (calibration_n * sum(candidate_limits) + held_out_n * max(candidate_limits))
    )


def _cost_ceiling(
    spec: CalibrationSpec, base: Any, calibration_n: int, held_out_n: int
) -> tuple[float, set[str]]:
    """Reserve the full enforceable per-run exposure before any model call begins."""
    candidate_costs: list[float] = []
    sources: set[str] = set()
    for candidate in spec.candidates:
        resolved = resolve_agent_config(
            spec.subject, _candidate_spec(spec, base, candidate), durable=True)
        source = model_factory.pricing_source(resolved.model.resolved_model)
        sources.add(source)
        if source in {"stub", "custom-zero"}:
            candidate_costs.append(0.0)
        elif source == "genai-prices":
            candidate_costs.append(resolved.budget.effective.max_cost_usd * MAX_SIZE_FACTOR)
        else:
            # PydanticAI cannot enforce a pre-request dollar ceiling from our custom fallback
            # table, and an unknown table cannot enforce one at all. Reject before egress.
            raise ValueError(
                f"maximum_cost_usd cannot be enforced before calls for pricing source "
                f"{source!r}; use a genai-prices model or an explicitly zero-priced backend"
            )
    ceiling = spec.repetitions * (
        calibration_n * sum(candidate_costs) + held_out_n * max(candidate_costs)
    )
    return round(ceiling, 6), sources


def _check_cost_cap(spec: CalibrationSpec, spent: float, cost_is_unknown: bool,
                    stage: str) -> None:
    """Stop the experiment once its declared cost cap can no longer be shown to hold."""
    cap = spec.constraints.maximum_cost_usd
    if cap is None:
        return
    if cost_is_unknown:
        raise RuntimeError(
            f"{stage} cost is unknown; the experiment cost cap cannot be enforced")
    if spent > cap:
        raise RuntimeError(f"experiment cost ${spent:.6f} crossed maximum_cost_usd=${cap:.6f}")


def admissible(policy: ReleasePolicy, metrics: dict[str, Any] | None) -> bool:
    """A complete, fully covered run that clears every hard gate in the agent's own policy.

    A gate whose metric is missing is unknown evidence and fails closed, just like a nonzero
    count.
    """
    return bool(
        metrics
        and metrics.get("status") == "complete"
        and metrics.get("n") == metrics.get("n_planned")
        and policy.evaluate(metrics, hard_gates_only=True).passed
    )


def _selection_key(trial: TrialResult) -> tuple[float, float, float]:
    metrics = trial.metrics or {}
    latency = (metrics.get("distributions") or {}).get("p95_latency_s")
    avg_tokens = metrics.get("avg_tokens")
    return (
        float(metrics.get("task_success_rate") or 0.0),
        -float(latency if latency is not None else float("inf")),
        -float(avg_tokens if avg_tokens is not None else float("inf")),
    )


def _promotion_eligible(
    *,
    policy: ReleasePolicy,
    selected: TrialResult | None,
    held_out_metrics: dict[str, Any] | None,
    selected_quality: bool,
    held_out_quality: bool,
    code: CodeVersion,
    model_mode: str,
    cost_is_unknown: bool,
    maximum_cost_usd: float | None,
) -> bool:
    """Promotion requires live evidence from immutable source plus every quality gate."""
    return bool(
        selected is not None
        and admissible(policy, held_out_metrics)
        and selected_quality
        and held_out_quality
        and code.describes_a_commit
        and model_mode == "live"
        and not (cost_is_unknown and maximum_cost_usd is not None)
    )


async def run_calibration(spec: CalibrationSpec) -> CalibrationReport:
    """Run calibration candidates, select an admissible one, then run grouped holdouts."""
    policy = load_policy(spec.subject)
    calibration_n, held_out_n = _validate_groups(spec, load_dataset(spec.subject).cases, policy)
    base_spec = load_spec(spec.subject)
    ceiling = _request_ceiling(spec, base_spec, calibration_n, held_out_n)
    if ceiling > spec.constraints.maximum_model_requests:
        raise ValueError(
            f"planned worst-case model requests {ceiling} exceed "
            f"maximum_model_requests={spec.constraints.maximum_model_requests}"
        )

    baseline_digest = config_hash(spec.subject, base_spec, durable=True)
    if spec.baseline_manifest and spec.baseline_manifest != baseline_digest:
        raise ValueError(
            f"baseline_manifest={spec.baseline_manifest!r} does not match the resolved baseline "
            f"configuration {baseline_digest!r}"
        )
    code = code_version()
    resolved_model = model_factory.resolve_config(
        spec.subject,
        spec.model or base_spec.model or "sonnet",
        model_settings=dict(base_spec.model_settings or {}),
    )
    backend = resolved_model.backend_name
    if spec.backend_profile and spec.backend_profile != backend:
        raise ValueError(
            f"experiment requires backend_profile={spec.backend_profile!r}, resolved {backend!r}"
        )

    planned_cost_ceiling: float | None = None
    if spec.constraints.maximum_cost_usd is not None:
        planned_cost_ceiling, _ = _cost_ceiling(spec, base_spec, calibration_n, held_out_n)
        if planned_cost_ceiling > spec.constraints.maximum_cost_usd:
            raise ValueError(
                f"planned worst-case cost ${planned_cost_ceiling:.6f} exceeds "
                f"maximum_cost_usd=${spec.constraints.maximum_cost_usd:.6f}; "
                "the cap is reserved before calls so the experiment cannot overshoot it"
            )

    started = time.monotonic()
    deadline = started + spec.constraints.maximum_duration_seconds
    trials: list[TrialResult] = []
    first_by_digest: dict[str, object] = {}
    spent = 0.0
    cost_is_unknown = False

    async def run_one(
        candidate: object, groups: set[str], split: str
    ) -> tuple[str, dict[str, Any]]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CalibrationDeadline()
        experiment_id = await run_with_timeout(
            run_experiment(
                spec.subject,
                overlay=_agent_overlay(spec, candidate),
                repeat=spec.repetitions,
                groups=groups,
                split=split,
            ),
            remaining,
            expired=CalibrationDeadline,
        )
        row = await load_experiment(experiment_id)
        return experiment_id, dict(row.metrics or {})

    for candidate in spec.candidates:
        digest = resolve_agent_config(
            spec.subject, _candidate_spec(spec, base_spec, candidate), durable=True,
        ).effective_digest
        if digest in first_by_digest:
            trials.append(
                TrialResult(
                    candidate=candidate,
                    effective_config_digest=digest,
                    status="duplicate_effective",
                    duplicate_of=first_by_digest[digest],
                )
            )
            continue
        first_by_digest[digest] = candidate
        try:
            experiment_id, metrics = await run_one(
                candidate, set(spec.dataset.calibration), "calibration"
            )
        except (KeyboardInterrupt, asyncio.CancelledError):
            raise
        except BaseException as exc:
            trials.append(
                TrialResult(
                    candidate=candidate,
                    effective_config_digest=digest,
                    status="failed",
                    error=f"{type(exc).__name__}: {str(exc)[:500]}",
                )
            )
            continue
        trials.append(
            TrialResult(
                candidate=candidate,
                effective_config_digest=digest,
                status="complete",
                experiment_id=experiment_id,
                metrics=metrics,
            )
        )
        measured_cost = metrics.get("cost_usd_total")
        cost_is_unknown = cost_is_unknown or measured_cost is None
        spent += float(measured_cost or 0.0)
        _check_cost_cap(spec, spent, cost_is_unknown, "calibration")

    candidates = [
        trial
        for trial in trials
        if trial.status == "complete" and admissible(policy, trial.metrics)
    ]
    selected = max(candidates, key=_selection_key) if candidates else None
    held_out_id = None
    held_out_metrics = None
    if selected is not None:
        held_out_id, held_out_metrics = await run_one(
            selected.candidate, set(spec.dataset.held_out), "held_out"
        )
        held_out_cost = held_out_metrics.get("cost_usd_total")
        cost_is_unknown = cost_is_unknown or held_out_cost is None
        spent += float(held_out_cost or 0.0)
        _check_cost_cap(spec, spent, cost_is_unknown, "held-out")

    limitations: list[str] = []
    if cost_is_unknown:
        limitations.append("cost was unavailable; cost-based promotion is ineligible")
    if selected is None:
        limitations.append("no calibration candidate passed all hard gates")
    if held_out_metrics is not None and not admissible(policy, held_out_metrics):
        limitations.append("selected candidate failed held-out hard gates")
    selected_quality = bool(
        selected
        and (selected.metrics or {}).get("task_success_rate", 0)
        >= spec.constraints.minimum_task_success_rate
    )
    held_out_quality = bool(
        held_out_metrics
        and held_out_metrics.get("task_success_rate", 0)
        >= spec.constraints.minimum_task_success_rate
    )
    if selected is not None and not selected_quality:
        limitations.append(
            "selected candidate missed the predeclared calibration quality threshold"
        )
    if held_out_metrics is not None and not held_out_quality:
        limitations.append("selected candidate missed the predeclared held-out quality threshold")
    if code.git_dirty:
        limitations.append(
            "working tree was dirty; source_digest identifies the measured bytes but promotion "
            "requires an immutable clean revision"
        )
    if resolved_model.mode == "stub":
        limitations.append(
            "stub-model results exercise calibration machinery only; promotion requires live "
            "provider evidence"
        )
    promotion_eligible = _promotion_eligible(
        policy=policy,
        selected=selected,
        held_out_metrics=held_out_metrics,
        selected_quality=selected_quality,
        held_out_quality=held_out_quality,
        code=code,
        model_mode=resolved_model.mode,
        cost_is_unknown=cost_is_unknown,
        maximum_cost_usd=spec.constraints.maximum_cost_usd,
    )
    return CalibrationReport(
        experiment=spec.experiment,
        subject=spec.subject,
        hypothesis=spec.hypothesis,
        variable=spec.variable,
        baseline_config_digest=baseline_digest,
        declared_baseline_manifest=spec.baseline_manifest,
        backend_profile=backend,
        code_identity=code.as_dict(),
        thresholds={
            "minimum_task_success_rate": spec.constraints.minimum_task_success_rate,
            "maximum_model_requests": spec.constraints.maximum_model_requests,
            "maximum_duration_seconds": spec.constraints.maximum_duration_seconds,
            **(
                {"maximum_cost_usd": spec.constraints.maximum_cost_usd}
                if spec.constraints.maximum_cost_usd is not None
                else {}
            ),
        },
        repetitions=spec.repetitions,
        calibration_groups=spec.dataset.calibration,
        held_out_groups=spec.dataset.held_out,
        planned_model_request_ceiling=ceiling,
        planned_cost_ceiling_usd=planned_cost_ceiling,
        elapsed_seconds=round(time.monotonic() - started, 3),
        trials=trials,
        selected_candidate=selected.candidate if selected else None,
        held_out_experiment_id=held_out_id,
        held_out_metrics=held_out_metrics,
        promotion_eligible=promotion_eligible,
        limitations=limitations,
    )


def write_report(path: Path, report: CalibrationReport) -> None:
    """Atomically publish a completed report; production configuration is never modified."""
    write_json(path, report.model_dump(mode="json"))
