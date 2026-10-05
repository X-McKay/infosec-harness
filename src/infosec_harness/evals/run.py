"""Per-agent evaluation (§10): run an agent's dataset, score deterministically, persist.

An experiment = dataset x agent config x repetitions. Each (case, repetition) becomes one
attempt record; the experiment's metrics are computed from those records alone
(:mod:`infosec_harness.evals.metrics`) and persisted to the experiment store after every case,
so ``harness eval compare`` can read a model/prompt/skill change one variable at a time.

An experiment overlay records one variable against a committed spec. Applied to a later spec it
measures something else -- an overlay that replaces ``instructions`` silently reverts every
instruction change made since -- so each agent entry declares the ``base_version`` (the spec's
``metadata.version``) it was authored against, and a mismatch is refused rather than run.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import time
import traceback
import uuid
from collections.abc import Awaitable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel
from pydantic_ai import capture_run_messages
from pydantic_ai.exceptions import UnexpectedModelBehavior, UsageLimitExceeded

from infosec_harness.agents import models as model_factory
from infosec_harness.agents import registry
from infosec_harness.agents.intake_contracts import render_intake_prompt
from infosec_harness.agents.planning_window import planning_window_diagnostic
from infosec_harness.agents.render import render_prompt
from infosec_harness.domain.models import ExperimentStatus
from infosec_harness.evals.adapters import (
    ADAPTERS,
    AdaptedCase,
    defines_unevidenced_safety,
    is_unevidenced_safe,
)
from infosec_harness.evals.budget_stop import budget_stop_diagnostic
from infosec_harness.evals.coverage import ScenarioCoverage, scenario_coverage
from infosec_harness.evals.dataset import Dataset, case_group, case_set_identity, load_dataset
from infosec_harness.evals.errors import failure_diagnostic
from infosec_harness.evals.execution_checks import run_execution_check
from infosec_harness.evals.gates import ReleasePolicy, load_policy
from infosec_harness.evals.intake_fields import intake_field_summary
from infosec_harness.evals.metrics import RunPlan, experiment_metrics
from infosec_harness.evals.output_retries import output_retry_summary
from infosec_harness.evals.pricing import PricingStatus, pricing_status
from infosec_harness.evals.probe_execution import evaluate_probe_execution
from infosec_harness.evals.provenance import CodeVersion, code_version
from infosec_harness.evals.release_report import report_provenance, write_release_report
from infosec_harness.evals.trajectory import summarize_calls
from infosec_harness.inference.invocations import eval_invocation
from infosec_harness.inference.protocol import BrokerError
from infosec_harness.inference.provenance import runtime_evidence
from infosec_harness.persistence import db
from infosec_harness.settings import get_settings

EVALUATOR_VERSION = "deterministic-agent-output-v12"
# Model/provider settings mirror the durable worker, while orchestration and activity retries
# do not run under Temporal in this evaluator. Latency and failure behavior are only
# comparable between runs carrying this same execution contract.
EVAL_EXECUTION_MODE = "local-eval-production-transport-v1"


class TruncatedExperiment(RuntimeError):
    """A run stopped on an infrastructure failure after some cases had already been scored.

    The completed cases are persisted before this is raised, so a long run is not lost -- but
    it is raised because a truncated experiment is a failed run, not a smaller one.
    ``experiment_id`` is the partial experiment; ``truncation`` is the sanitized record stored
    in its metrics.
    """

    def __init__(self, experiment_id: str, truncation: dict) -> None:
        self.experiment_id = experiment_id
        self.truncation = truncation
        super().__init__(
            f"experiment {experiment_id} TRUNCATED after "
            f"{truncation['completed_runs']}/{truncation['planned_runs']} case runs "
            f"({truncation['completed_cases']}/{truncation['planned_cases']} dataset cases): "
            f"{truncation['error_type']}: {truncation['error']} "
            f"-- failed on case {truncation['failed_case']!r} repetition "
            f"{truncation['failed_repetition']}. The completed cases are saved as "
            f"EXPERIMENT_ID={experiment_id}, marked status=truncated: its metrics cover only "
            f"the cases that ran and must not be compared against a complete experiment."
        )


class AgentRunTimeout(TimeoutError):
    """The evaluator stopped an agent at its declared wall-clock limit."""

    def __init__(self, message: str = "Agent exceeded its configured time budget") -> None:
        super().__init__(message)


async def run_with_timeout[T](invocation: Awaitable[T], seconds: float, *,
                              expired: type[TimeoutError] = AgentRunTimeout) -> T:
    """Await ``invocation`` under the evaluator's own deadline.

    Only the expiry of *this* deadline raises ``expired``; a timeout raised inside the
    invocation (a transport timeout, say) propagates unchanged, so it is never mislabelled as
    the evaluator stopping the run.
    """
    deadline = asyncio.timeout(seconds)
    try:
        async with deadline:
            return await invocation
    except TimeoutError as exc:
        if deadline.expired():
            raise expired() from exc
        raise


class StaleOverlay(ValueError):
    """The overlay was written against a different version of the agent's spec."""


def load_overlay(path: Path) -> dict[str, dict[str, Any]]:
    """Read an overlay file and check every entry against the current spec version."""
    document = yaml.safe_load(Path(path).read_text())
    if not isinstance(document, Mapping) or not document:
        raise ValueError(f"{path}: an overlay maps agent names to spec fragments")
    overlay: dict[str, dict[str, Any]] = {}
    for agent, fragment in document.items():
        if not isinstance(fragment, Mapping):
            raise ValueError(f"{path}: the overlay for {agent!r} must be a mapping")
        fragment = dict(fragment)
        declared = fragment.pop("base_version", None)
        current = str((registry.load_spec(str(agent)).metadata or {}).get("version"))
        if declared is None:
            raise StaleOverlay(
                f"{path}: the overlay for {agent!r} declares no base_version, so it cannot be "
                f"checked against the current spec ({current})")
        if str(declared) != current:
            raise StaleOverlay(
                f"{path}: the overlay for {agent!r} was written against spec version "
                f"{declared}, but the current spec is {current}. Re-derive the overlay from "
                "the current spec before running it; applied as-is it measures a different "
                "change than the one it records")
        overlay[str(agent)] = fragment
    return overlay


async def load_experiment(experiment_id: str) -> db.EvalExperiment | None:
    """One stored experiment row, ``None`` when there is no such experiment."""
    async with db.session() as session:
        return await session.get(db.EvalExperiment, experiment_id)


class _BrokerBudgetStop(UsageLimitExceeded):
    """An evaluator disposition only; it grants no retry or dispatch authority."""


@asynccontextmanager
async def _broker_budget_as_usage_stop():
    try:
        yield
    except BrokerError as error:
        if type(error.code) is str and error.code == "budget":
            # Keep arbitrary broker/endpoint text out of diagnostic evidence. The closed
            # admission disposition establishes a stop, not its exact bound.
            raise _BrokerBudgetStop("Trusted broker admission budget stop") from None
        raise


_DIAGNOSTIC_OUTPUT_LIMIT = 16_000
_SENSITIVE_OUTPUT_KEYS = {
    "api_key", "authorization", "credential", "credentials", "password", "secret",
    "access_token", "refresh_token",
}
# The experiment row's `dataset` column width: the tail of a long path is the informative part.
_DATASET_COLUMN_CHARS = db.EvalExperiment.__table__.c.dataset.type.length


def _redact(item: Any) -> Any:
    if isinstance(item, dict):
        return {
            str(key): "[REDACTED]"
            if str(key).lower().replace("-", "_").replace(" ", "_") in _SENSITIVE_OUTPUT_KEYS
            else _redact(child)
            for key, child in item.items()
        }
    if isinstance(item, list):
        return [_redact(child) for child in item]
    return item


def _bounded_typed_output(output: Any) -> dict[str, Any]:
    """Retain bounded typed evidence under the eval store's existing classification."""
    if not isinstance(output, BaseModel):
        return {"type": type(output).__name__, "truncated": False, "unsupported": True}
    value = _redact(output.model_dump(mode="json"))
    encoded = json.dumps(value, sort_keys=True, default=repr)
    if len(encoded) > _DIAGNOSTIC_OUTPUT_LIMIT:
        return {"type": type(output).__name__, "truncated": True, "original_chars": len(encoded),
                "json_prefix": encoded[:_DIAGNOSTIC_OUTPUT_LIMIT]}
    return {"type": type(output).__name__, "truncated": False, "value": value}


def _no_output_check(case: Mapping[str, Any], reason: str) -> dict[str, Any]:
    return {"status": "not_checked", "check": case["execution_check"],
            "reason": f"agent output unavailable after {reason}",
            "execution_mode": "not-run-no-typed-output-v1"}


@dataclass
class _Experiment:
    """Everything fixed for one experiment, plus the attempts it has scored so far."""

    agent: str
    experiment_id: str
    built: Any
    spec: Any
    base_config: Any
    model_tier: str
    model_name: str
    pricing: str
    cfg_hash: str
    overlay_label: str
    data: Dataset
    plan: RunPlan
    coverage: ScenarioCoverage
    identity: dict[str, Any]
    code: CodeVersion
    policy: ReleasePolicy
    provenance: dict[str, Any]
    attempts: list[dict] = field(default_factory=list)
    completed_cases: int = 0

    @property
    def stub(self) -> bool:
        return self.pricing == PricingStatus.STUB

    @property
    def cost_known_zero(self) -> bool:
        return self.pricing in {PricingStatus.STUB, PricingStatus.ZERO_PRICED}


def _observations(experiment: _Experiment, adapted: AdaptedCase,
                  messages: list) -> dict[str, object]:
    return {
        "call_summary": summarize_calls(messages),
        "output_retry_summary": output_retry_summary(messages, agent=experiment.agent),
        "intake_field_summary": intake_field_summary(
            messages, report=adapted.deps.report_text, agent=experiment.agent),
    }


def _attempt(case: Mapping[str, Any], rep: int, config: Any, **fields: object) -> dict[str, object]:
    return {
        "case": case["name"], "group": case_group(case), "repetition": rep,
        "expected": case["expected"], **fields,
        "effective_config_digest": config.digest,
        "effective_budget_digest": config.budget.digest,
    }


async def _score_output(experiment: _Experiment, case: Mapping[str, Any],
                        adapted: AdaptedCase, output: Any) -> tuple[str, str, dict[str, Any]]:
    """(predicted, outcome, diagnostic) for a typed answer, execution evidence included."""
    predicted, outcome = adapted.predict(output), "answered"
    diagnostic: dict[str, Any] = {"typed_output": _bounded_typed_output(output)}
    execution = await run_execution_check(dict(case), output, stub=experiment.stub)
    if execution is not None:
        predicted = execution.predicted
        diagnostic["execution_check"] = execution.as_score()
        if execution.status in {"not_checked", "failed"}:
            outcome = f"execution_{execution.status}"
    probe = await evaluate_probe_execution(experiment.agent, dict(case), output,
                                           stub=experiment.stub)
    if probe is not None:
        # Same-process tracing is useful diagnostic evidence, but candidate code can tamper
        # with or forge it. It must not change the structural score or satisfy
        # release-grade execution gates.
        diagnostic["probe_observation"] = probe.as_score()
    return predicted, outcome, diagnostic


def _stopped(exc: BaseException, case: Mapping[str, Any], config: Any,
             messages: list) -> tuple[str, dict[str, Any]]:
    """(outcome, diagnostic) for a run with no accepted answer that is still a scored outcome."""
    if isinstance(exc, UsageLimitExceeded | AgentRunTimeout):
        # The run hit its declared budget: it was stopped, not answered. That is a hard gate,
        # so it is its own outcome rather than a wrong answer.
        diagnostic: dict[str, Any] = {
            "error_type": ("UsageLimitExceeded" if isinstance(exc, UsageLimitExceeded)
                           else "AgentRunTimeout"),
            "error_category": "budget_exhausted",
            "budget_stop": budget_stop_diagnostic(exc, config.budget, messages),
        }
        if isinstance(exc, _BrokerBudgetStop):
            diagnostic.update(failure_diagnostic(BrokerError("budget")))
        outcome, reason = "budget_exhausted", "budget stop"
    else:
        # This also covers exhausted function-tool retries and provider protocol failures. No
        # typed answer was accepted; do not claim the output schema itself was the cause, and
        # omit exception/provider text, which may contain sensitive content.
        diagnostic = {"error_type": "UnexpectedModelBehavior",
                      "error_category": "no_accepted_output", "provider_body_retained": False}
        outcome, reason = "invalid_output", "no accepted output"
    if case.get("execution_check"):
        diagnostic["execution_check"] = _no_output_check(case, reason)
    return outcome, diagnostic


async def _run_case(experiment: _Experiment, case: dict, adapted: AdaptedCase,
                    rep: int) -> db.EvalCaseResult:
    """Invoke the agent on one case once; append its attempt record and return its row.

    Budget stops and outputs that never validated are scored outcomes. Anything else is the
    run falling over: its attempt is recorded as ``failed`` and the exception propagates.
    """
    agent, expected = experiment.agent, case["expected"]
    render = render_intake_prompt if agent == "intake" else render_prompt
    prompt = render(adapted.task, adapted.payload)
    config = registry.resolve_agent_config(agent, experiment.spec,
                                           source_files=adapted.deps.source_files, durable=True)
    metadata = experiment.spec.metadata or {}
    started = time.monotonic()
    usage: dict[str, object] | None = None
    cost: float | None = 0.0 if experiment.cost_known_zero else None
    messages: list = []
    try:
        async with (_broker_budget_as_usage_stop(),
                    eval_invocation(agent, adapted.deps, config,
                                    configuration_digest=experiment.base_config.digest) as live):
            with capture_run_messages() as messages:
                result = await run_with_timeout(
                    experiment.built.run(prompt, deps=live,
                                         usage_limits=config.budget.to_usage_limits()),
                    seconds=get_settings().agent_run_timeout_s,
                )
        predicted, outcome, diagnostic = await _score_output(experiment, case, adapted,
                                                             result.output)
        messages = result.all_messages()
        estimated, _ = model_factory.estimate_cost(experiment.model_name, result.usage)
        cost = estimated if estimated is not None else cost
        usage = {
            "requests": result.usage.requests or 0,
            "input_tokens": result.usage.input_tokens,
            "output_tokens": result.usage.output_tokens,
            "cache_read_tokens": result.usage.cache_read_tokens or 0,
            "cache_write_tokens": result.usage.cache_write_tokens or 0,
        }
    except (UsageLimitExceeded, AgentRunTimeout, UnexpectedModelBehavior) as exc:
        outcome, diagnostic = _stopped(exc, case, config, messages)
        predicted = outcome
    except BaseException as exc:
        experiment.attempts.append(_attempt(
            case, rep, config, outcome="failed", **_observations(experiment, adapted, messages),
            **failure_diagnostic(exc), latency_s=time.monotonic() - started, usage=None,
            usage_status="unknown",
            planning_window=planning_window_diagnostic(
                metadata, config.budget.effective.max_requests, None),
            cost_usd=cost, cost_status="known_zero" if cost == 0.0 else "unknown",
        ))
        raise
    diagnostic["planning_window"] = planning_window_diagnostic(
        metadata, config.budget.effective.max_requests,
        usage["requests"] if usage is not None else None)
    if config.model.broker_contract is not None:
        diagnostic["inference_runtime"] = runtime_evidence(messages)
    diagnostic.update(_observations(experiment, adapted, messages))
    latency = time.monotonic() - started
    passed = predicted == expected
    usage_status = "observed" if usage is not None else "unknown"
    cost_status = ("known_zero" if cost == 0.0 and experiment.cost_known_zero
                   else "observed" if cost is not None else "unknown")
    experiment.attempts.append(_attempt(
        case, rep, config, predicted=predicted, passed=passed, outcome=outcome,
        unevidenced_safe=is_unevidenced_safe(agent, case, predicted),
        latency_s=latency, usage=usage, usage_status=usage_status, cost_usd=cost,
        cost_status=cost_status, **diagnostic,
    ))
    return db.EvalCaseResult(
        experiment_id=experiment.experiment_id, case_name=case["name"], repetition=rep,
        passed=passed,
        scores={
            "expected": expected, "predicted": predicted, "outcome": outcome, "usage": usage,
            "usage_status": usage_status, "cost_usd": cost, "cost_status": cost_status,
            "group": case_group(case), "effective_config_digest": config.digest,
            "effective_budget": config.budget.model_dump(mode="json"), **diagnostic,
        },
        # Non-null column: truth lives in scores.cost_usd/cost_status when unknown.
        cost_usd=cost or 0.0,
        latency_s=latency,
    )


def _agent_overlay(agent: str, overlay: Path | Mapping[str, object] | None,
                   model: str | None) -> dict[str, Any] | None:
    overlay_data = load_overlay(overlay) if isinstance(overlay, Path) else overlay
    fragment = dict((overlay_data or {}).get(agent) or {}) or None
    if model:
        # `--model` is the one-variable-at-a-time knob, expressed as the smallest possible
        # overlay. It is applied after any --overlay file, being the more specific instruction.
        fragment = {**(fragment or {}), "model": model}
    return fragment


def _metrics(experiment: _Experiment, status: ExperimentStatus,
             truncation: dict | None = None) -> dict[str, Any]:
    metrics = experiment_metrics(experiment.attempts, experiment.plan, status=status,
                                 cases_completed=experiment.completed_cases)
    metrics.update(
        scenario_coverage=experiment.coverage.as_report(),
        comparison_identity=experiment.identity,
        effective_configuration=experiment.base_config.model_dump(mode="json"),
        code_identity=experiment.code.as_dict(),
    )
    if truncation is not None:
        metrics["truncated"] = truncation
    if status is ExperimentStatus.complete:
        # The policy verdict travels with the stored run, so a reader of the experiment
        # store sees the same gate status the release report records.
        metrics["gate_evaluation"] = experiment.policy.evaluate(
            metrics, provenance=experiment.provenance).as_report()
    return metrics


async def _persist(experiment: _Experiment, status: ExperimentStatus, rows: list,
                   truncation: dict | None = None) -> dict[str, Any]:
    """Upsert the experiment with the metrics so far and append the new case rows."""
    metrics = _metrics(experiment, status, truncation)
    code, model_name = experiment.code, experiment.model_name
    async with db.session() as session:
        await session.merge(db.EvalExperiment(
            id=experiment.experiment_id, agent=experiment.agent,
            dataset=experiment.data.display_path[-_DATASET_COLUMN_CHARS:],
            dataset_version=experiment.data.version, git_sha=code.git_commit,
            git_dirty=code.git_dirty, harness_version=code.harness_version,
            overlay=experiment.overlay_label, config_hash=experiment.cfg_hash,
            model_tier=experiment.model_tier, model_name=model_name,
            backend=model_name.split(":", 1)[0] if ":" in model_name else "",
            pricing=experiment.pricing, repetitions=experiment.plan.repetitions,
            metrics=metrics,
        ))
        session.add_all(rows)
        await session.commit()
    return metrics


def _prepare(agent: str, *, overlay: Path | Mapping[str, object] | None, repeat: int,
             model: str | None, groups: set[str] | None, split: str | None,
             dataset: Path | None) -> tuple[_Experiment, list[dict]]:
    """Resolve everything an experiment fixes before its first case, and the cases it runs."""
    data = load_dataset(agent, dataset)
    cases = data.select(groups)
    fragment = _agent_overlay(agent, overlay, model)
    # The runner itself is local, while the model/provider contract intentionally mirrors the
    # durable worker, so transport retry settings stay aligned with production.
    built = registry.build_agent(agent, fragment, durable=False, production_transport=True)
    spec = registry.load_spec(agent, fragment)
    cfg_hash = registry.config_hash(agent, spec, durable=True)
    model_tier = spec.model or "sonnet"
    model_name = model_factory.resolved_model_name(agent, model_tier)
    pricing = pricing_status(model_name).value
    code = code_version()
    overlay_label = str(overlay) if isinstance(overlay, Path) else "inline" if overlay else ""
    experiment_id = "exp-" + hashlib.sha256(
        f"{agent}:{data.version}:{cfg_hash}:{overlay_label}:{uuid.uuid4()}".encode()
    ).hexdigest()[:16]
    coverage = scenario_coverage(agent, cases)
    identity = {
        **case_set_identity(cases),
        "evaluator_version": EVALUATOR_VERSION,
        "execution_mode": EVAL_EXECUTION_MODE,
        "dataset_version": data.version,
        "dataset": data.display_path,
        "repetitions": repeat,
        # "full" means the agent's own packaged dataset, all of it. A named dataset (a sealed
        # held-out set, say) is a different denominator and is labelled so by default.
        "split": split or ("full" if dataset is None else "external"),
    }
    experiment = _Experiment(
        agent=agent, experiment_id=experiment_id, built=built, spec=spec,
        base_config=registry.resolve_agent_config(agent, spec, durable=True),
        model_tier=model_tier, model_name=model_name, pricing=pricing, cfg_hash=cfg_hash,
        overlay_label=overlay_label, data=data,
        plan=RunPlan(
            cases=len(cases), repetitions=repeat,
            execution_checks=sum(bool(case.get("execution_check")) for case in cases) * repeat,
            unevidenced_safety=defines_unevidenced_safety(agent),
            uncovered_material_scenarios=len(coverage.uncovered_material),
        ),
        coverage=coverage, identity=identity, code=code, policy=load_policy(agent),
        provenance=report_provenance(
            code_identity=code.as_dict(), comparison_identity=identity,
            agent_version=str((spec.metadata or {}).get("version", "0.0.0")),
            cfg_hash=cfg_hash, model_name=model_name, pricing=pricing,
            experiment_id=experiment_id, spec=spec,
        ),
    )
    return experiment, cases


async def run_experiment(
    agent: str,
    *,
    overlay: Path | Mapping[str, object] | None = None,
    repeat: int = 1,
    report: Path | None = None,
    report_dir: Path | None = None,
    model: str | None = None,
    groups: set[str] | None = None,
    split: str | None = None,
    dataset: Path | None = None,
) -> str:
    """Run an agent's dataset (or the one at ``dataset``), score it, and persist the experiment.

    Persistence is incremental: the experiment row and its case results are written as each
    case finishes, so an endpoint failure (or a kill) partway through a long ``--repeat`` run
    keeps the work already scored. An experiment is only ``status=complete`` once every planned
    case run has been scored; a run cut short is stored as ``status=truncated`` and raises
    :class:`TruncatedExperiment`.

    A release report is written only when asked for: to ``report``, or to
    ``report_dir/<experiment-id>.json``. Truncated runs never write one.
    """
    if agent not in ADAPTERS:
        raise SystemExit(f"No eval adapter for agent {agent!r}. Available: {sorted(ADAPTERS)}")
    experiment, cases = _prepare(agent, overlay=overlay, repeat=repeat, model=model,
                                 groups=groups, split=split, dataset=dataset)
    exp_id, plan = experiment.experiment_id, experiment.plan
    await db.create_all()
    # Claim the row before the first model call: a run that dies on case 1 is still a visible
    # `status=running` experiment rather than nothing at all.
    await _persist(experiment, ExperimentStatus.running, [])
    case_name, rep = "", 0
    # Rows scored but not yet committed: never more than one case's worth, and flushed on the
    # way out too, so the persisted rows always match the persisted counters.
    pending: list = []
    try:
        for case in cases:
            case_name = case["name"]
            adapted = ADAPTERS[agent](case)
            for rep in range(repeat):
                pending.append(await _run_case(experiment, case, adapted, rep))
            experiment.completed_cases += 1
            await _persist(experiment, ExperimentStatus.running, pending)
            pending = []
    except BaseException as exc:
        # Anything the per-case handlers did not classify is not an answer about the model:
        # it is the run falling over (transport error, a cancelled or hung request, Ctrl-C, an
        # adapter bug). Record where it stopped, keep the scored cases, then fail.
        scored = sum(attempt["outcome"] != "failed" for attempt in experiment.attempts)
        truncation = {
            **failure_diagnostic(exc), "failed_case": case_name, "failed_repetition": rep,
            "completed_runs": scored, "planned_runs": plan.runs,
            "completed_cases": experiment.completed_cases, "planned_cases": plan.cases,
        }
        await _persist(experiment, ExperimentStatus.truncated, pending, truncation)
        # The persisted record is sanitized; the operator running this still needs the
        # actual failure, so the full traceback goes to this process's stderr only.
        traceback.print_exception(exc, file=sys.stderr)
        print(
            f"experiment {exp_id}: TRUNCATED on case {case_name!r} rep {rep} after "
            f"{scored}/{plan.runs} case runs ({truncation['error_type']}, "
            f"http_status_code={truncation['http_status_code']}); the scored case runs are "
            "saved and the experiment is marked truncated"
        )
        if report is not None or report_dir is not None:
            print("no release report written: a truncated run cannot clear release gates "
                  "it did not measure")
        if isinstance(exc, KeyboardInterrupt | SystemExit | asyncio.CancelledError):
            raise  # an interrupt or a cancellation keeps its own semantics
        raise TruncatedExperiment(exp_id, truncation) from exc

    metrics = await _persist(experiment, ExperimentStatus.complete, pending)
    code = experiment.code
    cost_label = (f"${metrics['cost_usd_per_case']:.4f}"
                  if metrics["cost_usd_per_case"] is not None else "unknown")
    cache_label = (f"{metrics['cache_hit_ratio']:.2%}"
                   if metrics["cache_hit_ratio"] is not None else "unknown")
    print(f"experiment {exp_id}: task_success_rate={metrics['task_success_rate']:.2%} "
          f"cost/case={cost_label} cache_hit={cache_label} (model {experiment.model_name} "
          f"[{experiment.pricing}], config {experiment.cfg_hash}, code {code.label()})")
    if code.git_dirty:
        # Said once, where the number is produced: this result cannot be filed against a
        # commit, so it is not a baseline and is not reproducible from the SHA it carries.
        print("  ! the working tree is dirty, so this result does not describe "
              f"{code.git_commit[:12] or 'any commit'} -- commit before recording a baseline")
    target = report or (report_dir / f"{exp_id}.json" if report_dir is not None else None)
    if target is not None:
        write_release_report(target, agent=agent, metrics=metrics,
                             provenance=experiment.provenance, policy=experiment.policy)
    return exp_id
