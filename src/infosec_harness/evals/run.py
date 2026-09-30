"""Per-agent evaluation (§10): run an agent's dataset, score deterministically, persist.

An experiment = dataset version x agent config x repetitions. Results (accuracy, cost,
latency, cache-hit) go to Postgres so ``harness eval compare`` can show the tradeoffs of a
model/prompt/skill change with an evidence-based, one-variable-at-a-time method.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import time
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel
from pydantic_ai import capture_run_messages

from infosec_harness.agents.planning_window import planning_window_diagnostic
from infosec_harness.agents.render import render_prompt
from infosec_harness.evals.adapters import (
    ADAPTERS,
    UNEVIDENCED_SAFETY_AGENTS,
    is_unevidenced_safe,
)
from infosec_harness.evals.budget_stop import budget_stop_diagnostic
from infosec_harness.evals.errors import failure_diagnostic
from infosec_harness.evals.invocation import AgentRunTimeout, run_with_timeout
from infosec_harness.evals.output_retries import output_retry_summary
from infosec_harness.evals.provenance import code_version
from infosec_harness.evals.trajectory import summarize_calls
from infosec_harness.settings import get_settings

EVALUATOR_VERSION = "deterministic-agent-output-v9"
EVAL_EXECUTION_MODE = "local-eval-production-transport-v1"


_DIAGNOSTIC_OUTPUT_LIMIT = 16_000
_SENSITIVE_OUTPUT_KEYS = {
    "api_key",
    "authorization",
    "credential",
    "credentials",
    "password",
    "secret",
    "access_token",
    "refresh_token",
}


def _bounded_typed_output(output: Any) -> dict[str, Any]:
    """Retain bounded typed evidence under the eval store's existing classification."""
    if not isinstance(output, BaseModel):
        return {"type": type(output).__name__, "truncated": False, "unsupported": True}
    value = output.model_dump(mode="json")

    def redact(item: Any) -> Any:
        if isinstance(item, dict):
            return {
                str(key): "[REDACTED]"
                if str(key).lower().replace("-", "_").replace(" ", "_") in _SENSITIVE_OUTPUT_KEYS
                else redact(child)
                for key, child in item.items()
            }
        if isinstance(item, list):
            return [redact(child) for child in item]
        return item

    value = redact(value)
    encoded = json.dumps(value, sort_keys=True, default=repr)
    diagnostic = {"type": type(output).__name__, "truncated": False, "value": value}
    if len(encoded) > _DIAGNOSTIC_OUTPUT_LIMIT:
        diagnostic = {
            "type": type(output).__name__,
            "truncated": True,
            "original_chars": len(encoded),
            "json_prefix": encoded[:_DIAGNOSTIC_OUTPUT_LIMIT],
        }
    return diagnostic


def case_group(case: Mapping[str, object]) -> str:
    """Stable group used to keep related variants on the same side of a holdout split."""
    if group := case.get("group"):
        return str(group)
    if repo := case.get("repo"):
        value = str(repo).rstrip("/")
        for suffix in ("/vulnerable", "/fixed"):
            if value.endswith(suffix):
                return value.removesuffix(suffix)
        return value
    name = str(case.get("name") or "")
    for suffix in ("-vulnerable", "-fixed"):
        if name.endswith(suffix):
            return name.removesuffix(suffix)
    return name


def _usage_metrics(
    attempts: list[dict[str, object]], tokens: float, cache_read: float
) -> dict[str, object]:
    """Publish aggregate usage only when every attempted run supplied usage."""
    attempt_count = len(attempts)
    observed_count = sum(attempt.get("usage_status") == "observed" for attempt in attempts)
    observed_average = round(tokens / observed_count, 1) if observed_count else None
    observed_cache_ratio = (
        round(cache_read / tokens, 4) if tokens else 0.0 if observed_count else None
    )
    complete = attempt_count > 0 and observed_count == attempt_count
    return {
        "avg_tokens": observed_average if complete else None,
        "cache_hit_ratio": observed_cache_ratio if complete else None,
        "usage_observations": {
            "attempts_observed": observed_count,
            "attempts_total": attempt_count,
            "attempt_coverage_rate": (
                round(observed_count / attempt_count, 4) if attempt_count else None
            ),
            "observed_tokens_total": tokens,
            "observed_avg_tokens": observed_average,
            "observed_cache_read_tokens": cache_read,
            "observed_cache_hit_ratio": observed_cache_ratio,
        },
    }


def _dataset_identity(cases: list[dict]) -> dict[str, object]:
    case_contracts = [
        {"name": case.get("name"), "group": case_group(case), "expected": case.get("expected")}
        for case in cases
    ]
    encoded = json.dumps(case_contracts, sort_keys=True, separators=(",", ":"))
    return {
        "case_set_digest": hashlib.sha256(encoded.encode()).hexdigest(),
        "case_ids": [str(case.get("name")) for case in cases],
        "groups": sorted({case_group(case) for case in cases}),
        "evaluator_version": EVALUATOR_VERSION,
        # Model/provider settings mirror the durable worker, while orchestration and activity
        # retries do not run under Temporal in this evaluator. Latency and failure behavior are
        # only comparable between runs carrying this same execution contract.
        "execution_mode": EVAL_EXECUTION_MODE,
    }


def _pricing_label(model_name: str) -> str:
    """Whether this run's dollar figures are money, a self-hosted zero, or unknown.

    Routed through the same estimator the eval loop uses, so it cannot claim a cost is real
    when the price table has nothing for the model. Stored on the experiment because a cost
    comparison across two models priced differently is not a comparison at all -- a
    self-hosted model always "wins" on cost against a billed one, for no reason worth acting
    on -- and after the fact there is no way to tell which kind of zero a zero was.
    """
    try:
        from infosec_harness.evals.inert_gates import pricing_status

        return pricing_status(model_name).value
    except Exception:
        return "undetermined"


class TruncatedExperiment(SystemExit):
    """A run stopped on an infrastructure failure after some cases had already been scored.

    The completed cases are persisted before this is raised, so a long run is not lost — but
    it is raised (non-zero exit) because a truncated experiment is a failed run, not a smaller
    one. ``experiment_id`` is the partial experiment; ``truncation`` is the record stored in
    its metrics.
    """

    def __init__(self, experiment_id: str, truncation: dict) -> None:
        self.experiment_id = experiment_id
        self.truncation = truncation
        super().__init__(
            f"experiment {experiment_id} TRUNCATED after "
            f"{truncation['completed_runs']}/{truncation['planned_runs']} case runs "
            f"({truncation['completed_cases']}/{truncation['planned_cases']} dataset cases): "
            f"{truncation['error_type']}: {truncation['error']} "
            f"— failed on case {truncation['failed_case']!r} repetition "
            f"{truncation['failed_repetition']}. The completed cases are saved as "
            f"EXPERIMENT_ID={experiment_id}, marked status=truncated: its metrics cover only "
            f"the cases that ran and must not be compared against a complete experiment."
        )


async def run_experiment(
    agent: str,
    *,
    overlay: Path | Mapping[str, object] | None = None,
    repeat: int = 1,
    report: Path | None = None,
    model: str | None = None,
    groups: set[str] | None = None,
    split: str | None = None,
) -> str:
    """Run an agent's dataset, score it, and persist the experiment.

    Persistence is incremental: the experiment row and its case results are written as each
    case finishes, so an endpoint failure (or a kill) partway through a long ``--repeat`` run
    keeps the work already scored instead of discarding it. An experiment is only marked
    ``status=complete`` once every planned case run has been scored; a run cut short is stored
    as ``status=truncated`` with the error and the count, and raises
    :class:`TruncatedExperiment` so the failure is not mistaken for a smaller-but-clean run.
    """
    if agent not in ADAPTERS:
        raise SystemExit(f"No eval adapter for agent {agent!r}. Available: {sorted(ADAPTERS)}")
    from infosec_harness.agents.registry import (
        build_agent,
        config_hash,
        load_spec,
        resolve_agent_config,
    )
    from infosec_harness.persistence import db

    overlay_data = yaml.safe_load(overlay.read_text()) if isinstance(overlay, Path) else overlay
    agent_overlay = (overlay_data or {}).get(agent)
    if model:
        # `--model` is the one-variable-at-a-time knob the playbook's comparison method asks
        # for, expressed as the smallest possible overlay so nothing else moves with it. It is
        # applied *after* any --overlay file, because naming a model on the command line is the
        # more specific instruction.
        agent_overlay = {**(agent_overlay or {}), "model": model}
    dataset_path = get_settings().agents_dir / agent / "evals" / "dataset.yaml"
    dataset = yaml.safe_load(dataset_path.read_text())
    all_cases = dataset["cases"]
    cases = [case for case in all_cases if groups is None or case_group(case) in groups]
    if not cases:
        raise ValueError(f"no cases selected for groups {sorted(groups or ())}")
    version = str(dataset.get("version", "1"))

    # The runner itself is local, while the model/provider contract intentionally mirrors the
    # durable worker. This keeps transport retry settings in the effective identity and on the
    # actual client aligned with production without requiring a Temporal activity context.
    built = build_agent(agent, agent_overlay, durable=False, production_transport=True)
    spec = load_spec(agent, agent_overlay)
    cfg_hash = config_hash(agent, spec, durable=True)
    base_effective_config = resolve_agent_config(agent, spec, durable=True)
    dataset_identity = _dataset_identity(cases)
    # build_agent already applied the overlay; run through it directly for accounting.
    from infosec_harness.agents import models as model_factory

    model_tier = spec.model or "sonnet"
    model_name = model_factory.resolved_model_name(agent, model_tier)
    # "<backend>:<id>" is what the factory returns; the backend half is what decides whether a
    # cost figure is money at all, so it is worth storing on its own.
    backend = model_name.split(":", 1)[0] if ":" in model_name else ""
    pricing = _pricing_label(model_name)
    code = code_version()

    overlay_label = str(overlay) if isinstance(overlay, Path) else "inline" if overlay else ""
    exp_id = (
        "exp-"
        + hashlib.sha256(
            f"{agent}:{version}:{cfg_hash}:{overlay_label}:{uuid.uuid4()}".encode()
        ).hexdigest()[:16]
    )

    total = passed = invalid_output = budget_exhausted = unevidenced_safe = 0
    execution_not_checked_outcomes = execution_checks_passed = execution_failed = 0
    completed_cases = 0
    cost = cache_read = tokens = 0.0
    cost_unknown = usage_unknown = 0
    model_requests: list[int] = []
    # Per-case series for the distributions the playbook asks for ("pass rate and worst-case
    # score / p50-p95 latency and cost / tool-call and model-request distributions"). A single
    # mean hides exactly the tail a budget is meant to brake.
    latencies: list[float] = []
    costs: list[float] = []
    tool_calls: list[int] = []
    # repetition -> [passed, total]; the worst repetition is the honest number to quote when
    # --repeat is used, because a mean across runs launders a bad one.
    per_repetition: dict[int, list[int]] = {}
    confusion: dict[tuple[str, str], int] = {}
    attempts: list[dict[str, object]] = []
    planned_runs = len(cases) * repeat
    execution_checks_planned = sum(bool(case.get("execution_check")) for case in cases) * repeat

    def build_metrics(status: str, truncation: dict | None = None) -> dict:
        execution_not_checked = max(
            0, execution_checks_planned - execution_checks_passed - execution_failed
        )
        complete_cost = round(cost, 6) if cost_unknown == 0 else None
        per_case_cost = round(cost / total, 6) if total and cost_unknown == 0 else None
        usage_metrics = _usage_metrics(attempts, tokens, cache_read)
        metrics = {
            "accuracy": round(passed / total, 4) if total else 0.0,
            "n": total,
            "passed": passed,
            "cost_usd_total": complete_cost,
            "cost_usd_per_case": per_case_cost,
            **usage_metrics,
            "confusion": {f"{k[0]}->{k[1]}": v for k, v in sorted(confusion.items())},
            "distributions": {
                "percentile_method": PERCENTILE_METHOD,
                # The worst repetition, not the mean across them: with --repeat, averaging
                # launders a bad run into an acceptable number.
                "worst_repetition_pass_rate": (
                    round(min(p / t for p, t in per_repetition.values()), 4)
                    if per_repetition
                    else 0.0
                ),
                "p50_latency_s": round(_pct(latencies, 0.50), 3),
                "p95_latency_s": round(_pct(latencies, 0.95), 3),
                "p50_cost_usd": round(_pct(costs, 0.50), 6) if costs else None,
                "p95_cost_usd": round(_pct(costs, 0.95), 6) if costs else None,
                "p50_model_requests": int(_pct([float(x) for x in model_requests], 0.50)),
                "p95_model_requests": _p95(model_requests),
                "p50_tool_calls": int(_pct([float(x) for x in tool_calls], 0.50)),
                "p95_tool_calls": int(_pct([float(x) for x in tool_calls], 0.95)),
                # Why cases failed, not just how many: a wrong answer, a run stopped by its
                # budget, and an output that never validated are three different problems.
                "failure_categories": {
                    "wrong_answer": (
                        total
                        - passed
                        - budget_exhausted
                        - invalid_output
                        - execution_not_checked_outcomes
                        - execution_failed
                    ),
                    "budget_exhausted": budget_exhausted,
                    "invalid_output": invalid_output,
                    "execution_not_checked": execution_not_checked_outcomes,
                    "execution_failed": execution_failed,
                },
            },
            # Named to match the release policy's gates and thresholds so the contract is
            # executable rather than aspirational (agent-playbook §7).
            "task_success_rate": round(passed / total, 4) if total else 0.0,
            "schema_validity_rate": round((total - invalid_output) / total, 4) if total else 0.0,
            "budget_exhausted_count": budget_exhausted,
            "budget_enforcement_violations": 0,
            "expected_budget_stops": sum(
                1
                for attempt in attempts
                if attempt.get("outcome") == "budget_exhausted"
                and attempt.get("expected") == "budget_exhausted"
            ),
            "unexpected_budget_stops": sum(
                1
                for attempt in attempts
                if attempt.get("outcome") == "budget_exhausted"
                and attempt.get("expected") != "budget_exhausted"
            ),
            "usage_unknown": usage_unknown,
            "cost_unknown": cost_unknown,
            "average_cost_usd": per_case_cost,
            "p95_model_requests": _p95(model_requests),
            "unevidenced_safe_verdicts": unevidenced_safe,
            # Execution-backed cases are material quality checks. Missing secure runtime or
            # stub mode is unknown evidence and must remain a failing hard-gate value.
            "execution_not_checked_count": execution_not_checked,
            "execution_failed_count": execution_failed,
            "execution_checks_planned": execution_checks_planned,
            "execution_checks_passed": execution_checks_passed,
            # Coverage travels with the numbers: every metric above is over `n` of
            # `n_planned` case runs, and only `status == "complete"` means they are equal.
            # `harness eval compare` refuses to read anything else as a like-for-like run.
            "status": status,
            "n_planned": planned_runs,
            "cases_planned": len(cases),
            "cases_completed": completed_cases,
            "attempted_runs": len(attempts),
            "attempts": attempts,
            "comparison_identity": {
                **dataset_identity,
                "dataset_version": version,
                "repetitions": repeat,
                "split": split or "full",
            },
            "effective_configuration": base_effective_config.model_dump(mode="json"),
            "code_identity": code.as_dict(),
        }
        if truncation is not None:
            metrics["truncated"] = truncation
        return metrics

    async def persist(status: str, rows: list, truncation: dict | None = None) -> None:
        """Upsert the experiment with the metrics so far and append the new case rows.

        Called after every case, so what has been scored is already durable when the next
        model call fails or the process is killed.
        """
        async with db.session() as s:
            await s.merge(
                db.EvalExperiment(
                    id=exp_id,
                    agent=agent,
                    dataset=str(dataset_path.name),
                    dataset_version=version,
                    git_sha=code.git_commit,
                    git_dirty=code.git_dirty,
                    harness_version=code.harness_version,
                    overlay=overlay_label,
                    config_hash=cfg_hash,
                    model_tier=model_tier,
                    model_name=model_name,
                    backend=backend,
                    pricing=pricing,
                    repetitions=repeat,
                    metrics=build_metrics(status, truncation),
                )
            )
            for row in rows:
                s.add(row)
            await s.commit()

    from pydantic_ai.exceptions import UnexpectedModelBehavior, UsageLimitExceeded

    await db.create_all()
    # Claim the row before the first model call: a run that dies on case 1 is still a visible
    # `status=running` experiment rather than nothing at all.
    await persist("running", [])

    truncation: dict | None = None
    case_name = ""
    rep = 0
    # Rows scored but not yet committed. Never more than one case's worth, and flushed on the
    # way out too, so the persisted rows always match the persisted counters.
    pending_rows: list = []
    try:
        for case in cases:
            case_name = case["name"]
            task_text, payload, deps, predict, expected = ADAPTERS[agent](case)
            for rep in range(repeat):
                prompt = render_prompt(task_text, payload)
                invocation_config = resolve_agent_config(
                    agent, spec, source_files=deps.source_files, durable=True
                )
                started = time.monotonic()
                usage_record: dict[str, object] | None = None
                outcome = "answered"
                diagnostic: dict[str, object] = {}
                messages = []
                try:
                    with capture_run_messages() as messages:
                        result = await run_with_timeout(
                            built.run(
                                prompt,
                                deps=deps,
                                usage_limits=invocation_config.budget.to_usage_limits(),
                            ),
                            seconds=get_settings().agent_run_timeout_s,
                        )
                    predicted = predict(result.output)
                    diagnostic["typed_output"] = _bounded_typed_output(result.output)
                    from infosec_harness.evals.execution_checks import run_execution_check

                    execution = await run_execution_check(
                        case, result.output, stub=pricing == "stub"
                    )
                    if execution is not None:
                        predicted = execution.predicted
                        diagnostic["execution_check"] = execution.as_score()
                        if execution.status == "not_checked":
                            outcome = "execution_not_checked"
                            execution_not_checked_outcomes += 1
                        elif execution.status == "failed":
                            outcome = "execution_failed"
                            execution_failed += 1
                        elif execution.status == "passed":
                            execution_checks_passed += 1
                    from infosec_harness.evals.probe_execution import evaluate_probe_execution

                    probe_check = await evaluate_probe_execution(
                        agent, case, result.output, stub=pricing == "stub"
                    )
                    if probe_check is not None:
                        # Same-process tracing is useful diagnostic evidence, but candidate
                        # code can tamper with or forge it. It must not change the structural
                        # score or satisfy release-grade execution gates.
                        diagnostic["probe_observation"] = probe_check.as_score()
                    requests = result.usage.requests or 0
                    model_requests.append(requests)
                    messages = result.all_messages()
                    c, _ = model_factory.estimate_cost(model_name, result.usage)
                    if c is None and pricing in {"stub", "zero_priced"}:
                        c = 0.0
                    elif c is None:
                        cost_unknown += 1
                    tokens += result.usage.input_tokens + result.usage.output_tokens
                    cache_read += result.usage.cache_read_tokens or 0
                    usage_record = {
                        "requests": requests,
                        "input_tokens": result.usage.input_tokens,
                        "output_tokens": result.usage.output_tokens,
                        "cache_read_tokens": result.usage.cache_read_tokens or 0,
                        "cache_write_tokens": result.usage.cache_write_tokens or 0,
                    }
                except (UsageLimitExceeded, AgentRunTimeout) as exc:
                    diagnostic = {
                        "error_type": "UsageLimitExceeded" if isinstance(exc, UsageLimitExceeded) else "AgentRunTimeout",
                        "error_category": "budget_exhausted",
                        "budget_stop": budget_stop_diagnostic(exc, invocation_config.budget, messages),
                    }
                    # The run hit its declared budget: it was stopped, not answered. This is a
                    # hard gate, so it is counted separately from a wrong answer.
                    predicted, c = (
                        "budget_exhausted",
                        (0.0 if pricing in {"stub", "zero_priced"} else None),
                    )
                    outcome = "budget_exhausted"
                    if check := case.get("execution_check"):
                        diagnostic["execution_check"] = {
                            "status": "not_checked",
                            "check": check,
                            "reason": "agent output unavailable after budget stop",
                            "execution_mode": "not-run-no-typed-output-v1",
                        }
                    budget_exhausted += 1
                    usage_unknown += 1
                    cost_unknown += int(c is None)
                except UnexpectedModelBehavior:
                    diagnostic = {
                        "error_type": "UnexpectedModelBehavior",
                        "error_category": "no_accepted_output",
                        "provider_body_retained": False,
                    }
                    # This exception also covers exhausted function-tool retries and provider
                    # protocol failures. No typed answer was accepted; do not claim that the
                    # output schema itself was the cause. Keep the conservative failure gate
                    # and omit exception/provider text, which may contain sensitive content.
                    predicted, c = (
                        "invalid_output",
                        (0.0 if pricing in {"stub", "zero_priced"} else None),
                    )
                    outcome = "invalid_output"
                    if check := case.get("execution_check"):
                        diagnostic["execution_check"] = {
                            "status": "not_checked",
                            "check": check,
                            "reason": "agent output unavailable after no accepted output",
                            "execution_mode": "not-run-no-typed-output-v1",
                        }
                    invalid_output += 1
                    usage_unknown += 1
                    cost_unknown += int(c is None)
                except BaseException as exc:
                    latency = time.monotonic() - started
                    usage_unknown += 1
                    failed_cost_unknown = pricing not in {"stub", "zero_priced"}
                    cost_unknown += int(failed_cost_unknown)
                    attempts.append(
                        {
                            "case": case_name,
                            "group": case_group(case),
                            "repetition": rep,
                            "expected": expected,
                            "outcome": "failed",
                            "call_summary": summarize_calls(messages),
                            "output_retry_summary": output_retry_summary(messages, agent=agent),
                            **failure_diagnostic(exc),
                            "latency_s": latency,
                            "usage": None,
                            "usage_status": "unknown",
                            "planning_window": planning_window_diagnostic(
                                spec.metadata or {}, invocation_config.budget.effective.max_requests, None
                            ),
                            "cost_usd": None if failed_cost_unknown else 0.0,
                            "cost_status": "unknown" if failed_cost_unknown else "known_zero",
                            "effective_config_digest": invocation_config.digest,
                            "effective_budget_digest": invocation_config.budget.digest,
                        }
                    )
                    raise
                # Recorded on every path, including the two failure branches above: a run
                # that was stopped by its budget still took time, and excluding it would make
                # the latency distribution describe only the cases that behaved.
                diagnostic["planning_window"] = planning_window_diagnostic(
                    spec.metadata or {}, invocation_config.budget.effective.max_requests,
                    usage_record["requests"] if usage_record is not None else None,
                )
                diagnostic["call_summary"] = summarize_calls(messages)
                diagnostic["output_retry_summary"] = output_retry_summary(messages, agent=agent)
                tool_calls.append(diagnostic["call_summary"]["tool_call_count"])
                latency = time.monotonic() - started
                latencies.append(latency)
                if c is not None:
                    costs.append(c)
                attempts.append(
                    {
                        "case": case_name,
                        "group": case_group(case),
                        "repetition": rep,
                        "expected": expected,
                        "outcome": outcome,
                        "latency_s": latency,
                        "usage": usage_record,
                        "usage_status": "observed" if usage_record is not None else "unknown",
                        "cost_usd": c,
                        "cost_status": (
                            "known_zero"
                            if c == 0.0 and pricing in {"stub", "zero_priced"}
                            else "observed"
                            if c is not None
                            else "unknown"
                        ),
                        "effective_config_digest": invocation_config.digest,
                        "effective_budget_digest": invocation_config.budget.digest,
                        **diagnostic,
                    }
                )
                if is_unevidenced_safe(agent, case, predicted):
                    unevidenced_safe += 1
                ok = predicted == expected
                per_repetition[rep] = per_repetition.get(rep, [0, 0])
                per_repetition[rep][0] += int(ok)
                per_repetition[rep][1] += 1
                total += 1
                passed += int(ok)
                cost += c or 0.0
                confusion[(expected, predicted)] = confusion.get((expected, predicted), 0) + 1
                pending_rows.append(
                    db.EvalCaseResult(
                        experiment_id=exp_id,
                        case_name=case["name"],
                        repetition=rep,
                        passed=ok,
                        scores={
                            "expected": expected,
                            "predicted": predicted,
                            "outcome": outcome,
                            "usage": usage_record,
                            "usage_status": "observed" if usage_record is not None else "unknown",
                            "cost_usd": c,
                            "cost_status": attempts[-1]["cost_status"],
                            "group": case_group(case),
                            "effective_config_digest": invocation_config.digest,
                            "effective_budget": invocation_config.budget.model_dump(mode="json"),
                            **diagnostic,
                        },
                        # Legacy non-null column: truth lives in scores.cost_usd/status when unknown.
                        cost_usd=c or 0.0,
                        latency_s=latency,
                    )
                )
            completed_cases += 1
            await persist("running", pending_rows)
            pending_rows = []
    except BaseException as exc:
        # Anything the per-case handlers above did not classify is not an answer about the
        # model: it is the run falling over (transport error, a cancelled/hung request, Ctrl-C,
        # a bug in an adapter). Record where it stopped, keep the scored cases, then fail.
        truncation = {
            **failure_diagnostic(exc),
            "failed_case": case_name,
            "failed_repetition": rep,
            "completed_runs": total,
            "planned_runs": planned_runs,
            "completed_cases": completed_cases,
            "planned_cases": len(cases),
        }
        await persist("truncated", pending_rows, truncation)
        print(
            f"experiment {exp_id}: TRUNCATED on case {case_name!r} rep {rep} after "
            f"{total}/{planned_runs} case runs ({truncation['error_type']}, "
            f"http_status_code={truncation['http_status_code']}); "
            f"the {total} scored case runs are saved and the experiment is marked truncated"
        )
        if report is not None:
            print(
                f"no release report written to {report}: a truncated run cannot clear "
                f"release gates it did not measure"
            )
        if isinstance(exc, KeyboardInterrupt | SystemExit | asyncio.CancelledError):
            raise  # an interrupt or a cancellation keeps its own semantics
        raise TruncatedExperiment(exp_id, truncation) from exc

    metrics = build_metrics("complete")
    await persist("complete", pending_rows)

    cost_label = (
        f"${metrics['cost_usd_per_case']:.4f}"
        if metrics["cost_usd_per_case"] is not None
        else "unknown"
    )
    cache_label = (
        f"{metrics['cache_hit_ratio']:.2%}" if metrics["cache_hit_ratio"] is not None else "unknown"
    )
    print(
        f"experiment {exp_id}: accuracy={metrics['accuracy']:.2%} "
        f"cost/case={cost_label} cache_hit={cache_label} "
        f"(model {model_name} [{pricing}], config {cfg_hash}, code {code.label()})"
    )
    if code.git_dirty:
        # Said once, at the point the number is produced: this result cannot be filed against
        # a commit, so it is not a baseline and is not reproducible from the SHA it carries.
        print(
            "  ! the working tree is dirty, so this result does not describe "
            f"{code.git_commit[:12] or 'any commit'} -- commit before recording a baseline"
        )
    if report is not None:
        write_release_report(
            report,
            agent=agent,
            metrics=metrics,
            cfg_hash=cfg_hash,
            model_name=model_name,
            dataset_version=version,
            experiment_id=exp_id,
            repeat=repeat,
            spec=spec,
            agent_version=str((spec.metadata or {}).get("version", "0.0.0")),
            extra_gates={
                **(
                    {"unevidenced_safe_verdicts": metrics["unevidenced_safe_verdicts"]}
                    if agent in UNEVIDENCED_SAFETY_AGENTS
                    else {}
                ),
                **(
                    {
                        "execution_not_checked_count": metrics["execution_not_checked_count"],
                        "execution_failed_count": metrics["execution_failed_count"],
                    }
                    if agent == "build-repair"
                    else {}
                ),
            },
        )
        print(f"release report written to {report}")
    return exp_id


PERCENTILE_METHOD = "nearest-rank-v1"


def _pct(values: list[float], q: float) -> float:
    """Nearest-rank percentile, 0.0 when nothing ran. Small samples, so no interpolation."""
    if not values:
        return 0.0
    if not 0.0 <= q <= 1.0:
        raise ValueError(f"percentile must be between 0 and 1, got {q}")
    ordered = sorted(values)
    # Nearest-rank is the observation at ceil(q * N), using one-based ranks. Clamp q=0
    # to the first observation so the helper remains defined on the closed interval.
    index = max(0, math.ceil(q * len(ordered)) - 1)
    return ordered[index]


def _p95(values: list[int]) -> int:
    """The 95th percentile, or 0 when nothing ran. Nearest-rank on a small sample."""
    return int(_pct([float(value) for value in values], 0.95))


# Public compatibility surface. Cohesive corpus and reporting implementations live in focused
# modules, while existing callers can continue importing these names from ``evals.run``.
from infosec_harness.evals.corpus_run import _stage_results, score_corpus  # noqa: E402
from infosec_harness.evals.reporting import (  # noqa: E402
    IncomparableExperiments,
    comparability_issues,
    compare_experiments,
    compare_models_for,
    comparison_table,
    list_experiments,
    save_baseline,
    sweep_models,
    write_release_report,
)

__all__ = [
    "IncomparableExperiments",
    "TruncatedExperiment",
    "_stage_results",
    "case_group",
    "comparability_issues",
    "compare_experiments",
    "compare_models_for",
    "comparison_table",
    "list_experiments",
    "run_experiment",
    "save_baseline",
    "score_corpus",
    "sweep_models",
    "write_release_report",
]
