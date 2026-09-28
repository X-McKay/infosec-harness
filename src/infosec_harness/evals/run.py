"""Per-agent evaluation (§10): run an agent's dataset, score deterministically, persist.

An experiment = dataset version x agent config x repetitions. Results (accuracy, cost,
latency, cache-hit) go to Postgres so ``harness eval compare`` can show the tradeoffs of a
model/prompt/skill change with an evidence-based, one-variable-at-a-time method.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import platform
import subprocess
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import yaml

from infosec_harness.agents.render import render_prompt
from infosec_harness.evals.adapters import (
    ADAPTERS,
    UNEVIDENCED_SAFETY_AGENTS,
    is_unevidenced_safe,
)
from infosec_harness.evals.coverage import coverage_for
from infosec_harness.evals.trajectory import inspect_messages, scores_skills
from infosec_harness.settings import get_settings


def _spread(values: list[float]) -> str:
    """`mean` when one sample, `mean [min-max]` when several — so noise is visible."""
    mean = sum(values) / len(values)
    if len(values) == 1:
        return f"{mean:.0%}"
    return f"{mean:.0%} [{min(values):.0%}-{max(values):.0%}]"


# The pipeline's stages, in order, each scored against ground truth the manifest already
# carries. A single accuracy number says a case failed; it cannot say *where*, and locating that
# by hand meant reading raw traces for every failure. Each entry is
# (label, applies_to_case, verdict_fn) where verdict_fn returns True/False, or None for "this
# stage did not get to run", which is counted separately so a late-stage rate is never inflated
# by the cases that never reached it.
def _stage_results(case, out) -> list[tuple[str, bool | None]]:
    """Score one case at each stage. None means the stage was never reached."""
    ctx = out.context
    execs = out.executions
    last = execs[-1] if execs else None
    probes = case.early_exit is None  # `testonly` is meant to stop before a probe

    def sink_located() -> bool | None:
        if ctx is None or ctx.sink is None:
            return None if ctx is None else False
        # The line is what the probe author actually needs; the file alone is not enough.
        # A CodeRef may legitimately span the whole statement, so the truth line must fall
        # inside the range rather than equal its start.
        if ctx.sink.file_path != case.sink_file:
            return False
        last = ctx.sink.end_line or ctx.sink.start_line
        return ctx.sink.start_line <= case.sink_line <= last

    return [
        ("environment built", out.prepared_status == "ready"),
        ("context: reachability", None if ctx is None else ctx.reachability.value == case.reachability),
        ("context: sink located", sink_located()),
        ("context: target callable",
         None if ctx is None else ctx.target_callable == case.target_callable),
        ("probe reached the sink",
         None if not probes else (last.precondition_reached if last else False)),
        ("probe's sink returned",
         None if not probes else (last.sink_returned if last else False)),
        # Gated on the sink having returned, not merely on a probe existing. A silent oracle
        # after a probe that never ran is not agreement -- and on the `fixed` half it would
        # score as a pass for the same reason a zero-test run once scored as a clean negative.
        ("oracle agreed with truth",
         None if not probes or last is None or not last.sink_returned
         else last.oracle_fired == (case.expected_verdict == "potentially_exploitable")),
        ("verdict", out.result.verdict.label.value == case.expected_verdict),
    ]


async def score_corpus(*, language: str = "python", sandbox: bool | None = None,
                       repeat: int = 1, manifest_path: Path | None = None,
                       dataset: str = "seed", limit: int = 0) -> dict:
    """Run the seeded corpus end-to-end and score verdicts against ground truth (§10.2).

    Headline metrics: per-class recall and the false-negative rate on truly exploitable
    cases (the costliest error). With stub models the verdicts are not meaningful (the stub
    is not a judge) — this is the harness that lights up under a live model.
    `sandbox=None` auto-detects the gVisor runtime.

    `language="all"` sweeps every language in the corpus. `repeat` runs the whole thing
    more than once and reports the spread: the corpus is small and the model is stochastic,
    so a single pass has enough run-to-run variance (measured: one agent's skill-evocation
    rate moved between 0% and 44% with no change at all) that comparing two one-pass runs
    cannot separate a real effect from noise. Repeat both sides of an A/B.
    """
    from infosec_harness.evals.corpus import languages as corpus_languages
    from infosec_harness.evals.corpus import load_corpus

    if language == "all" and manifest_path is not None:
        # `languages()` reads the seeded manifest, so sweeping a harvested one has to come
        # from the harvested file rather than from the seed's language list.
        langs = sorted({c.language for c in load_corpus(manifest_path=manifest_path)})
    else:
        langs = corpus_languages() if language == "all" else [language]
    runs: list[dict] = []
    for rep in range(repeat):
        for lang in langs:
            if len(langs) > 1 or repeat > 1:
                print(f"--- {lang}" + (f" (pass {rep + 1}/{repeat})" if repeat > 1 else ""))
            runs.append({"language": lang, **await _score_corpus_once(
                language=lang, sandbox=sandbox, manifest_path=manifest_path,
                dataset=dataset, limit=limit)})
    if len(runs) == 1:
        return runs[0]

    agents = sorted({a for r in runs for a in r["trajectory"]})
    summary = {
        "runs": runs,
        "languages": langs,
        "repeat": repeat,
        "n": sum(r["n"] for r in runs),
        "accuracy_mean": round(sum(r["accuracy"] for r in runs) / len(runs), 4),
        "accuracy_min": min(r["accuracy"] for r in runs),
        "accuracy_max": max(r["accuracy"] for r in runs),
        "trajectory": {
            a: {
                "n": sum(r["trajectory"][a]["n"] for r in runs if a in r["trajectory"]),
                "tool_use_rate_mean": round(_mean_rate(runs, a, "tool_use_rate"), 3),
                "skill_use_rate_mean": round(_mean_rate(runs, a, "skill_use_rate"), 3),
            }
            for a in agents
        },
    }
    print("\n=== aggregate over "
          f"{len(runs)} run(s): {', '.join(langs)}"
          + (f" x{repeat}" if repeat > 1 else "") + " ===")
    print(f"accuracy {_spread([r['accuracy'] for r in runs])}  "
          f"FN-on-exploitable {_spread([r['false_negative_rate_on_exploitable'] for r in runs])}")
    print("tool/skill evocation:")
    for a in agents:
        tools = [r["trajectory"][a]["tool_use_rate"] for r in runs if a in r["trajectory"]]
        skills = [r["trajectory"][a]["skill_use_rate"] for r in runs if a in r["trajectory"]]
        skill_col = _spread(skills) if scores_skills(a) else "n/a (no expectation)"
        print(f"  {a:14} tools {_spread(tools):18} skills {skill_col}")
    return summary


def _mean_rate(runs: list[dict], agent: str, key: str) -> float:
    """Weight each run's rate by the cases it saw, so languages don't count equally."""
    num = sum(r["trajectory"][agent][key] * r["trajectory"][agent]["n"]
              for r in runs if agent in r["trajectory"])
    den = sum(r["trajectory"][agent]["n"] for r in runs if agent in r["trajectory"])
    return num / den if den else 0.0


def _git_sha() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()[:40]
    except Exception:
        return ""


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


async def run_experiment(agent: str, *, overlay: Path | None = None, repeat: int = 1,
                         report: Path | None = None) -> str:
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
    from infosec_harness.agents.registry import build_agent, config_hash, load_spec
    from infosec_harness.persistence import db

    overlay_data = yaml.safe_load(overlay.read_text()) if overlay else None
    agent_overlay = (overlay_data or {}).get(agent)
    dataset_path = get_settings().agents_dir / agent / "evals" / "dataset.yaml"
    dataset = yaml.safe_load(dataset_path.read_text())
    cases = dataset["cases"]
    version = str(dataset.get("version", "1"))

    built = build_agent(agent, agent_overlay, durable=False)
    spec = load_spec(agent, agent_overlay)
    cfg_hash = config_hash(agent, spec)
    # build_agent already applied the overlay; run through it directly for accounting.
    from infosec_harness.agents import models as model_factory

    model_name = model_factory.resolved_model_name(agent, spec.model or "sonnet")

    exp_id = "exp-" + hashlib.sha256(
        f"{agent}:{version}:{cfg_hash}:{overlay}:{uuid.uuid4()}".encode()).hexdigest()[:16]

    total = passed = invalid_output = budget_exhausted = unevidenced_safe = 0
    completed_cases = 0
    cost = cache_read = tokens = 0.0
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
    planned_runs = len(cases) * repeat

    def build_metrics(status: str, truncation: dict | None = None) -> dict:
        metrics = {
            "accuracy": round(passed / total, 4) if total else 0.0,
            "n": total, "passed": passed,
            "cost_usd_total": round(cost, 6), "cost_usd_per_case": round(cost / total, 6) if total else 0.0,
            "avg_tokens": round(tokens / total, 1) if total else 0.0,
            "cache_hit_ratio": round(cache_read / tokens, 4) if tokens else 0.0,
            "confusion": {f"{k[0]}->{k[1]}": v for k, v in sorted(confusion.items())},
            "distributions": {
                # The worst repetition, not the mean across them: with --repeat, averaging
                # launders a bad run into an acceptable number.
                "worst_repetition_pass_rate": (
                    round(min(p / t for p, t in per_repetition.values()), 4)
                    if per_repetition else 0.0),
                "p50_latency_s": round(_pct(latencies, 0.50), 3),
                "p95_latency_s": round(_pct(latencies, 0.95), 3),
                "p50_cost_usd": round(_pct(costs, 0.50), 6),
                "p95_cost_usd": round(_pct(costs, 0.95), 6),
                "p50_model_requests": int(_pct([float(x) for x in model_requests], 0.50)),
                "p95_model_requests": _p95(model_requests),
                "p50_tool_calls": int(_pct([float(x) for x in tool_calls], 0.50)),
                "p95_tool_calls": int(_pct([float(x) for x in tool_calls], 0.95)),
                # Why cases failed, not just how many: a wrong answer, a run stopped by its
                # budget, and an output that never validated are three different problems.
                "failure_categories": {
                    "wrong_answer": total - passed - budget_exhausted - invalid_output,
                    "budget_exhausted": budget_exhausted,
                    "invalid_output": invalid_output,
                },
            },
            # Named to match the release policy's gates and thresholds so the contract is
            # executable rather than aspirational (agent-playbook §7).
            "task_success_rate": round(passed / total, 4) if total else 0.0,
            "schema_validity_rate": round((total - invalid_output) / total, 4) if total else 0.0,
            "budget_exhausted_count": budget_exhausted,
            "average_cost_usd": round(cost / total, 6) if total else 0.0,
            "p95_model_requests": _p95(model_requests),
            "unevidenced_safe_verdicts": unevidenced_safe,
            # Coverage travels with the numbers: every metric above is over `n` of
            # `n_planned` case runs, and only `status == "complete"` means they are equal.
            # `harness eval compare` refuses to read anything else as a like-for-like run.
            "status": status,
            "n_planned": planned_runs,
            "cases_planned": len(cases),
            "cases_completed": completed_cases,
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
            await s.merge(db.EvalExperiment(
                id=exp_id, agent=agent, dataset=str(dataset_path.name),
                dataset_version=version, git_sha=git_sha,
                overlay=str(overlay) if overlay else "", config_hash=cfg_hash,
                repetitions=repeat, metrics=build_metrics(status, truncation)))
            for row in rows:
                s.add(row)
            await s.commit()

    from pydantic_ai.exceptions import UnexpectedModelBehavior, UsageLimitExceeded

    git_sha = _git_sha()
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
                started = time.monotonic()
                try:
                    result = await built.run(prompt, deps=deps)
                    predicted = predict(result.output)
                    model_requests.append(result.usage.requests)
                    tool_calls.append(len(inspect_messages(result.all_messages())[0]))
                    c, _ = model_factory.estimate_cost(model_name, result.usage)
                    tokens += result.usage.input_tokens + result.usage.output_tokens
                    cache_read += result.usage.cache_read_tokens or 0
                except UsageLimitExceeded:
                    # The run hit its declared budget: it was stopped, not answered. This is a
                    # hard gate, so it is counted separately from a wrong answer.
                    predicted, c = "budget_exhausted", 0.0
                    budget_exhausted += 1
                except UnexpectedModelBehavior:
                    # The model could not produce a valid output within its retry budget
                    # (e.g. it kept violating an output contract). That is a failed case, and an
                    # output that does not validate is no answer rather than a wrong one.
                    predicted, c = "invalid_output", 0.0
                    invalid_output += 1
                # Recorded on every path, including the two failure branches above: a run
                # that was stopped by its budget still took time, and excluding it would make
                # the latency distribution describe only the cases that behaved.
                latencies.append(time.monotonic() - started)
                costs.append(c or 0.0)
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
                pending_rows.append(db.EvalCaseResult(
                    experiment_id=exp_id, case_name=case["name"], repetition=rep, passed=ok,
                    scores={"expected": expected, "predicted": predicted}, cost_usd=c or 0.0))
            completed_cases += 1
            await persist("running", pending_rows)
            pending_rows = []
    except BaseException as exc:
        # Anything the per-case handlers above did not classify is not an answer about the
        # model: it is the run falling over (transport error, a cancelled/hung request, Ctrl-C,
        # a bug in an adapter). Record where it stopped, keep the scored cases, then fail.
        truncation = {
            "error_type": type(exc).__name__,
            "error": str(exc)[:500] or repr(exc)[:500],
            "failed_case": case_name,
            "failed_repetition": rep,
            "completed_runs": total,
            "planned_runs": planned_runs,
            "completed_cases": completed_cases,
            "planned_cases": len(cases),
        }
        await persist("truncated", pending_rows, truncation)
        print(f"experiment {exp_id}: TRUNCATED on case {case_name!r} rep {rep} after "
              f"{total}/{planned_runs} case runs ({type(exc).__name__}: {str(exc)[:200]}); "
              f"the {total} scored case runs are saved and the experiment is marked truncated")
        if report is not None:
            print(f"no release report written to {report}: a truncated run cannot clear "
                  f"release gates it did not measure")
        if isinstance(exc, KeyboardInterrupt | SystemExit | asyncio.CancelledError):
            raise  # an interrupt or a cancellation keeps its own semantics
        raise TruncatedExperiment(exp_id, truncation) from exc

    metrics = build_metrics("complete")
    await persist("complete", pending_rows)

    print(f"experiment {exp_id}: accuracy={metrics['accuracy']:.2%} "
          f"cost/case=${metrics['cost_usd_per_case']:.4f} cache_hit={metrics['cache_hit_ratio']:.2%} "
          f"(config {cfg_hash})")
    if report is not None:
        write_release_report(
            report, agent=agent, metrics=metrics, cfg_hash=cfg_hash, model_name=model_name,
            dataset_version=version, experiment_id=exp_id, repeat=repeat, spec=spec,
            agent_version=str((spec.metadata or {}).get("version", "0.0.0")),
            extra_gates=({"unevidenced_safe_verdicts": metrics["unevidenced_safe_verdicts"]}
                         if agent in UNEVIDENCED_SAFETY_AGENTS else None),
        )
        print(f"release report written to {report}")
    return exp_id


def _pct(values: list[float], q: float) -> float:
    """Nearest-rank percentile, 0.0 when nothing ran. Small samples, so no interpolation."""
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(q * (len(ordered) - 1))))]


def _p95(values: list[int]) -> int:
    """The 95th percentile, or 0 when nothing ran. Nearest-rank on a small sample."""
    if not values:
        return 0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1))))
    return ordered[index]


def write_release_report(path: Path, *, agent: str, metrics: dict, cfg_hash: str,
                         model_name: str, dataset_version: str, agent_version: str,
                         extra_gates: dict | None = None, experiment_id: str = "",
                         repeat: int = 1, spec: object | None = None) -> None:
    """Write the report `agentctl release` compares against the agent's release policy.

    The gate and threshold names here are the policy's names; provenance is what makes a pass
    reproducible rather than a claim.
    """
    gates = {
        "schema_validity_rate": metrics["schema_validity_rate"],
        "budget_exhausted_count": metrics["budget_exhausted_count"],
        **(extra_gates or {}),
    }
    report = {
        "schema_version": 1,
        "subject": {"kind": "agent", "name": agent},
        "agent": agent,
        "hard_gates": {**gates,
                       # Zero is the only passing value: "passing average quality cannot
                       # compensate for an uncovered material risk".
                       "uncovered_material_scenarios":
                           len(coverage_for(agent).uncovered_material)},
        "metrics": {k: metrics[k] for k in
                    ("task_success_rate", "average_cost_usd", "p95_model_requests")},
        # The playbook makes uncovered material risk a release blocker, so the report must
        # carry covered *and uncovered* scenario IDs -- a report that lists only what passed
        # cannot show what was never tested.
        "coverage": coverage_for(agent).as_report(),
        # Distributions, not just means: the playbook asks for pass rate and worst case,
        # p50/p95 latency and cost, and tool-call and model-request spreads, because a single
        # average cannot show the tail a budget exists to brake.
        "distributions": metrics.get("distributions", {}),
        "provenance": {
            "git_commit": _git_sha(),
            "agent_version": agent_version,
            "config_hash": cfg_hash,
            "model": model_name,
            "dataset_version": dataset_version,
            # The rest of what the playbook's Provenance section enumerates. What makes a pass
            # reproducible is knowing which skills, toolsets and model settings produced it --
            # `config_hash` fingerprints them, but a reader cannot expand a hash.
            "recorded_at": datetime.now(UTC).isoformat(),
            "run_count": repeat,
            "experiment_id": experiment_id,
            "dataset": f"agents/{agent}/evals/dataset.yaml",
            "evaluators": ["deterministic_output_match", "schema_validity", "budget_gate",
                           "scenario_coverage"],
            # No LLM judge is used anywhere in this suite, which is deliberate: the playbook
            # forbids one as the sole evaluator for schema validity and safety properties, and
            # every gate here is deterministic. Recorded explicitly so its absence is a stated
            # fact rather than an omission.
            "judge_rubric": None,
            "model_settings": dict(getattr(spec, "model_settings", None) or {}),
            "skills": list(getattr(spec, "enabled_skills", None) or []),
            "toolsets": list(getattr(spec, "enabled_toolsets", None) or []),
            "python": platform.python_version(),
            # Case-level results (per repetition, with pass/fail and cost) are persisted to the
            # experiment store under this id rather than inlined, so the report stays readable.
            "case_results": f"experiment {experiment_id}" if experiment_id else None,
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")


async def compare_experiments(baseline: str, candidate: str) -> None:
    from infosec_harness.persistence import db

    async with db.session() as s:
        b = await s.get(db.EvalExperiment, baseline)
        c = await s.get(db.EvalExperiment, candidate)
    if b is None or c is None:
        raise SystemExit("experiment not found")

    def delta(key: str) -> str:
        bv, cv = b.metrics.get(key, 0), c.metrics.get(key, 0)
        return f"{bv:>10} -> {cv:<10} ({cv - bv:+.4f})"

    print(f"agent={b.agent}  baseline={baseline}  candidate={candidate}")
    incomplete = [(label, exp) for label, exp in (("baseline", b), ("candidate", c))
                  if exp.metrics.get("status", "complete") != "complete"]
    for label, exp in incomplete:
        # Loud and first: the deltas below are between different numbers of cases, so a
        # "+8% accuracy" here can be nothing but which cases happened to run.
        t = exp.metrics.get("truncated") or {}
        print(f"  !! {label} {exp.id} is {exp.metrics.get('status', 'incomplete').upper()}: "
              f"{exp.metrics.get('n', 0)}/{exp.metrics.get('n_planned', '?')} case runs scored"
              + (f" — stopped on case {t['failed_case']!r} ({t['error_type']}: {t['error'][:120]})"
                 if t else "")
              + ". Its metrics cover only those cases.")
    if incomplete:
        print("  !! NOT a like-for-like comparison: re-run the "
              f"{'/'.join(label for label, _ in incomplete)} side before drawing a conclusion.")
    print(f"  config      {b.config_hash} -> {c.config_hash}")
    print(f"  coverage    {b.metrics.get('n', 0)}/{b.metrics.get('n_planned', '?')} -> "
          f"{c.metrics.get('n', 0)}/{c.metrics.get('n_planned', '?')} case runs "
          f"({b.metrics.get('status', 'complete')} -> {c.metrics.get('status', 'complete')})")
    for key in ("accuracy", "cost_usd_per_case", "avg_tokens", "cache_hit_ratio"):
        print(f"  {key:18} {delta(key)}")
    print(f"  baseline confusion: {b.metrics.get('confusion')}")
    print(f"  candidate confusion: {c.metrics.get('confusion')}")


async def _score_corpus_once(*, language: str, sandbox: bool | None,
                             manifest_path: Path | None = None, dataset: str = "seed",
                             limit: int = 0) -> dict:
    """One pass over the corpus. See :func:`score_corpus`."""
    from infosec_harness.domain.models import Finding, InconclusiveReason
    from infosec_harness.evals.corpus import load_corpus
    from infosec_harness.evals.trajectory import (
        AGENT_EXPECTATIONS,
        TrajectoryExpectation,
        check_expectations,
        cwe_skill_prefix,
    )
    from infosec_harness.graph.local import triage_batch_local

    cases = load_corpus(language, manifest_path=manifest_path, dataset=dataset)
    if limit:
        # Harvested manifests run to hundreds of cases against real repositories; a bounded
        # slice keeps a first run interpretable. Pairs are kept together, since scoring one
        # half of a pair measures nothing.
        keep = {c.name.rsplit("-", 1)[0] for c in cases[:limit]}
        cases = [c for c in cases if c.name.rsplit("-", 1)[0] in keep]
    if sandbox is None:
        from infosec_harness.sandbox import docker
        sandbox = await docker.docker_available() and await docker.runtime_available()
    prepare_sink: dict[tuple[str, str], list] = {}
    # A harvested case ships the PoV test that established its ground truth, and on a `-fixed`
    # revision the fix commit put it in the tree. Strip it before any agent reads the checkout,
    # or probe-author is scored on copying rather than authoring.
    masks: dict[tuple[str, str], list[str]] = {}
    for c in cases:
        if c.mask_paths:
            masks.setdefault((c.finding.repo_url, c.finding.revision), []).extend(c.mask_paths)
    # Cache off: an eval must exercise every stage and give the same answer twice.
    outputs = await triage_batch_local([c.finding for c in cases], sandbox=sandbox,
                                       recipe_cache=False, mask_paths=masks,
                                       prepare_sink=prepare_sink)
    by_fp = {o.finding.fingerprint: o for o in outputs}

    rows, confusion = [], {}
    correct = fn = exploitable = 0
    # Cases the manifest expects to run the full pipeline, and how many of those were right
    # *and* actually got there. `accuracy` alone cannot distinguish a probed verdict from a
    # label guessed before the build.
    expected_to_probe = correct_with_evidence = 0
    unexpected_exits: list[str] = []
    # stage label -> [passed, scored, not_reached], in the order _stage_results returns them.
    stages: dict[str, list[int]] = {}
    first_failures: dict[str, list[str]] = {}
    infrastructure_failures: list[str] = []
    # Trajectory scoring: did the tool-using agents evoke the expected tools/skills?
    traj_totals: dict[str, dict[str, int]] = {}
    # Request counts and repeated identical tool calls, so a `request_limit` breach can be told
    # from honest work without re-running live. inspect_messages de-duplicates by tool name and
    # drops arguments, so without this a run that read one file eight times is byte-identical in
    # the record to one that read it once.
    budget_totals: dict[str, dict[str, int]] = {}
    worst_repeats: dict[str, dict[str, int]] = {}

    def _score_trajectory(agent: str, tools_called, skills_loaded, cwe: str | None = None,
                          requests: int = 0, repeated: dict[str, int] | None = None) -> None:
        # Recorded for every agent, including those with no expectation: an agent that burns its
        # request budget is worth seeing whether or not its tool use is scored.
        b = budget_totals.setdefault(agent, {"n": 0, "requests": 0, "max_requests": 0, "looping": 0})
        b["n"] += 1
        b["requests"] += requests
        b["max_requests"] = max(b["max_requests"], requests)
        b["looping"] += int(bool(repeated))
        for key, count in (repeated or {}).items():
            worst_repeats.setdefault(agent, {})
            worst_repeats[agent][key] = max(worst_repeats[agent].get(key, 0), count)
        base = AGENT_EXPECTATIONS.get(agent)
        if base is None:
            return
        skill_prefixes = base.skill_prefixes
        if agent == "context" and (p := cwe_skill_prefix(cwe)):
            skill_prefixes = (p,)  # require the *matching* CWE skill, not just any
        exp = TrajectoryExpectation(tool_groups=base.tool_groups, skill_prefixes=skill_prefixes)
        res = check_expectations(tools_called, skills_loaded, exp)
        t = traj_totals.setdefault(agent, {"n": 0, "tools_ok": 0, "skills_ok": 0})
        t["n"] += 1
        t["tools_ok"] += int(res.tools_ok)
        t["skills_ok"] += int(res.skills_ok)

    # Prepare-phase agents (recon, env-planner, build repair) run once per repo.
    for invs in prepare_sink.values():
        for inv in invs:
            _score_trajectory(inv.agent, inv.tools_called, inv.skills_loaded,
                              requests=inv.requests, repeated=inv.repeated_tool_calls)

    for c in cases:
        out = by_fp[Finding.compute_fingerprint(c.finding)]
        actual = out.result.verdict.label.value
        ok = actual == c.expected_verdict
        correct += int(ok)
        # An early exit the manifest did not ask for means the label was reached without the
        # mechanism under test: no build, no probe, no oracle. Measured on the Perl pair --
        # both `fixed` cases came back `likely_not_exploitable` via `unreachable_by_context`,
        # scoring as clean passes while never probing anything. Label accuracy stays label
        # accuracy, but a pass with no evidence behind it must be visible, because the same
        # reasoning applied to a vulnerable case is a false negative.
        unexpected_exit = out.result.early_exit and out.result.early_exit != c.early_exit
        if unexpected_exit:
            unexpected_exits.append(f"{c.name} ({out.result.early_exit})")
        if c.early_exit is None:
            expected_to_probe += 1
            correct_with_evidence += int(ok and not unexpected_exit)
        confusion[(c.expected_verdict, actual)] = confusion.get((c.expected_verdict, actual), 0) + 1
        if c.expected_verdict == "potentially_exploitable":
            exploitable += 1
            if actual != "potentially_exploitable":
                fn += 1  # missed a real vulnerability — the costliest error
        rows.append({"case": c.name, "expected": c.expected_verdict, "actual": actual,
                     "ok": ok, "early_exit": out.result.early_exit,
                     "unexpected_early_exit": bool(unexpected_exit),
                     "priority": out.result.priority.value,
                     # Why, not just that: a table of `inconclusive` tells you nothing about
                     # whether the environment failed, the probe was unrepairable, or the
                     # judge declined.
                     "rationale": out.result.verdict.rationale})
        # A provider outage tells us nothing about any stage. Counting it would have read
        # "environment built 1/4" on a run where the environment stage worked and the model
        # endpoint was returning 502 -- the precise misattribution this funnel exists to stop.
        if out.result.verdict.inconclusive_reason == InconclusiveReason.infrastructure_error:
            infrastructure_failures.append(c.name)
            continue
        stage_results = _stage_results(c, out)
        blamed = False
        for label, passed in stage_results:
            tally = stages.setdefault(label, [0, 0, 0])
            if passed is None:
                tally[2] += 1
                continue
            tally[1] += 1
            tally[0] += int(passed)
            # Attribute each failing case to the FIRST stage that went wrong. A late stage
            # inherits every earlier mistake, so without this the blame lands on `verdict`
            # for a case whose context misread reachability three stages earlier.
            if not passed and not blamed:
                first_failures.setdefault(label, []).append(c.name)
                blamed = True

        # Per-finding triage agents (context, probe-author, ...).
        for inv in out.invocations:
            _score_trajectory(inv.agent, inv.tools_called, inv.skills_loaded, c.finding.cwe,
                              requests=inv.requests, repeated=inv.repeated_tool_calls)

    trajectory = {a: {"n": v["n"],
                      "tool_use_rate": round(v["tools_ok"] / v["n"], 3) if v["n"] else 0.0,
                      "skill_use_rate": round(v["skills_ok"] / v["n"], 3) if v["n"] else 0.0}
                  for a, v in sorted(traj_totals.items())}
    metrics = {
        "n": len(cases), "accuracy": round(correct / len(cases), 4) if cases else 0.0,
        "false_negative_rate_on_exploitable": round(fn / exploitable, 4) if exploitable else 0.0,
        "sandbox": sandbox,
        "accuracy_with_evidence": (round(correct_with_evidence / expected_to_probe, 4)
                                   if expected_to_probe else 0.0),
        "unexpected_early_exits": unexpected_exits,
        "infrastructure_failures": infrastructure_failures,
        "confusion": {f"{k[0]}->{k[1]}": v for k, v in sorted(confusion.items())},
        "trajectory": trajectory,
        "stages": {label: {"passed": p, "scored": n, "not_reached": nr,
                           "rate": round(p / n, 3) if n else None,
                           "first_failed_here": first_failures.get(label, [])}
                   for label, (p, n, nr) in stages.items()},
        "budget": {a: {"n": v["n"],
                       "mean_requests": round(v["requests"] / v["n"], 2) if v["n"] else 0.0,
                       "max_requests": v["max_requests"],
                       "runs_with_repeated_calls": v["looping"],
                       "worst_repeats": dict(sorted(worst_repeats.get(a, {}).items(),
                                                    key=lambda kv: -kv[1])[:3])}
                   for a, v in sorted(budget_totals.items())},
    }
    for r in rows:
        mark = "OK " if r["ok"] else "XX "
        print(f"  {mark}{r['case']:26} {r['expected']:24} -> {r['actual']:24} {r['early_exit'] or ''}")
        if not r["ok"] and r["rationale"]:
            # Long enough to carry the whole failure. A truncated reason costs more time than
            # the extra lines do: "UsageLimitExceeded: The" says nothing about which limit.
            print(f"        {r['rationale'][:600]}")
    print(f"accuracy={metrics['accuracy']:.0%}  FN-on-exploitable={metrics['false_negative_rate_on_exploitable']:.0%}  "
          f"sandbox={'on' if sandbox else 'off (verdicts not meaningful)'}")
    if unexpected_exits:
        print(f"accuracy-with-evidence={metrics['accuracy_with_evidence']:.0%}  "
              f"({expected_to_probe - correct_with_evidence} of {expected_to_probe} cases that "
              f"should have probed did not reach a probed verdict)")
        print(f"  unexpected early exits: {', '.join(unexpected_exits)}")
    if infrastructure_failures:
        print(f"WARNING: {len(infrastructure_failures)} of {len(cases)} cases failed on "
              f"infrastructure, not on the pipeline (model provider unreachable, timed out, or "
              f"a transport error). These are excluded from the stage funnel below, and the "
              f"accuracy above is not a measurement of anything: {', '.join(infrastructure_failures)}")
    if metrics["stages"]:
        print("stage funnel (where the pipeline actually loses cases):")
        for label, st in metrics["stages"].items():
            if not st["scored"]:
                print(f"  {label:26} --      (not reached in {st['not_reached']} cases)")
                continue
            blame = st["first_failed_here"]
            note = f"   <- first failure for {', '.join(blame)}" if blame else ""
            skipped = f"  (+{st['not_reached']} not reached)" if st["not_reached"] else ""
            print(f"  {label:26} {st['passed']}/{st['scored']}"
                  f"  {st['rate']:.0%}{skipped}{note}")
    print("tool/skill evocation (per agent, rate across cases):")
    for agent, t in trajectory.items():
        skills = f"{t['skill_use_rate']:.0%}" if scores_skills(agent) else "n/a"
        print(f"  {agent:14} tools {t['tool_use_rate']:.0%}  skills {skills}  (n={t['n']})")
    if any(v["max_requests"] for v in metrics["budget"].values()):
        print("requests per agent run (max, and identical calls repeated):")
        for agent, b in metrics["budget"].items():
            if not b["max_requests"]:
                continue
            note = ""
            if b["runs_with_repeated_calls"]:
                worst = next(iter(b["worst_repeats"].items()), None)
                note = (f"  LOOPING in {b['runs_with_repeated_calls']}/{b['n']} runs"
                        + (f", worst {worst[0]} x{worst[1]}" if worst else ""))
            # 15 wide: this section lists every agent, including probe-diagnosis, which is
            # one character wider than the tool-using agents the trajectory table covers.
            print(f"  {agent:15} max {b['max_requests']:3}  mean {b['mean_requests']:6.2f}{note}")
    return metrics
