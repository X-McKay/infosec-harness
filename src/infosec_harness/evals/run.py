"""Per-agent evaluation (§10): run an agent's dataset, score deterministically, persist.

An experiment = dataset version x agent config x repetitions. Results (accuracy, cost,
latency, cache-hit) go to Postgres so ``harness eval compare`` can show the tradeoffs of a
model/prompt/skill change with an evidence-based, one-variable-at-a-time method.
"""

from __future__ import annotations

import hashlib
import subprocess
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.agents.render import render_prompt
from infosec_harness.domain.models import VerdictFacts
from infosec_harness.evals.trajectory import scores_skills
from infosec_harness.settings import get_settings

# Per-agent adapter: (case) -> (task_text, payload, deps, predicted_label_fn, expected)
Adapter = Callable[[dict], tuple[str, dict, AgentDeps, Callable[[Any], str], str]]


def _verdict_adapter(case: dict):
    facts = VerdictFacts.model_validate(case.get("facts", {}))
    deps = AgentDeps(repo_path="/nonexistent", facts=facts)
    return ("Decide the three-way exploitability verdict from the evidence.",
            case["payload"], deps, lambda o: o.label.value, case["expected"])


def _diagnosis_adapter(case: dict):
    deps = AgentDeps(repo_path="/nonexistent")
    return ("Classify this probe execution.", case["payload"], deps,
            lambda o: o.kind.value, case["expected"])


ADAPTERS: dict[str, Adapter] = {"verdict": _verdict_adapter, "probe-diagnosis": _diagnosis_adapter}


def _spread(values: list[float]) -> str:
    """`mean` when one sample, `mean [min-max]` when several — so noise is visible."""
    mean = sum(values) / len(values)
    if len(values) == 1:
        return f"{mean:.0%}"
    return f"{mean:.0%} [{min(values):.0%}-{max(values):.0%}]"


async def score_corpus(*, language: str = "python", sandbox: bool | None = None,
                       repeat: int = 1) -> dict:
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

    langs = corpus_languages() if language == "all" else [language]
    runs: list[dict] = []
    for rep in range(repeat):
        for lang in langs:
            if len(langs) > 1 or repeat > 1:
                print(f"--- {lang}" + (f" (pass {rep + 1}/{repeat})" if repeat > 1 else ""))
            runs.append({"language": lang, **await _score_corpus_once(language=lang, sandbox=sandbox)})
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


async def run_experiment(agent: str, *, overlay: Path | None = None, repeat: int = 1) -> str:
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

    total = passed = 0
    cost = cache_read = tokens = 0.0
    case_rows = []
    confusion: dict[tuple[str, str], int] = {}

    from pydantic_ai.exceptions import UnexpectedModelBehavior

    for case in cases:
        task_text, payload, deps, predict, expected = ADAPTERS[agent](case)
        for rep in range(repeat):
            prompt = render_prompt(task_text, payload)
            try:
                result = await built.run(prompt, deps=deps)
                predicted = predict(result.output)
                c, _ = model_factory.estimate_cost(model_name, result.usage)
                tokens += result.usage.input_tokens + result.usage.output_tokens
                cache_read += result.usage.cache_read_tokens or 0
            except UnexpectedModelBehavior:
                # The model could not produce a valid output within its retry budget
                # (e.g. it kept violating an output contract). That is a failed case.
                predicted, c = "invalid_output", 0.0
            ok = predicted == expected
            total += 1
            passed += int(ok)
            cost += c or 0.0
            confusion[(expected, predicted)] = confusion.get((expected, predicted), 0) + 1
            case_rows.append(db.EvalCaseResult(
                experiment_id=exp_id, case_name=case["name"], repetition=rep, passed=ok,
                scores={"expected": expected, "predicted": predicted}, cost_usd=c or 0.0))

    metrics = {
        "accuracy": round(passed / total, 4) if total else 0.0,
        "n": total, "passed": passed,
        "cost_usd_total": round(cost, 6), "cost_usd_per_case": round(cost / total, 6) if total else 0.0,
        "avg_tokens": round(tokens / total, 1) if total else 0.0,
        "cache_hit_ratio": round(cache_read / tokens, 4) if tokens else 0.0,
        "confusion": {f"{k[0]}->{k[1]}": v for k, v in sorted(confusion.items())},
    }

    await db.create_all()
    async with db.session() as s:
        s.add(db.EvalExperiment(id=exp_id, agent=agent, dataset=str(dataset_path.name),
                                dataset_version=version, git_sha=_git_sha(),
                                overlay=str(overlay) if overlay else "", config_hash=cfg_hash,
                                repetitions=repeat, metrics=metrics))
        for row in case_rows:
            s.add(row)
        await s.commit()

    print(f"experiment {exp_id}: accuracy={metrics['accuracy']:.2%} "
          f"cost/case=${metrics['cost_usd_per_case']:.4f} cache_hit={metrics['cache_hit_ratio']:.2%} "
          f"(config {cfg_hash})")
    return exp_id


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
    print(f"  config      {b.config_hash} -> {c.config_hash}")
    for key in ("accuracy", "cost_usd_per_case", "avg_tokens", "cache_hit_ratio"):
        print(f"  {key:18} {delta(key)}")
    print(f"  baseline confusion: {b.metrics.get('confusion')}")
    print(f"  candidate confusion: {c.metrics.get('confusion')}")


async def _score_corpus_once(*, language: str, sandbox: bool | None) -> dict:
    """One pass over the corpus. See :func:`score_corpus`."""
    from infosec_harness.domain.models import Finding
    from infosec_harness.evals.corpus import load_corpus
    from infosec_harness.evals.trajectory import (
        AGENT_EXPECTATIONS,
        TrajectoryExpectation,
        check_expectations,
        cwe_skill_prefix,
    )
    from infosec_harness.graph.local import triage_batch_local

    cases = load_corpus(language)
    if sandbox is None:
        from infosec_harness.sandbox import docker
        sandbox = await docker.docker_available() and await docker.runtime_available()
    prepare_sink: dict[tuple[str, str], list] = {}
    outputs = await triage_batch_local([c.finding for c in cases], sandbox=sandbox,
                                       prepare_sink=prepare_sink)
    by_fp = {o.finding.fingerprint: o for o in outputs}

    rows, confusion = [], {}
    correct = fn = exploitable = 0
    # Trajectory scoring: did the tool-using agents evoke the expected tools/skills?
    traj_totals: dict[str, dict[str, int]] = {}

    def _score_trajectory(agent: str, tools_called, skills_loaded, cwe: str | None = None) -> None:
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
            _score_trajectory(inv.agent, inv.tools_called, inv.skills_loaded)

    for c in cases:
        out = by_fp[Finding.compute_fingerprint(c.finding)]
        actual = out.result.verdict.label.value
        ok = actual == c.expected_verdict
        correct += int(ok)
        confusion[(c.expected_verdict, actual)] = confusion.get((c.expected_verdict, actual), 0) + 1
        if c.expected_verdict == "potentially_exploitable":
            exploitable += 1
            if actual != "potentially_exploitable":
                fn += 1  # missed a real vulnerability — the costliest error
        rows.append({"case": c.name, "expected": c.expected_verdict, "actual": actual,
                     "ok": ok, "early_exit": out.result.early_exit,
                     "priority": out.result.priority.value})
        # Per-finding triage agents (context, probe-author, ...).
        for inv in out.invocations:
            _score_trajectory(inv.agent, inv.tools_called, inv.skills_loaded, c.finding.cwe)

    trajectory = {a: {"n": v["n"],
                      "tool_use_rate": round(v["tools_ok"] / v["n"], 3) if v["n"] else 0.0,
                      "skill_use_rate": round(v["skills_ok"] / v["n"], 3) if v["n"] else 0.0}
                  for a, v in sorted(traj_totals.items())}
    metrics = {
        "n": len(cases), "accuracy": round(correct / len(cases), 4) if cases else 0.0,
        "false_negative_rate_on_exploitable": round(fn / exploitable, 4) if exploitable else 0.0,
        "sandbox": sandbox,
        "confusion": {f"{k[0]}->{k[1]}": v for k, v in sorted(confusion.items())},
        "trajectory": trajectory,
    }
    for r in rows:
        mark = "OK " if r["ok"] else "XX "
        print(f"  {mark}{r['case']:26} {r['expected']:24} -> {r['actual']:24} {r['early_exit'] or ''}")
    print(f"accuracy={metrics['accuracy']:.0%}  FN-on-exploitable={metrics['false_negative_rate_on_exploitable']:.0%}  "
          f"sandbox={'on' if sandbox else 'off (verdicts not meaningful)'}")
    print("tool/skill evocation (per agent, rate across cases):")
    for agent, t in trajectory.items():
        skills = f"{t['skill_use_rate']:.0%}" if scores_skills(agent) else "n/a"
        print(f"  {agent:14} tools {t['tool_use_rate']:.0%}  skills {skills}  (n={t['n']})")
    return metrics
