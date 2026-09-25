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


ADAPTERS: dict[str, Adapter] = {"verdict": _verdict_adapter, "probe_diagnosis": _diagnosis_adapter}


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


async def score_corpus(*, language: str = "python", sandbox: bool | None = None) -> dict:
    """Run the seeded corpus end-to-end and score verdicts against ground truth (§10.2).

    Headline metrics: per-class precision/recall and the false-negative rate on truly
    exploitable cases (the costliest error). With stub models the verdicts are not
    meaningful (the stub is not a judge) — this is the harness that lights up under a live
    model. `sandbox=None` auto-detects the gVisor runtime.
    """
    from infosec_harness.domain.models import Finding
    from infosec_harness.evals.corpus import load_corpus
    from infosec_harness.graph.local import triage_batch_local

    cases = load_corpus(language)
    if sandbox is None:
        from infosec_harness.sandbox import docker
        sandbox = await docker.docker_available() and await docker.runtime_available()
    outputs = await triage_batch_local([c.finding for c in cases], sandbox=sandbox)
    by_fp = {o.finding.fingerprint: o for o in outputs}

    rows, confusion = [], {}
    correct = fn = exploitable = 0
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
    metrics = {
        "n": len(cases), "accuracy": round(correct / len(cases), 4) if cases else 0.0,
        "false_negative_rate_on_exploitable": round(fn / exploitable, 4) if exploitable else 0.0,
        "sandbox": sandbox,
        "confusion": {f"{k[0]}->{k[1]}": v for k, v in sorted(confusion.items())},
    }
    for r in rows:
        mark = "OK " if r["ok"] else "XX "
        print(f"  {mark}{r['case']:26} {r['expected']:24} -> {r['actual']:24} {r['early_exit'] or ''}")
    print(f"accuracy={metrics['accuracy']:.0%}  FN-on-exploitable={metrics['false_negative_rate_on_exploitable']:.0%}  "
          f"sandbox={'on' if sandbox else 'off (verdicts not meaningful)'}")
    return metrics
