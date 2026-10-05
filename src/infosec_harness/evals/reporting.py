"""Strict experiment comparison, model sweeps, result listing, and baselines."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

from sqlalchemy import select

from infosec_harness.evals import baselines as baseline_store
from infosec_harness.evals.provenance import code_version
from infosec_harness.evals.run import load_experiment, run_experiment
from infosec_harness.persistence import db

_COMPARISON_COLUMNS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("accuracy", ("task_success_rate",), "pct"),
    ("worst rep", ("distributions", "worst_repetition_pass_rate"), "pct"),
    ("schema", ("schema_validity_rate",), "pct"),
    ("p50 lat", ("distributions", "p50_latency_s"), "secs"),
    ("p95 lat", ("distributions", "p95_latency_s"), "secs"),
    ("$/case", ("average_cost_usd",), "usd"),
    ("p95 $", ("distributions", "p95_cost_usd"), "usd"),
    ("p95 req", ("p95_model_requests",), "int"),
    ("budget", ("budget_exhausted_count",), "int"),
)


class IncomparableExperiments(SystemExit):
    """Release-grade comparison was requested for incompatible experiment records."""

    def __init__(self, issues: list[str]) -> None:
        self.issues = issues
        super().__init__(
            "experiments are not strictly comparable:\n- " + "\n- ".join(issues)
            + "\nUse a descriptive comparison only for inspection; it cannot clear release gates."
        )


def comparability_issues(found: list[object]) -> list[str]:
    """Reasons these rows cannot support a release-grade comparative claim."""
    issues: list[str] = []
    if len({row.agent for row in found}) > 1:
        issues.append(f"different subjects: {sorted({row.agent for row in found})}")
    if len({(row.dataset, row.dataset_version) for row in found}) > 1:
        issues.append("different dataset names or versions")

    identities = [(row.metrics or {}).get("comparison_identity") or {} for row in found]
    for field in (
        "case_set_digest", "evaluator_version", "execution_mode", "repetitions", "split"
    ):
        values = {identity.get(field) for identity in identities}
        if None in values:
            issues.append(f"missing comparison identity field {field!r}")
        elif len(values) > 1:
            issues.append(f"different {field.replace('_', ' ')} values")

    # Default comparisons support parameter-only experiments: the source under test must be
    # byte-identical. Intentional code-change studies remain available in descriptive mode,
    # where they are labelled as incapable of clearing release gates rather than silently
    # attributing a code difference to the parameter being tuned.
    code_identities = [(row.metrics or {}).get("code_identity") or {} for row in found]
    source_digests = {identity.get("source_digest") for identity in code_identities}
    if None in source_digests:
        issues.append("missing source digest; exact code identity is required")
    elif len(source_digests) > 1:
        issues.append("different source digests; use descriptive mode for code-change studies")
    if len({row.git_sha for row in found}) > 1:
        issues.append("different git commits; use descriptive mode for code-change studies")
    if len({row.harness_version for row in found}) > 1:
        issues.append("different harness versions")
    if any(row.git_dirty for row in found):
        issues.append("dirty source snapshots cannot clear release gates")
    pricing = {row.pricing for row in found}
    if None in pricing or "" in pricing:
        issues.append("missing pricing status")
    elif len(pricing) > 1:
        issues.append("different pricing status; cost results are not comparable")

    required_numbers = (
        "n", "n_planned", "passed", "task_success_rate", "schema_validity_rate",
        "p95_model_requests",
    )
    for row in found:
        metrics = row.metrics or {}
        status = metrics.get("status")
        if status != "complete":
            issues.append(f"{row.id} has status {status!r}, not 'complete'")
        if metrics.get("n") != metrics.get("n_planned"):
            issues.append(
                f"{row.id} has incomplete coverage "
                f"{metrics.get('n')}/{metrics.get('n_planned')}"
            )
        for key in required_numbers:
            value = metrics.get(key)
            if isinstance(value, bool) or not isinstance(value, int | float) \
                    or not math.isfinite(float(value)):
                issues.append(f"{row.id} metric {key!r} is not a finite number")
        cost = metrics.get("average_cost_usd")
        if cost is None:
            if not metrics.get("cost_unknown"):
                issues.append(f"{row.id} has unexplained unknown cost")
        elif isinstance(cost, bool) or not isinstance(cost, int | float) \
                or not math.isfinite(float(cost)):
            issues.append(f"{row.id} metric 'average_cost_usd' is not finite")
    return list(dict.fromkeys(issues))


async def compare_experiments(
    experiment_ids: list[str], *, descriptive: bool = False
) -> None:
    """Compare two or more experiments. The first is the baseline the rest are read against."""
    rows = [(eid, await load_experiment(eid)) for eid in experiment_ids]
    if missing := [eid for eid, row in rows if row is None]:
        raise SystemExit(f"experiment not found: {', '.join(missing)}")
    found = [row for _, row in rows]
    _render_comparison(found, descriptive=descriptive)
    if len(found) == 2:
        _print_pairwise(found[0], found[1])


def _render_comparison(found: list, *, descriptive: bool) -> None:
    """The comparison table, refused outright unless the runs are release-comparable or the
    caller asked for a descriptive view -- which then says, loudly, that it is only that."""
    issues = comparability_issues(found)
    if issues and not descriptive:
        raise IncomparableExperiments(issues)
    _print_comparison(found)
    if issues:
        print("\n  !! DESCRIPTIVE ONLY: these experiments are not release-comparable, so this "
              "output cannot clear release gates:")
        for issue in issues:
            print(f"     - {issue}")


def _coverage_warning(label: str, row: Any) -> str | None:
    """A loud line for a run that did not score every planned case, ``None`` for one that did.

    Its numbers are then over a different set of cases than a complete run's, so any delta
    against it can be nothing but which cases happened to run.
    """
    metrics = row.metrics or {}
    status = metrics.get("status") or "unknown"
    if status == "complete":
        return None
    cut = metrics.get("truncated") or {}
    return (f"  !! {label} {row.id} is {str(status).upper()}: "
            f"{metrics.get('n', 0)}/{metrics.get('n_planned', '?')} case runs scored"
            + (f" — stopped on case {cut['failed_case']!r} "
               f"({cut['error_type']}: {cut['error'][:120]})" if cut else "")
            + ". Its metrics cover only those cases, so it is not a like-for-like row.")


def _experiment_label(row) -> str:
    """How a row identifies itself in a table: the model, plus anything else that differs."""
    return row.model_tier or row.config_hash[:8] or row.id


def _print_comparison(found: list) -> None:
    print(f"agent={found[0].agent}  dataset={found[0].dataset} v{found[0].dataset_version}\n")
    print(comparison_table([
        {"label": _experiment_label(row), "experiment_id": row.id, "pricing": row.pricing,
         "metrics": row.metrics} for row in found]))
    print()
    for row in found:
        code = f"{row.git_sha[:12] or '(no commit)'}{'-dirty' if row.git_dirty else ''}"
        print(f"  {_experiment_label(row):<14} {row.model_name or '(unknown model)':<40} "
              f"config {row.config_hash[:8]}  code {code}  v{row.harness_version or '?'}")
    # Comparing runs of different code is a common and easy mistake -- a model sweep taken
    # across an afternoon of edits reads as a model difference. Say it rather than assume it
    # was noticed.
    if len({(row.git_sha, row.git_dirty) for row in found}) > 1:
        print("\n  ! these runs are of different code, so a difference between them is not "
              "necessarily a difference between the models.")
    if any(row.git_dirty for row in found):
        print("  ! at least one run had a dirty working tree and cannot be reproduced from "
              "its commit.")
    for row in found:
        if warning := _coverage_warning(_experiment_label(row), row):
            print(warning)


def _print_pairwise(b, c) -> None:
    """The original two-experiment view: deltas and confusion matrices, which only mean
    something between exactly two runs."""
    print()

    def delta(key: str) -> str:
        bv, cv = b.metrics.get(key), c.metrics.get(key)
        if bv is None or cv is None:
            before = "unknown" if bv is None else str(bv)
            after = "unknown" if cv is None else str(cv)
            return f"{before:>10} -> {after:<10} (unknown)"
        return f"{bv:>10} -> {cv:<10} ({cv - bv:+.4f})"

    # Loud and first: the deltas below are between different numbers of cases.
    warnings = {label: _coverage_warning(label, exp)
                for label, exp in (("baseline", b), ("candidate", c))}
    incomplete = [label for label, warning in warnings.items() if warning]
    for label in incomplete:
        print(warnings[label])
    if incomplete:
        print("  !! NOT a like-for-like comparison: re-run the "
              f"{'/'.join(incomplete)} side before drawing a conclusion.")
    print(f"  config      {b.config_hash} -> {c.config_hash}")
    print(f"  coverage    {b.metrics.get('n', 0)}/{b.metrics.get('n_planned', '?')} -> "
          f"{c.metrics.get('n', 0)}/{c.metrics.get('n_planned', '?')} case runs "
          f"({b.metrics.get('status') or 'unknown'} -> {c.metrics.get('status') or 'unknown'})")
    for key in ("task_success_rate", "cost_usd_per_case", "avg_tokens", "cache_hit_ratio"):
        print(f"  {key:18} {delta(key)}")
    print(f"  baseline confusion: {b.metrics.get('confusion')}")
    print(f"  candidate confusion: {c.metrics.get('confusion')}")


def _dig(metrics: dict, path: tuple[str, ...]):
    value = metrics
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _fmt(value, kind: str) -> str:
    if value is None:
        return "-"
    if kind == "pct":
        return f"{value:.0%}"
    if kind == "secs":
        return f"{value:.1f}s"
    if kind == "usd":
        return f"${value:.4f}"
    return str(value)


def comparison_table(rows: list[dict]) -> str:
    """Render one row per model: quality, latency and cost side by side.

    ``rows`` are ``{"label", "pricing", "metrics", "experiment_id"}``. Kept separate from both
    the runner and the store so the same table renders a fresh sweep and a query over past
    experiments, and so it can be tested without either.
    """
    if not rows:
        return "(no experiments)"
    headers = ["model", *(name for name, _, _ in _COMPARISON_COLUMNS)]
    body = [[row["label"], *(_fmt(_dig(row["metrics"], path), kind)
                             for _, path, kind in _COMPARISON_COLUMNS)] for row in rows]
    widths = [max(len(str(r[i])) for r in [headers, *body]) for i in range(len(headers))]
    lines = [
        "  ".join(h.ljust(w) for h, w in zip(headers, widths, strict=True)),
        "  ".join("-" * w for w in widths),
        *("  ".join(str(c).ljust(w) for c, w in zip(row, widths, strict=True)) for row in body),
    ]
    # A cost column is only comparable between models priced the same way. Saying which kind of
    # zero each zero is turns a misleading "cheaper" into a fact about the price table.
    kinds = {row.get("pricing", "") for row in rows}
    if kinds - {"priced"}:
        lines.append("")
        lines.append("  cost basis: " + ", ".join(
            f"{row['label']}={row.get('pricing') or 'unknown'}" for row in rows))
        if len(kinds) > 1:
            lines.append("  ! these models are not priced on the same basis, so the cost "
                         "columns are not comparable between them.")
    lines.append("")
    for row in rows:
        lines.append(f"  {row['label'].ljust(widths[0])}  {row['experiment_id']}")
    return "\n".join(lines)


async def sweep_models(agent: str, models: list[str], *, overlay: Path | None = None,
                       repeat: int = 1, report_dir: Path | None = None,
                       dataset: Path | None = None) -> list[dict]:
    """Run one agent's dataset once per model, then report them side by side.

    Sequential on purpose. These runs are the measurement, and latency is one of the things
    being measured -- running them concurrently would have them contend for the same endpoint
    and make every number a function of how many models were in the sweep.

    A model that fails does not abort the sweep: its row is recorded as failed and the others
    still produce numbers, because "opus could not complete the dataset" is itself a result
    worth seeing next to the models that could. Every completed model writes its own release
    report into ``report_dir`` when one is given, audited like any other.
    """
    results: list[dict] = []
    for tier in models:
        print(f"\n=== {agent} @ {tier} " + "=" * 40)
        try:
            exp_id = await run_experiment(
                agent, overlay=overlay, repeat=repeat, model=tier, dataset=dataset,
                report_dir=report_dir)
        except Exception as exc:  # includes TruncatedExperiment; the next model still runs
            print(f"  {tier}: FAILED -- {type(exc).__name__}: {str(exc)[:200]}")
            results.append({"label": tier, "experiment_id": getattr(exc, "experiment_id", "-"),
                            "pricing": "", "metrics": {}, "failed": True})
            continue
        row = await load_experiment(exp_id)
        results.append({"label": tier, "experiment_id": exp_id,
                        "pricing": row.pricing, "metrics": row.metrics, "failed": False})
    print(f"\n{agent}: {len(models)} models, {repeat} repetition(s), "
          f"code {code_version().label()}\n")
    print(comparison_table(results))
    return results


async def _stored_experiments(*, agent: str | None, commit: str | None) -> list:
    """Stored experiments, newest first, optionally for one agent and one commit prefix."""
    await db.create_all()
    query = select(db.EvalExperiment).order_by(db.EvalExperiment.created_at.desc())
    if agent:
        query = query.where(db.EvalExperiment.agent == agent)
    async with db.session() as s:
        rows = list((await s.execute(query)).scalars())
    return [r for r in rows if r.git_sha.startswith(commit)] if commit else rows


async def list_experiments(*, agent: str | None = None, commit: str | None = None,
                           limit: int = 20) -> list:
    """Print stored experiments, newest first, with what identifies each one.

    The columns are the ones you need to decide whether two rows are comparable at all: the
    model, the code, and the config -- not just the score.
    """
    rows = (await _stored_experiments(agent=agent, commit=commit))[:limit]
    if not rows:
        print("no experiments stored" + (f" for {agent}" if agent else ""))
        return rows
    header = f"{'experiment':<22} {'agent':<16} {'model':<10} {'code':<20} {'status':<10} succ    $/case"
    print(header)
    print("-" * len(header))
    for row in rows:
        metrics = row.metrics or {}
        code = f"{row.git_sha[:12] or '-'}{'-dirty' if row.git_dirty else ''}"
        average_cost = metrics.get("average_cost_usd")
        cost_text = f"${average_cost:.4f}" if average_cost is not None else "unknown"
        print(f"{row.id:<22} {row.agent:<16} {(row.model_tier or '-'):<10} {code:<20} "
              f"{metrics.get('status', '?'):<10} "
              f"{metrics.get('task_success_rate', 0):<7.0%} "
              f"{cost_text}")
    return rows


async def compare_models_for(
    agent: str, *, commit: str | None = None, descriptive: bool = False
) -> list:
    """Line up an agent's most recent run for each model it has been evaluated against.

    This is the query the sweep produces live, asked after the fact -- so a comparison survives
    the terminal it was printed in, and so models run days apart can still be read together
    (with the code difference called out, because that is exactly when it matters).
    """
    latest: dict[str, object] = {}
    for row in await _stored_experiments(agent=agent, commit=commit):
        # Newest first, so the first of each model wins.
        latest.setdefault(row.model_tier or row.config_hash[:8], row)
    if not latest:
        raise SystemExit(f"no experiments stored for {agent}"
                         + (f" at commit {commit}" if commit else ""))
    found = list(latest.values())
    _render_comparison(found, descriptive=descriptive)
    return found


async def save_baseline(experiment_id: str) -> Path:
    """Record one experiment as the committed baseline for its agent and model."""
    row = await load_experiment(experiment_id)
    if row is None:
        raise SystemExit(f"experiment not found: {experiment_id}")
    try:
        baseline = baseline_store.from_experiment(row)
    except baseline_store.BaselineRefused as refusal:
        raise SystemExit(f"not recorded as a baseline: {refusal}") from refusal
    previous = baseline_store.load(baseline.agent, baseline.model_tier)
    path = baseline_store.save(baseline)
    print(f"wrote {path}")
    print(f"  {baseline.agent} @ {baseline.model_tier} ({baseline.model_name}) "
          f"at {baseline.git_commit[:12]}, cost basis {baseline.pricing}")
    if previous is not None:
        moved = baseline_store.drift(previous, baseline.metrics)
        if moved:
            print(f"  replaces the baseline from {previous.git_commit[:12]}; what moved:")
            for key, was, now in moved:
                print(f"    {key:<24} {was} -> {now}")
        else:
            print(f"  replaces the baseline from {previous.git_commit[:12]}; no pinned metric "
                  f"changed")
    print("  commit this file: a baseline is only useful to the next person if it is in the repo")
    return path
