"""`harness` CLI: the product (submit, inspect, serve), its evals, and operator checks.

Every `--help` is one sentence; the reasoning lives in comments here and in the modules each
command calls. Commands that run on a developer's machine (evals, `submit --local`, `runs`,
`report`) default to the checkout's `.harness/local.db` when no database is configured; the
worker, the API and `migrate` keep the deployment default (`settings.default_to_local_database`).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer

from infosec_harness.domain.models import FindingInput

app = typer.Typer(add_completion=False, help="Triage pre-identified vulnerability findings for exploitability.")
agents_app = typer.Typer(help="Validate agent specs and regenerate their JSON schema.")
eval_app = typer.Typer(help="Run, compare and record agent evaluations.")
baseline_app = typer.Typer(help="Record and list the committed accepted eval results.")
# Operator checks live in their own group so the top level is the product alone. They are
# normally reached through `./dev validate` and `just validate-services`, which spell the
# extra word once, in scripts/service_validation.py.
ops_app = typer.Typer(help="Read-only checks against a configured deployment.")
app.add_typer(agents_app, name="agents")
app.add_typer(eval_app, name="eval")
app.add_typer(ops_app, name="ops")
eval_app.add_typer(baseline_app, name="baseline")


def _local_store() -> None:
    """Default an unconfigured local command to `.harness/local.db`, saying so once."""
    from infosec_harness.settings import default_to_local_database

    path = default_to_local_database()
    if path is not None:
        typer.echo(f"HARNESS_DATABASE_URL is unset: using the local database {path}", err=True)


def _load_findings(path: Path) -> list[FindingInput]:
    data = json.loads(path.read_text())
    if isinstance(data, dict):
        data = data.get("findings", [data])
    return [FindingInput.model_validate(f) for f in data]


@app.command()
def submit(
    findings: Path = typer.Argument(..., help="JSON file: a finding, a list, or {findings:[...]}."),
    label: str = typer.Option("", help="Human label for the batch."),
    local: bool = typer.Option(False, "--local", help="Run in-process on stub models, without Temporal."),
):
    """Submit findings for triage and print the batch id."""
    from infosec_harness.persistence import db
    from infosec_harness.settings import default_to_stub_models
    from infosec_harness.workflows.local_run import (
        LocalModeUnavailable,
        require_local_mode,
        run_in_process,
    )
    from infosec_harness.workflows.submission import submit_via_temporal

    if local:
        # --local is stub-only: an unset mode means stub, an explicit `live` is still refused.
        if default_to_stub_models():
            typer.echo("HARNESS_MODEL_MODE is unset: --local runs stub models", err=True)
        _local_store()
        try:
            require_local_mode()
        except LocalModeUnavailable as e:
            raise typer.BadParameter(str(e)) from e
    items = _load_findings(findings)

    async def _go():
        await db.create_all()
        if local:
            batch_id, outputs = await run_in_process(items, label=label)
            for o in outputs:
                typer.echo(f"  {o.finding.fingerprint}  {o.result.verdict.label.value:26} {o.result.priority.value}")
        else:
            batch_id = await submit_via_temporal(items, label=label)
        typer.echo(f"BATCH_ID={batch_id}")

    asyncio.run(_go())


@app.command()
def runs(
    batch_id: str = typer.Option(None, help="Only this batch."),
    verdict: str = typer.Option(None, help="Only this verdict."),
    limit: int = typer.Option(50, help="At most N runs."),
):
    """List triage runs, highest priority first."""
    from infosec_harness.persistence import store

    _local_store()
    rows = asyncio.run(store.list_runs(batch_id=batch_id, verdict=verdict, limit=limit))
    for r in rows:
        typer.echo(f"{r['id']}  {r['priority'] or '-':3} {(r['verdict'] or r['status']):26} "
                   f"{r['cwe'] or '-':8} {r['title'][:50]}")


@app.command()
def report(run_id: str = typer.Argument(..., help="Run id from `harness runs`.")):
    """Print the full triage report for one run as JSON."""
    from infosec_harness.persistence import store

    _local_store()
    detail = asyncio.run(store.get_run(run_id))
    if detail is None:
        raise typer.Exit(code=1)
    typer.echo(json.dumps(detail, indent=2))


@ops_app.command("readiness")
def readiness(
    timeout: float = typer.Option(15, help="Seconds allowed per check (1-300)."),
    worker_hostname: str = typer.Option(
        None, help="Exact worker hostname, or `current` inside its container."),
):
    """Check the database schema and recent Temporal pollers."""
    from infosec_harness.operations import readiness as checks

    result, code = checks.report(timeout, worker_hostname)
    typer.echo(json.dumps(result, sort_keys=True))
    raise typer.Exit(code)


@ops_app.command("model-connectivity")
def model_connectivity(
    model: bool = typer.Option(
        False, "--model", help="Authorize the one configured model request."),
    timeout: float = typer.Option(90, help="Seconds allowed for the request (1-300)."),
):
    """Make one explicit model request to check connectivity."""
    if not model:
        raise typer.BadParameter("--model is required to authorize inference")
    from infosec_harness.operations import model_connectivity as check

    result, code = check.report(timeout)
    typer.echo(json.dumps(result, sort_keys=True))
    raise typer.Exit(code)


@app.command()
def worker():
    """Run the Temporal worker."""
    from infosec_harness.workflows.worker import main

    main()


@app.command()
def api(
    host: str = typer.Option("0.0.0.0", help="Bind address."),
    port: int = typer.Option(8000, help="Port."),
):
    """Run the FastAPI server."""
    import uvicorn

    uvicorn.run("infosec_harness.api.app:app", host=host, port=port)


@app.command("migrate")
def migrate(
    local: bool = typer.Option(False, "--local", help="Migrate .harness/local.db instead."),
):
    """Migrate the configured database to the latest revision."""
    # An empty database migrated to head is what bootstrap would create, so there is no
    # separate create command. --local exists because local commands default to local.db and
    # a schema behind head there would otherwise send the developer to the deployment default.
    from infosec_harness.persistence import db
    from infosec_harness.settings import local_database_path, local_database_url

    if local:
        local_database_path().parent.mkdir(parents=True, exist_ok=True)
    typer.echo(f"database at revision {db.upgrade_to_head(local_database_url() if local else None)}")


@agents_app.command("validate")
def agents_validate():
    """Validate every agent spec against its bindings, capabilities and cache rules."""
    from infosec_harness.runtime.registry import validate_all

    problems = validate_all()
    if problems:
        for p in problems:
            typer.echo(f"  - {p}")
        raise typer.Exit(code=1)
    typer.echo("all agent specs valid")


@agents_app.command("schema")
def agents_schema():
    """Regenerate agents/agent_schema.json from the capability allowlist."""
    from infosec_harness.runtime.registry import get_settings, json_schema

    path = get_settings().agents_dir / "agent_schema.json"
    path.write_text(json.dumps(json_schema(), indent=2) + "\n")
    typer.echo(f"wrote {path}")


def _default_report_dir(kind: str) -> Path:
    from infosec_harness.settings import get_settings

    return get_settings().reports_dir / kind


@eval_app.command("run")
def eval_run(
    agents: list[str] = typer.Argument(None, help="Agent names; or pass --all.", show_default=False),
    all_agents: bool = typer.Option(False, "--all", help="Every agent with a packaged dataset."),
    model: list[str] = typer.Option(
        None, "--model", "-m", help="Model tier; repeat to compare (-m sonnet -m opus)."),
    overlay: Path = typer.Option(None, help="Experiment overlay YAML pinned to spec versions."),
    repeat: int = typer.Option(1, help="Repetitions per case."),
    dataset: Path = typer.Option(None, help="Dataset YAML to run instead of the packaged one."),
    report: Path = typer.Option(None, help="Report path for a single run."),
    report_dir: Path = typer.Option(
        None, help="Report directory (default: HARNESS_REPORTS_DIR/evals)."),
    require_gates: bool = typer.Option(
        False, "--require-gates", help="Also exit 1 unless every release gate passed."),
):
    """Run agents' eval datasets and print one summary table."""
    # Sequential on purpose: latency is measured, so concurrent runs would contend. Exit 1 when
    # any run did not complete (truncated, or failed before storing a result); --require-gates
    # also fails on a gate that is `failed` or `not_checked`. The default keeps stub runs (CI's
    # `just eval`) meaningful: they prove datasets and adapters load and score, while stub
    # accuracy is meaningless and fails the quality gates by design.
    from infosec_harness.evals.reporting import exit_status, packaged_eval_agents, run_evals

    names = list(agents or [])
    if all_agents == bool(names):
        raise typer.BadParameter("name one or more agents, or pass --all (not both)")
    models = list(model or [])
    if all_agents:
        names = packaged_eval_agents()
    if dataset is not None and len(names) > 1:
        raise typer.BadParameter("--dataset belongs to one agent")
    if report is not None and len(names) * max(len(models), 1) > 1:
        raise typer.BadParameter("--report names one file; use --report-dir for several runs")
    _local_store()
    directory = report_dir or (None if report is not None else _default_report_dir("evals"))
    outcomes = asyncio.run(run_evals(names, models, overlay=overlay, repeat=repeat,
                                     report=report, report_dir=directory, dataset=dataset))
    raise typer.Exit(exit_status(outcomes, require_gates=require_gates))


@eval_app.command("release")
def eval_release(
    agent: list[str] = typer.Option(None, "--agent", help="Only this agent (repeatable)."),
    model: str = typer.Option(None, "--model", "-m", help="Model tier for every agent."),
    save_baselines: bool = typer.Option(
        False, "--save-baselines", help="Record every passing run as the committed baseline."),
):
    """Qualify a release: every agent on a live model at a clean commit."""
    # Refuses stub mode and a dirty tree before any model call; exit 1 unless every gate
    # passed. Execution-backed gates need a runsc host (see evals/release.py).
    from infosec_harness.evals.release import ReleaseRefused, qualify_release

    _local_store()
    try:
        _, status = asyncio.run(qualify_release(
            list(agent or []), model=model, save_baselines=save_baselines))
    except ReleaseRefused as refused:
        typer.echo(str(refused), err=True)
        raise typer.Exit(code=2) from None
    raise typer.Exit(status)


@eval_app.command("results")
def eval_results(
    agent: str = typer.Option(None, help="Only this agent."),
    commit: str = typer.Option(None, help="Only runs of this commit (prefix match)."),
    limit: int = typer.Option(20, help="Most recent N experiments."),
):
    """List stored experiments, newest first."""
    from infosec_harness.evals.reporting import list_experiments

    _local_store()
    asyncio.run(list_experiments(agent=agent, commit=commit, limit=limit))


@eval_app.command("calibrate")
def eval_calibrate(
    specification: Path = typer.Argument(..., help="Validated calibration experiment YAML."),
    report: Path = typer.Option(..., help="Atomic JSON report output path."),
):
    """Select a calibration candidate by hard gates and score its holdouts."""
    from infosec_harness.evals.calibration import load_calibration, run_calibration, write_report

    _local_store()
    calibration = load_calibration(specification)
    result = asyncio.run(run_calibration(calibration))
    write_report(report, result)
    typer.echo(
        f"CALIBRATION_REPORT={report} selected={result.selected_candidate!r} "
        f"promotion_eligible={str(result.promotion_eligible).lower()}"
    )


@eval_app.command("compare")
def eval_compare(
    experiments: list[str] = typer.Argument(
        None, help="Two or more experiment ids; the first is the baseline."),
    agent: str = typer.Option(None, help="Compare this agent's latest run per model instead."),
    commit: str = typer.Option(None, help="With --agent, only runs of this commit."),
    descriptive: bool = typer.Option(
        False, "--descriptive", help="Show incomparable runs too; cannot clear release gates."),
):
    """Compare experiments on task success, latency and cost."""
    # Runs that are not release-comparable (different cases, code, evaluator or pricing;
    # incomplete or dirty runs) are refused unless --descriptive is passed.
    from infosec_harness.evals.reporting import compare_experiments, compare_models_for

    _local_store()
    ids = list(experiments or [])
    if agent:
        asyncio.run(compare_models_for(agent, commit=commit, descriptive=descriptive))
    elif len(ids) >= 2:
        asyncio.run(compare_experiments(ids, descriptive=descriptive))
    else:
        raise typer.BadParameter("pass two or more experiment ids, or --agent <name>")


@baseline_app.command("save")
def baseline_save(
    experiment: str = typer.Argument(None, help="Experiment id to record.", show_default=False),
    latest: str = typer.Option(
        None, "--latest", metavar="AGENT", help="Record this agent's newest complete live run."),
    model: str = typer.Option(
        None, "--model", "-m", help="With --latest, the tier (default: the agent's own)."),
):
    """Record an experiment as its agent's committed baseline."""
    # Refused for a run that is not complete, covers less than the full dataset, ran against
    # the stub model, or came from a dirty tree (evals/baselines.py states why).
    from infosec_harness.evals.reporting import latest_live_experiment, save_baseline

    if (experiment is None) == (latest is None):
        raise typer.BadParameter("pass an experiment id or --latest <agent>, not both")
    if model and not latest:
        raise typer.BadParameter("--model selects a tier for --latest")
    _local_store()

    async def _save() -> None:
        target = experiment
        if latest:
            row = await latest_live_experiment(latest, model)
            typer.echo(f"newest complete live run of {latest} on {row.model_tier}: {row.id}")
            target = row.id
        await save_baseline(target)

    asyncio.run(_save())


@baseline_app.command("list")
def baseline_list(agent: str = typer.Option(None, help="Only this agent.")):
    """List committed baselines and whether the code has moved since."""
    from infosec_harness.evals import baselines as baseline_store
    from infosec_harness.evals.reporting import comparison_table

    stored = baseline_store.load_all(agent)
    if not stored:
        typer.echo("no baselines recorded yet (`harness eval baseline save --latest <agent>`)")
        return
    for name in sorted({b.agent for b in stored}):
        rows = [b for b in stored if b.agent == name]
        typer.echo(f"\n{name}")
        typer.echo(comparison_table([
            {"label": b.model_tier, "experiment_id": b.experiment_id, "pricing": b.pricing,
             "metrics": {**b.metrics, "distributions": b.distributions}} for b in rows]))
        for b in rows:
            note = baseline_store.staleness(b)
            typer.echo(f"  {b.model_tier:<14} {b.git_commit[:12]}  {b.model_name}"
                       + (f"  ! {note}" if note else ""))


@eval_app.command("corpus")
def eval_corpus(
    language: str = typer.Option("python", help="Corpus language, or 'all'."),
    sandbox: bool = typer.Option(None, help="Force the sandbox on or off."),
    repeat: int = typer.Option(1, help="Passes over the corpus; prints the spread."),
    manifest: Path = typer.Option(
        None, help="Corpus manifest (default: eval-corpus/manifest.json)."),
    dataset: str = typer.Option("seed", help="Source label recorded on every case."),
    limit: int = typer.Option(0, help="Score only the first N cases, keeping pairs together."),
    report: Path = typer.Option(
        None, help="Report path (default: HARNESS_REPORTS_DIR/corpus/<timestamp>.json)."),
):
    """Score the ground-truth corpus end to end."""
    from datetime import UTC, datetime

    from infosec_harness.evals.corpus_run import score_corpus

    _local_store()
    target = report or _default_report_dir("corpus") / (
        datetime.now(UTC).strftime("corpus-%Y%m%dT%H%M%S%fZ") + ".json")
    asyncio.run(score_corpus(language=language, sandbox=sandbox, repeat=repeat,
                             manifest_path=manifest, dataset=dataset, limit=limit, report=target))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
