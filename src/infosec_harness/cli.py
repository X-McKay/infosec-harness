"""`harness` CLI: submit findings, inspect runs, run the worker/API, manage agent specs."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer

from infosec_harness.domain.models import FindingInput

app = typer.Typer(add_completion=False, help="Exploitability triage harness")
agents_app = typer.Typer(help="Agent spec tooling")
eval_app = typer.Typer(help="Evaluations")
app.add_typer(agents_app, name="agents")
app.add_typer(eval_app, name="eval")


def _load_findings(path: Path) -> list[FindingInput]:
    data = json.loads(path.read_text())
    if isinstance(data, dict):
        data = data.get("findings", [data])
    return [FindingInput.model_validate(f) for f in data]


@app.command()
def submit(
    findings: Path = typer.Argument(..., help="JSON file: a finding, a list, or {findings:[...]}"),
    label: str = typer.Option("", help="Human label for the batch"),
    local: bool = typer.Option(False, "--local", help="Run in-process without Temporal"),
):
    """Submit findings for triage and print the batch id."""
    from infosec_harness.persistence import db
    from infosec_harness.workflows import runner

    items = _load_findings(findings)

    async def _go():
        await db.create_all()
        if local:
            batch_id, outputs = await runner.run_local(items, label=label)
            for o in outputs:
                typer.echo(f"  {o.finding.fingerprint}  {o.result.verdict.label.value:26} {o.result.priority.value}")
        else:
            batch_id = await runner.submit_via_temporal(items, label=label)
        typer.echo(f"BATCH_ID={batch_id}")

    asyncio.run(_go())


@app.command()
def runs(batch_id: str = typer.Option(None), verdict: str = typer.Option(None), limit: int = 50):
    """List triage runs, highest priority first."""
    from infosec_harness.persistence import store

    rows = asyncio.run(store.list_runs(batch_id=batch_id, verdict=verdict, limit=limit))
    for r in rows:
        typer.echo(f"{r['id']}  {r['priority'] or '-':3} {(r['verdict'] or r['status']):26} "
                   f"{r['cwe'] or '-':8} {r['title'][:50]}")


@app.command()
def report(run_id: str):
    """Print the full triage report for one run as JSON."""
    from infosec_harness.persistence import store

    detail = asyncio.run(store.get_run(run_id))
    if detail is None:
        raise typer.Exit(code=1)
    typer.echo(json.dumps(detail, indent=2))


@app.command()
def worker():
    """Run the Temporal worker."""
    from infosec_harness.workflows.worker import main

    main()


@app.command()
def api(host: str = "0.0.0.0", port: int = 8000):
    """Run the FastAPI server."""
    import uvicorn

    uvicorn.run("infosec_harness.api.app:app", host=host, port=port)


@app.command("init-db")
def init_db():
    """Create database tables."""
    from infosec_harness.persistence import db

    asyncio.run(db.create_all())
    typer.echo("database tables created")


@agents_app.command("validate")
def agents_validate():
    """Validate every agent.yaml against bindings, the capability allowlist, and cache rules."""
    from infosec_harness.agents.registry import validate_all

    problems = validate_all()
    if problems:
        for p in problems:
            typer.echo(f"  - {p}")
        raise typer.Exit(code=1)
    typer.echo("all agent specs valid")


@agents_app.command("schema")
def agents_schema():
    """Regenerate agents/agent_schema.json from the allowlisted capabilities."""
    from infosec_harness.agents.registry import get_settings, json_schema

    path = get_settings().agents_dir / "agent_schema.json"
    path.write_text(json.dumps(json_schema(), indent=2) + "\n")
    typer.echo(f"wrote {path}")


@eval_app.command("run")
def eval_run(
    agent: str = typer.Argument(..., help="Agent name, or 'e2e' for the end-to-end corpus"),
    overlay: Path = typer.Option(None, help="Experiment overlay YAML"),
    repeat: int = typer.Option(1, help="Repetitions (LLM variance)"),
):
    """Run an agent's eval dataset (or the e2e corpus) and persist the experiment."""
    from infosec_harness.evals.run import run_experiment

    exp_id = asyncio.run(run_experiment(agent, overlay=overlay, repeat=repeat))
    typer.echo(f"EXPERIMENT_ID={exp_id}")


@eval_app.command("corpus")
def eval_corpus(language: str = "python", sandbox: bool = typer.Option(None, help="Force sandbox on/off")):
    """Run the seeded ground-truth corpus end-to-end and score verdicts against truth."""
    from infosec_harness.evals.run import score_corpus

    asyncio.run(score_corpus(language=language, sandbox=sandbox))


@eval_app.command("compare")
def eval_compare(baseline: str, candidate: str):
    """Compare two experiments on accuracy, cost, and latency."""
    from infosec_harness.evals.run import compare_experiments

    asyncio.run(compare_experiments(baseline, candidate))


if __name__ == "__main__":
    app()


def main() -> None:
    app()
