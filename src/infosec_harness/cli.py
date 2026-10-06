"""Operator entry points for the single native investigation path."""

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import typer

from infosec_harness.config import get_settings, use_settings_file

app = typer.Typer(no_args_is_help=True)


@app.callback()
def configure(
    settings: Path | None = typer.Option(
        None, help="Frozen Settings JSON; HARNESS_* environment variables are then ignored."
    ),
):
    """Investigate reported vulnerabilities through native OpenShell and Temporal."""
    if settings is not None:
        use_settings_file(settings)


def new_report(kind: str) -> Path:
    # Timestamped by default; an existing report is still never overwritten.
    return Path(".harness/reports") / f"{kind}-{datetime.now(UTC):%Y%m%dT%H%M%SZ}.json"


@app.command()
def api(host: str = "127.0.0.1", port: int = 8000):
    """Serve the lightweight HTTP API."""
    import uvicorn

    uvicorn.run("infosec_harness.web:app", host=host, port=port)


@app.command()
def worker(
    task_queue: str | None = typer.Option(
        None, help="Serve this task queue (for example, drain an owned eval queue)."
    ),
):
    """Run the Temporal worker with native PydanticAI model/tool activities."""
    from infosec_harness.web import connect
    from infosec_harness.workflows.worker import create_worker

    settings = get_settings()
    if task_queue:
        settings = settings.model_copy(update={"task_queue": task_queue})

    async def serve():
        runtime = create_worker(await connect(settings), settings)
        await runtime.run()

    asyncio.run(serve())


@app.command()
def submit(path: Path):
    """Submit one Finding JSON document to Temporal."""
    from infosec_harness.models import Finding
    from infosec_harness.web import connect
    from infosec_harness.web import submit as start

    async def send():
        return await start(Finding.model_validate_json(path.read_text()), await connect())

    typer.echo(asyncio.run(send()).model_dump_json(indent=2))


@app.command()
def report(run_id: str):
    """Read an investigation's current status and validated result."""
    from infosec_harness.web import connect, run

    async def read():
        return await run(run_id, await connect())

    typer.echo(asyncio.run(read()).model_dump_json(indent=2))


@app.command("eval")
def evaluate(
    manifest: Path = typer.Option(
        Path("eval-corpus/manifest.json"), help="Corpus manifest with independent ground truth."
    ),
    output: Path | None = typer.Option(
        None,
        help="Report path, never overwritten. Default: .harness/reports/model-<UTC>.json "
        "(diagnostic-<UTC>.json with --case).",
    ),
    allow_inference: bool = typer.Option(
        False, help="Required: confirm that this run sends live model requests."
    ),
    owned_worker: bool = typer.Option(
        False, help="Run a worker in this process on a fresh queue until owned cleanup ends."
    ),
    case: list[str] | None = typer.Option(
        None, help="Diagnostic subset (repeatable); never qualifies a candidate."
    ),
    keep_going: bool = typer.Option(
        False, help="Continue only after a terminal agent/model-level case failure."
    ),
):
    """Run the paired corpus (or a diagnostic subset) once, preserving failures and unstarted cases."""
    if not allow_inference:
        raise typer.BadParameter("Live evaluation requires --allow-inference")
    from infosec_harness.evaluation import evaluate_corpus

    output = output or new_report("diagnostic" if case else "model")
    result = asyncio.run(evaluate_corpus(
        manifest, output, get_settings(), names=tuple(case or ()),
        owned_worker=owned_worker, keep_going=keep_going,
    ))
    typer.echo(json.dumps(result, indent=2))
    raise typer.Exit(0 if result["status"] == "passed" else 1)


@app.command()
def qualify(
    output: Path | None = typer.Option(
        None, help="Report path, never overwritten. Default: .harness/reports/openshell-<UTC>.json."
    ),
):
    """Exercise actual native workspace/probe boundaries, without model calls."""
    from infosec_harness.qualification import qualify_runtime

    result = asyncio.run(qualify_runtime(output or new_report("openshell")))
    typer.echo(json.dumps(result, indent=2))
    raise typer.Exit(0 if result["status"] == "passed" else 1)


@app.command()
def replay(
    run_id: str,
    output: Path | None = typer.Option(
        None, help="Also write the report here, never overwritten. Default: print only."
    ),
):
    """Replay one recorded workflow history with no native or model dispatch."""
    from infosec_harness._io import write_json
    from infosec_harness.evaluation import replay_history

    result = asyncio.run(replay_history(run_id, get_settings()))
    if output:
        write_json(output, result, exclusive=True)
    typer.echo(json.dumps(result, indent=2))
    raise typer.Exit(0 if result["status"] == "passed" else 1)


def main():
    app()


if __name__ == "__main__":
    main()
