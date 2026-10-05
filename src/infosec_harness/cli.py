"""Operator entry points for the single native investigation path."""

import asyncio
import json
from pathlib import Path

import typer

from infosec_harness.config import get_settings

app = typer.Typer(no_args_is_help=True)


@app.command()
def api(host: str = "127.0.0.1", port: int = 8000):
    """Serve the lightweight HTTP API."""
    import uvicorn

    uvicorn.run("infosec_harness.web:app", host=host, port=port)


@app.command()
def worker():
    """Run the Temporal worker with native PydanticAI model/tool activities."""
    from infosec_harness.web import connect
    from infosec_harness.workflow import create_worker

    async def serve():
        runtime = create_worker(await connect(), get_settings())
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
    manifest: Path = Path("eval-corpus/manifest.json"),
    output: Path = Path(".harness/reports/qualification.json"),
    allow_inference: bool = False,
):
    """Run the complete paired corpus once, preserving failures and unstarted cases."""
    if not allow_inference:
        raise typer.BadParameter("Live evaluation requires --allow-inference")
    from infosec_harness.evaluation import evaluate_corpus

    result = asyncio.run(evaluate_corpus(manifest, output))
    typer.echo(json.dumps(result, indent=2))
    raise typer.Exit(0 if result["status"] == "passed" else 1)


@app.command()
def qualify(output: Path = Path(".harness/reports/openshell-qualification.json")):
    """Exercise actual native workspace/probe boundaries, without model calls."""
    from infosec_harness.qualification import qualify_runtime

    result = asyncio.run(qualify_runtime(output))
    typer.echo(json.dumps(result, indent=2))
    raise typer.Exit(0 if result["status"] == "passed" else 1)


def main():
    app()


if __name__ == "__main__":
    main()
