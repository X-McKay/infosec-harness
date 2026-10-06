"""Operator entry points for the single native investigation path.

Exit codes: 0 passed (or a completed diagnostic), 1 a gate failed or was not checked,
2 a usage or configuration error, 3 an operational failure (Temporal, API or a crash).
"""

import asyncio
import json
import logging
import sys
from collections.abc import Coroutine
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn

import typer
from pydantic import ValidationError

from infosec_harness.config import get_settings, use_settings_file

# Locals can hold credentials (the Temporal API key), so tracebacks never print them.
app = typer.Typer(no_args_is_help=True, pretty_exceptions_show_locals=False)
log = logging.getLogger(__name__)

EXIT_FAILED = 1
EXIT_OPERATIONAL = 3
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"
# Per-request and per-call chatter; their warnings still reach the handler.
QUIET_LOGGERS = ("httpx", "httpcore", "openai", "botocore", "boto3", "urllib3", "uvicorn.access")
HANDLER_NAME = "harness-stderr"


def configure_logging() -> None:
    """One stderr handler for the long-running commands, at ``Settings.log_level``."""
    root = logging.getLogger()
    if not any(handler.get_name() == HANDLER_NAME for handler in root.handlers):
        handler = logging.StreamHandler(sys.stderr)
        handler.set_name(HANDLER_NAME)
        handler.setFormatter(logging.Formatter(LOG_FORMAT))
        root.addHandler(handler)
    root.setLevel(get_settings().log_level)
    for name in QUIET_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)


def validation_reasons(error: ValidationError) -> str:
    """Field locations and reasons only: input values may be credentials."""
    return "; ".join(
        f"{'.'.join(map(str, item['loc'])) or 'document'}: {item['msg']}"
        for item in error.errors(include_input=False, include_url=False)
    )


@app.callback()
def configure(
    settings: Path | None = typer.Option(
        None, help="Frozen Settings JSON; HARNESS_* environment variables are then ignored."
    ),
) -> None:
    """Investigate reported vulnerabilities through native OpenShell and Temporal."""
    if settings is None:
        return
    try:
        use_settings_file(settings)
    except OSError as exc:
        reason = exc.strerror or type(exc).__name__
        raise typer.BadParameter(f"{settings}: {reason}", param_hint="--settings") from exc
    except ValidationError as exc:
        raise typer.BadParameter(
            f"{settings}: {validation_reasons(exc)}", param_hint="--settings"
        ) from exc


def new_report(kind: str) -> Path:
    # Timestamped by default; an existing report is still never overwritten.
    return get_settings().reports_dir / f"{kind}-{datetime.now(UTC):%Y%m%dT%H%M%SZ}.json"


def operate[T](work: Coroutine[Any, Any, T]) -> T:
    """Run one command's work; an operational failure is one stderr line and exit 3."""
    from fastapi import HTTPException
    from temporalio.service import RPCError

    from infosec_harness.api import rpc_failure

    try:
        return asyncio.run(work)
    except HTTPException as exc:
        message = str(exc.detail)
    except RPCError as exc:
        message = rpc_failure(exc.status)[1]
    except Exception as exc:  # noqa: BLE001 - every crash exits 3, never as a gate result
        log.exception("event=command_failed error=%s", type(exc).__name__)
        message = f"{type(exc).__name__}: {exc}"[:300]
    typer.echo(f"error: {message}", err=True)
    raise typer.Exit(EXIT_OPERATIONAL)


def exit_status(result: dict[str, Any]) -> int:
    """0 for a passed gate or a completed diagnostic; anything else (or no status) is 1."""
    status = result.get("status")
    if status == "passed" or (result.get("kind") == "diagnostic" and status == "completed"):
        return 0
    return EXIT_FAILED


def finish(result: dict[str, Any]) -> NoReturn:
    typer.echo(json.dumps(result, indent=2))
    raise typer.Exit(exit_status(result))


@app.command()
def api(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Serve the lightweight HTTP API."""
    import uvicorn

    from infosec_harness.api import app as http

    configure_logging()
    # The app object, not an import string: a reloader or worker process would re-read the
    # environment instead of the bound settings. log_config=None keeps the one handler.
    uvicorn.run(http, host=host, port=port, log_config=None)


@app.command()
def worker(
    task_queue: str | None = typer.Option(
        None, help="Serve this task queue (for example, drain an owned eval queue)."
    ),
) -> None:
    """Run the Temporal worker with native PydanticAI model/tool activities."""
    from infosec_harness.api import connect
    from infosec_harness.workflows.worker import create_worker

    configure_logging()
    settings = get_settings()
    if task_queue:
        settings = settings.model_copy(update={"task_queue": task_queue})

    async def serve() -> None:
        runtime = create_worker(await connect(settings), settings)
        await runtime.run()

    operate(serve())


@app.command()
def submit(path: Path) -> None:
    """Submit one Finding JSON document to Temporal."""
    from infosec_harness.api import connect
    from infosec_harness.api import submit as start
    from infosec_harness.contracts import Finding, RunState

    try:
        finding = Finding.model_validate_json(path.read_bytes())
    except OSError as exc:
        reason = exc.strerror or type(exc).__name__
        raise typer.BadParameter(f"{path}: {reason}", param_hint="PATH") from exc
    except ValidationError as exc:
        raise typer.BadParameter(f"{path}: {validation_reasons(exc)}", param_hint="PATH") from exc

    async def send() -> RunState:
        return await start(finding, await connect())

    typer.echo(operate(send()).model_dump_json(indent=2))


@app.command()
def report(run_id: str) -> None:
    """Read an investigation's current status and validated result."""
    from infosec_harness.api import connect, run
    from infosec_harness.contracts import RunState

    async def read() -> RunState:
        return await run(run_id, await connect())

    typer.echo(operate(read()).model_dump_json(indent=2))


@app.command("eval")
def evaluate(
    manifest: Path = typer.Option(
        Path("eval-corpus/manifest.json"), help="Corpus manifest with independent ground truth."
    ),
    output: Path | None = typer.Option(
        None,
        help="Report path, never overwritten. Default: <reports_dir>/model-<UTC>.json "
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
    parallel: int = typer.Option(
        1, min=1, help="Run up to N cases at once (recorded as a run condition; default 1)."
    ),
) -> None:
    """Run the paired corpus (or a diagnostic subset) once, preserving failures and unstarted cases."""
    if not allow_inference:
        raise typer.BadParameter("Live evaluation requires --allow-inference")
    from infosec_harness.evals.cohort import evaluate_corpus

    configure_logging()
    output = output or new_report("diagnostic" if case else "model")
    finish(operate(evaluate_corpus(
        manifest, output, get_settings(), names=tuple(case or ()),
        owned_worker=owned_worker, keep_going=keep_going, parallel=parallel,
    )))


@app.command()
def qualify(
    output: Path | None = typer.Option(
        None, help="Report path, never overwritten. Default: <reports_dir>/openshell-<UTC>.json."
    ),
) -> None:
    """Exercise actual native workspace/probe boundaries, without model calls."""
    from infosec_harness.evals.qualification import qualify_runtime

    finish(operate(qualify_runtime(output or new_report("openshell"))))


@app.command()
def replay(
    run_id: str,
    output: Path | None = typer.Option(
        None, help="Also write the report here, never overwritten. Default: print only."
    ),
) -> None:
    """Replay one recorded workflow history with no native or model dispatch."""
    from infosec_harness._io import write_json
    from infosec_harness.evals.cohort import replay_history

    if output and output.exists():
        raise typer.BadParameter(f"{output} already exists", param_hint="--output")
    result = operate(replay_history(run_id, get_settings()))
    if output:
        write_json(output, result, exclusive=True)
    finish(result)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
