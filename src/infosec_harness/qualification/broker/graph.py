"""One frozen live production graph trial using only production submission, workflows and tools.

``freeze`` binds a reviewed pilot manifest to one fixed finding and source snapshot; each pilot
may freeze one trial per phase. ``execute`` runs that exact frozen manifest once, verifies the
persisted API result and actual sandbox oracle, replays every root/child history with external
I/O forbidden, and cleans up its owned workflows and worker.
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time
import uuid
from contextlib import suppress
from pathlib import Path

from infosec_harness.qualification.broker.support import (
    child_environment,
    forbid_io,
    ledger_snapshot,
    private_write,
    read_private_environment,
    reap,
)
from infosec_harness.qualification.broker.validators import (
    ROOT,
    RealProviderManifest,
    sha256_file,
    verify_configuration,
)

SOURCE = ROOT / "eval-corpus/python/sqli/vulnerable"
SOURCE_FILES = ("app.py", "requirements.txt")
DURATION_SECONDS = 7200
FINDING = {"title": "SQL injection in get_user",
    "description": "Untrusted name is concatenated into the SQL query in get_user.",
    "revision": "HEAD", "source_mode": "working_snapshot", "file_path": "app.py",
    "start_line": 16, "end_line": 16, "symbol": "get_user", "cwe": "CWE-89", "severity": "high"}


def artifact_root() -> Path:
    return (ROOT / ".harness/openshell-spike/live-qualification").resolve()


def _registry(pilot_sha256: str, phase: str) -> Path:
    return artifact_root() / f"graph-{phase}-{pilot_sha256}.frozen"


def _source_digests(directory: Path) -> dict[str, str]:
    digests = {}
    for name in SOURCE_FILES:
        if (directory / name).is_symlink():
            raise ValueError("Source fixture cannot be a symlink")
        digests[name] = sha256_file(directory / name)
    return digests


def _pilot(path: Path) -> RealProviderManifest:
    reviewed = RealProviderManifest.model_validate_json(path.read_bytes())
    verify_configuration(reviewed)
    return reviewed


def freeze(pilot: Path, destination: Path, phase: str) -> dict:
    if phase not in {"direct", "native"}:
        raise ValueError("Graph phase must be direct or native")
    if destination.exists():
        raise ValueError("Graph manifest destination already exists")
    destination = destination.resolve()
    if not destination.is_relative_to(artifact_root()):
        raise ValueError("Graph artifacts must remain checkout-owned")
    reviewed = _pilot(pilot)
    pilot_sha256 = sha256_file(pilot)
    registry = _registry(pilot_sha256, phase)
    if registry.exists():
        raise ValueError(f"This pilot already has a frozen {phase} graph trial")
    model = Path(reviewed.direct_models_config if phase == "direct" else reviewed.broker_models_config)
    source_digests = _source_digests(SOURCE)
    directory = destination.parent / ("graph-" + phase + "-" + uuid.uuid4().hex)
    directory.mkdir(mode=0o700)
    repo = directory / "repo"
    repo.mkdir()
    for name in SOURCE_FILES:
        target = repo / name
        target.write_bytes((SOURCE / name).read_bytes())
        target.chmod(0o444)
    if _source_digests(repo) != source_digests:
        raise ValueError("Graph fixture copy differs from its source")
    (repo / "tests").mkdir(mode=0o555)
    repo.chmod(0o555)
    manifest = {
        "version": 1, "phase": phase, "pilot_manifest": str(pilot.resolve()), "pilot_sha256": pilot_sha256,
        "directory": str(directory), "repo": str(repo), "source_sha256": source_digests,
        "models_config": str(model), "models_sha256": sha256_file(model),
        "broker_config": reviewed.broker_config,
        "broker_sha256": sha256_file(reviewed.broker_config) if phase == "native" else None,
        "database_env_file": reviewed.database_env_file, "worker_hmac_file": reviewed.worker_hmac_file,
        "worker_hmac_env": reviewed.worker_hmac_env, "temporal_address": reviewed.temporal_address,
        "task_queue": "broker-real-graph-" + uuid.uuid4().hex, "duration_seconds": DURATION_SECONDS,
        "concurrency": 1, "maximum_trials": 1, "finding": {**FINDING, "repo_url": str(repo)},
    }
    private_write(destination, manifest, exclusive=True)
    private_write(registry, {"manifest": str(destination), "sha256": sha256_file(destination)},
                  exclusive=True)
    return manifest


def preflight(path: Path, expected_sha256: str) -> dict:
    if sha256_file(path) != expected_sha256:
        raise ValueError("Graph execution requires its exact frozen manifest SHA256")
    value = json.loads(path.read_text())
    if value["version"] != 1:
        raise ValueError("Graph manifest version changed")
    if value["phase"] not in {"direct", "native"}:
        raise ValueError("Graph phase changed")
    if value["duration_seconds"] != DURATION_SECONDS:
        raise ValueError("Graph duration changed")
    if value["maximum_trials"] != 1:
        raise ValueError("Graph trial count changed")
    if value["concurrency"] != 1:
        raise ValueError("Graph concurrency changed")
    if not value["task_queue"].startswith("broker-real-graph-"):
        raise ValueError("Graph task queue is not owned by this runner")
    if sha256_file(value["pilot_manifest"]) != value["pilot_sha256"]:
        raise ValueError("Pilot manifest changed")
    if sha256_file(value["models_config"]) != value["models_sha256"]:
        raise ValueError("Model configuration changed")
    if value["phase"] == "native" and sha256_file(value["broker_config"]) != value["broker_sha256"]:
        raise ValueError("Broker catalog changed")
    _pilot(Path(value["pilot_manifest"]))
    registry = _registry(value["pilot_sha256"], value["phase"])
    if not registry.is_file() or json.loads(registry.read_text()) != {"manifest": str(path.resolve()),
                                                                      "sha256": expected_sha256}:
        raise ValueError("Graph registry ownership differs")
    repo = Path(value["repo"])
    if repo.is_symlink() or {p.name for p in repo.iterdir()} != {*SOURCE_FILES, "tests"}:
        raise ValueError("Graph repository contains unexpected files")
    if (repo / "tests").is_symlink() or list((repo / "tests").iterdir()):
        raise ValueError("Golden probes are forbidden")
    if _source_digests(repo) != value["source_sha256"]:
        raise ValueError("Graph repository differs from the frozen source")
    if _source_digests(SOURCE) != value["source_sha256"]:
        raise ValueError("Checkout source fixture differs from the frozen source")
    if value["finding"] != {**FINDING, "repo_url": str(repo)}:
        raise ValueError("Frozen graph finding changed")
    return value


def environment(value: dict) -> dict[str, str]:
    temporary = Path(value["directory"]) / "tmp"
    temporary.mkdir(mode=0o700, exist_ok=True)
    native = value["phase"] == "native"
    if not (ROOT / ".harness/dev.env").is_file():
        raise ValueError("The production graph trial requires the managed sandbox settings")
    env = child_environment(
        ROOT, models_config=value["models_config"],
        database=read_private_environment(value["database_env_file"]),
        worker_key=(value["worker_hmac_env"], value["worker_hmac_file"]),
        broker_config=value["broker_config"] if native else None)
    # The managed Docker CLI executes inside Lima; host /tmp is not shared.
    # All generated Dockerfiles and copied contexts must be guest-visible.
    env.update(TMPDIR=str(temporary), HARNESS_TASK_QUEUE=value["task_queue"],
        HARNESS_TEMPORAL_ADDRESS=value["temporal_address"], HARNESS_PER_REPO_CONCURRENCY="1",
        HARNESS_RECIPE_CACHE_ENABLED="false",
        HARNESS_WORKSPACE_DIR=str(Path(value["directory"]) / "workspace"),
        HARNESS_REPORTS_DIR=str(Path(value["directory"]) / "reports"), HARNESS_S3_ENDPOINT="",
        HARNESS_ROOT_MAX_ELAPSED_SECONDS=str(DURATION_SECONDS))
    if not native:
        env["HARNESS_OPENAI_API_KEY"] = "local-no-auth-qualification"
    return env


def oracle_passed(detail: dict, prepared_status: str | None = None) -> bool:
    evidence = detail.get("evidence", {})
    executions = evidence.get("executions", [])
    return (prepared_status == "ready"
            and evidence.get("manifest", {}).get("environment", {}).get("status") == "ready" and any(
        execution.get("exit_code") == 0 and not execution.get("timed_out")
        and execution.get("oracle_fired") and execution.get("precondition_reached")
        and execution.get("sink_returned") for execution in executions))


async def replay(histories: list, batch: str) -> None:
    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from temporalio.worker import Replayer

    from infosec_harness.workflows.worker import WORKFLOWS
    before = await ledger_snapshot(batch)
    with forbid_io(synchronous=True):
        player = Replayer(workflows=WORKFLOWS, plugins=[PydanticAIPlugin()])
        for history in histories:
            await player.replay_workflow(history)
    if await ledger_snapshot(batch) != before:
        raise AssertionError("Production replay changed the durable ledger")


async def histories_for(client, root: str):
    found, pending = {}, [root]
    while pending:
        identity = pending.pop()
        if identity in found:
            continue
        history = await client.get_workflow_handle(identity).fetch_history()
        found[identity] = history
        for event in history.events:
            if event.HasField("start_child_workflow_execution_initiated_event_attributes"):
                pending.append(event.start_child_workflow_execution_initiated_event_attributes.workflow_id)
    return found


def claim_execution(directory: Path) -> None:
    """A frozen trial may produce requests once, even if execution later fails."""
    descriptor = os.open(directory / "execution.started", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)


def _start_worker(log):
    # The external qualification watchdog owns one exclusive process group.
    # Keep the worker and its descendants in that group so a hard CLI deadline
    # cannot leave a detached worker able to schedule more activities.
    return subprocess.Popen([sys.executable, "-m", "infosec_harness.workflows.worker"],
        cwd=ROOT, env=dict(os.environ), stdout=log, stderr=log)


async def _cancel_owned(client, histories: dict, batch: str) -> bool:
    clean = True
    for identity in histories or {"batch:" + batch: None}:
        handle = client.get_workflow_handle(identity)
        try:
            if (await handle.describe()).status.name == "RUNNING":
                await handle.cancel()
                try:
                    await asyncio.wait_for(handle.result(), timeout=15)
                except Exception:
                    if (await handle.describe()).status.name == "RUNNING":
                        await handle.terminate("Scoped qualification deadline cleanup")
            if (await handle.describe()).status.name == "RUNNING":
                clean = False
        except Exception:
            clean = False
    return clean


async def execute(path: Path, expected_sha256: str) -> dict:
    value = preflight(path, expected_sha256)
    claim_execution(Path(value["directory"]))
    os.environ.update(environment(value))
    import httpx

    from infosec_harness.api.app import _submit, app
    from infosec_harness.domain.models import FindingInput, TriageRunOutput
    from infosec_harness.persistence import store
    from infosec_harness.workflows.worker import connect
    directory = Path(value["directory"])
    report = {"phase": value["phase"], "graph": "failed", "replay": "not_checked",
        "workflow_cleanup": "not_checked", "worker_cleanup": "not_checked", "quality_promotion": False}
    worker = None
    client = None
    batch = None
    histories = {}
    started = time.monotonic()
    try:
        with (directory / "worker.log").open("ab") as log:
            worker = _start_worker(log)
        client = await connect()
        batch = await _submit([FindingInput.model_validate(value["finding"])], "frozen-real-graph-" + value["phase"], "temporal")
        report["batch_id"] = batch
        handle = client.get_workflow_handle("batch:" + batch)
        outputs = await asyncio.wait_for(handle.result(), timeout=value["duration_seconds"])
        if not isinstance(outputs, list) or len(outputs) != 1:
            raise ValueError("Graph batch must return exactly one result")
        observed = TriageRunOutput.model_validate(outputs[0])
        private_write(directory / "workflow-result.json", observed.model_dump(mode="json"), exclusive=True)
        summaries = await store.list_runs(batch_id=batch)
        if len(summaries) != 1:
            raise ValueError("Graph batch must persist exactly one run")
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://qualification.local") as api:
            response = await api.get("/api/runs/" + summaries[0]["id"])
            if response.status_code != 200:
                raise ValueError("Persisted run query failed")
            detail = response.json()
        if detail["finding"]["fingerprint"] != observed.finding.fingerprint:
            raise ValueError("Persisted finding differs from the workflow result")
        if detail["result"] != observed.result.model_dump(mode="json"):
            raise ValueError("Persisted result differs from the workflow result")
        private_write(directory / "persisted-api-result.json", detail, exclusive=True)
        report.update(run_id=summaries[0]["id"], query_api="passed", temporal_visibility=(await handle.describe()).status.name,
            actual_runsc_oracle="passed" if oracle_passed(detail, observed.prepared_status) else "failed")
        histories = await histories_for(client, "batch:" + batch)
        for index, history in enumerate(histories.values()):
            (directory / f"history-{index}.json").write_text(history.to_json())
        report["production_histories"] = len(histories)
        await replay(list(histories.values()), batch)
        report["replay"] = "passed"
        report["expected_verdict"] = "passed" if observed.result.verdict.label.value == "potentially_exploitable" else "failed"
        report["graph"] = ("passed" if oracle_passed(detail, observed.prepared_status)
                           and report["expected_verdict"] == "passed" else "failed")
    except Exception as error:
        report["failure_class"] = type(error).__name__
    finally:
        if client is not None and batch is not None:
            if not histories:
                with suppress(Exception):
                    histories = await histories_for(client, "batch:" + batch)
            report["workflow_cleanup"] = "passed" if await _cancel_owned(client, histories, batch) else "failed"
        if worker is not None:
            # Signal the exact retained child, never the shared outer watchdog group.
            report["worker_cleanup"] = "passed" if await asyncio.to_thread(reap, worker) else "failed"
        report["elapsed_seconds"] = time.monotonic() - started
        private_write(directory / "report.json", report, exclusive=True)
    return report
