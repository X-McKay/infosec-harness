"""Frozen live graph qualification using only production submission/workflows/tools."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
import uuid
from contextlib import suppress
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "eval-corpus/python/sqli/vulnerable"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_private(path: Path, value: dict) -> None:
    with path.open("x") as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, sort_keys=True, indent=2)


def freeze(pilot: Path, destination: Path, phase: str, *, infrastructure_correction: str | None = None) -> dict:
    if phase not in {"direct", "native"} or destination.exists():
        raise ValueError("Choose an unused graph manifest and a declared phase")
    parent = (ROOT / ".harness/openshell-spike/live-qualification").resolve()
    destination = destination.resolve()
    if not destination.is_relative_to(parent):
        raise ValueError("Graph artifacts must remain checkout-owned")
    registry = parent / f"graph-{phase}-manifest.frozen"
    supersedes = None
    if registry.exists():
        if infrastructure_correction != "guest-visible-tmpdir" or phase != "direct":
            raise ValueError("This graph phase already has a frozen trial")
        previous = json.loads(registry.read_text())
        previous_manifest = Path(previous["manifest"])
        if sha(previous_manifest) != previous["sha256"]:
            raise ValueError("Previous trial manifest changed")
        prior = json.loads(previous_manifest.read_text())
        outcome = json.loads((Path(prior["directory"]) / "report.json").read_text())
        if outcome.get("graph") != "failed" or any(outcome.get(key) != "passed" for key in ("replay", "workflow_cleanup", "worker_cleanup")):
            raise ValueError("Previous trial must be terminal, replayed, and cleaned up")
        supersedes = {"manifest": str(previous_manifest), "sha256": previous["sha256"], "correction": infrastructure_correction}
        registry = parent / "graph-direct-guest-visible-tmpdir.frozen"
        if registry.exists():
            raise ValueError("This infrastructure correction already has a frozen trial")
    values = json.loads(pilot.read_text())
    directory = destination.parent / ("graph-" + phase + "-" + uuid.uuid4().hex)
    directory.mkdir(mode=0o700)
    repo = directory / "repo"
    repo.mkdir()
    digests = {}
    for name in ("app.py", "requirements.txt"):
        source = SOURCE / name
        if source.is_symlink():
            raise ValueError("Source fixture cannot be a symlink")
        target = repo / name
        target.write_bytes(source.read_bytes())
        target.chmod(0o444)
        digests[name] = sha(target)
    (repo / "tests").mkdir(mode=0o555)
    repo.chmod(0o555)
    model = Path(values["direct_models_config"] if phase == "direct" else values["broker_models_config"])
    manifest = {
        "version": 1, "phase": phase, "pilot_manifest": str(pilot.resolve()),
        "pilot_sha256": sha(pilot), "directory": str(directory), "repo": str(repo),
        "source_sha256": digests, "models_config": str(model), "models_sha256": sha(model),
        "broker_config": values["broker_config"],
        "broker_sha256": sha(Path(values["broker_config"])) if phase == "native" else None,
        "database_env_file": values["database_env_file"],
        "worker_hmac_file": values["worker_hmac_file"], "worker_hmac_env": values["worker_hmac_env"],
        "temporal_address": values["temporal_address"], "task_queue": "broker-real-graph-" + uuid.uuid4().hex,
        "duration_seconds": 7200, "concurrency": 1, "maximum_trials": 1,
        "finding": {"title": "SQL injection in get_user", "description": "Untrusted name is concatenated into the SQL query in get_user.",
            "repo_url": str(repo), "revision": "HEAD", "source_mode": "working_snapshot",
            "file_path": "app.py", "start_line": 16, "end_line": 16, "symbol": "get_user",
            "cwe": "CWE-89", "severity": "high"},
    }
    if supersedes is not None:
        manifest["supersedes_infrastructure_failure"] = supersedes
    write_private(destination, manifest)
    write_private(registry, {"manifest": str(destination), "sha256": sha(destination)})
    return manifest


def preflight(path: Path) -> dict:
    value = json.loads(path.read_text())
    if (value["version"] != 1 or value["phase"] not in {"direct", "native"}
            or value["duration_seconds"] != 7200 or value["maximum_trials"] != 1
            or value["concurrency"] != 1 or not value["task_queue"].startswith("broker-real-graph-")):
        raise ValueError("Graph scope changed")
    if sha(Path(value["pilot_manifest"])) != value["pilot_sha256"]:
        raise ValueError("Pilot manifest changed")
    if sha(Path(value["models_config"])) != value["models_sha256"]:
        raise ValueError("Model configuration changed")
    if value["phase"] == "native" and sha(Path(value["broker_config"])) != value["broker_sha256"]:
        raise ValueError("Broker catalog changed")
    repo = Path(value["repo"])
    if repo.is_symlink() or set(p.name for p in repo.iterdir()) != {"app.py", "requirements.txt", "tests"}:
        raise ValueError("Graph repository contains unexpected files")
    if (repo / "tests").is_symlink() or list((repo / "tests").iterdir()):
        raise ValueError("Golden probes are forbidden")
    for name in ("app.py", "requirements.txt"):
        if (repo / name).is_symlink() or sha(repo / name) != value["source_sha256"][name] or sha(SOURCE / name) != value["source_sha256"][name]:
            raise ValueError("Graph fixture differs from frozen source")
    expected = {"title": "SQL injection in get_user", "description": "Untrusted name is concatenated into the SQL query in get_user.",
        "repo_url": str(repo), "revision": "HEAD", "source_mode": "working_snapshot", "file_path": "app.py",
        "start_line": 16, "end_line": 16, "symbol": "get_user", "cwe": "CWE-89", "severity": "high"}
    if value["finding"] != expected:
        raise ValueError("Frozen graph finding changed")
    return value


def environment(value: dict) -> dict[str, str]:
    from broker_real_provider_fixture import read_private_environment
    env = dict(os.environ)
    temporary = Path(value["directory"]) / "tmp"
    temporary.mkdir(mode=0o700, exist_ok=True)
    # The managed Docker CLI executes inside Lima; host /tmp is not shared.
    # All generated Dockerfiles and copied contexts must be guest-visible.
    env["TMPDIR"] = str(temporary)
    for name in list(env):
        if name.startswith(("AWS_", "HARNESS_BROKER_")) or name in {"OPENAI_API_KEY", "HARNESS_OPENAI_API_KEY", "HARNESS_MODEL_BACKEND", "HARNESS_S3_ENDPOINT"}:
            env.pop(name, None)
    for name, setting in read_private_environment(str(ROOT / ".harness/dev.env")).items():
        if name.startswith(("HARNESS_SANDBOX_", "HARNESS_BUILD_")) or name == "HARNESS_BUILDX_BUILDER":
            env[name] = setting
    env.update(read_private_environment(value["database_env_file"]))
    env.update(HARNESS_MODEL_MODE="live", HARNESS_MODELS_CONFIG=value["models_config"],
        HARNESS_TASK_QUEUE=value["task_queue"], HARNESS_TEMPORAL_ADDRESS=value["temporal_address"],
        HARNESS_PER_REPO_CONCURRENCY="1", HARNESS_RECIPE_CACHE_ENABLED="false",
        HARNESS_WORKSPACE_DIR=str(Path(value["directory"]) / "workspace"),
        HARNESS_REPORTS_DIR=str(Path(value["directory"]) / "reports"), HARNESS_S3_ENDPOINT="",
        HARNESS_ALLOW_INSECURE_RUNTIME="false", HARNESS_SANDBOX_RUNTIME="runsc",
        HARNESS_AGENT_RUN_TIMEOUT_S="600", HARNESS_ROOT_MAX_ELAPSED_SECONDS="7200",
        PYDANTIC_AI_NO_BANNER="1",
        PYTHONPATH=os.pathsep.join((str(ROOT / "src"), str(ROOT / "tests/runtime"))))
    env["PATH"] = os.pathsep.join((str(ROOT / ".harness/bin"), str(ROOT / ".venv/bin"), env.get("PATH", "")))
    if value["phase"] == "native":
        env["HARNESS_BROKER_CONFIG"] = value["broker_config"]
        key = Path(value["worker_hmac_file"])
        if key.is_symlink() or key.stat().st_mode & 0o077:
            raise ValueError("Worker channel key must be private")
        env[value["worker_hmac_env"]] = key.read_text().strip()
    else:
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


async def ledger_snapshot(batch: str) -> dict:
    from sqlalchemy import select

    from infosec_harness.persistence import db
    async with db.session() as session:
        rows = (await session.scalars(select(db.InferenceRequestRecord).where(db.InferenceRequestRecord.root_id == batch))).all()
        root = await session.get(db.BudgetLedger, batch)
        return {"rows": [{"id": row.request_id, "state": row.state, "revision": row.revision, "result": row.result} for row in sorted(rows, key=lambda r: r.request_id)],
            "root": root.state if root else None}


async def replay(histories: list, batch: str) -> None:
    import httpx
    import httpx2
    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from temporalio.worker import Replayer

    from infosec_harness.inference import invocations
    from infosec_harness.inference.transport import BrokerModel
    from infosec_harness.persistence import db
    from infosec_harness.workflows.worker import WORKFLOWS
    before = await ledger_snapshot(batch)
    async def forbidden(*_args, **_kwargs):
        raise AssertionError("Production replay attempted external I/O")
    def forbidden_sync(*_args, **_kwargs):
        raise AssertionError("Production replay attempted synchronous I/O")
    with (patch.object(BrokerModel, "request", forbidden),
          patch.object(invocations, "request_invocation", forbidden),
          patch.object(httpx.AsyncClient, "request", forbidden),
          patch.object(httpx2.AsyncClient, "request", forbidden),
          patch.object(db, "session", forbidden_sync),
          patch.object(subprocess, "Popen", forbidden_sync),
          patch.object(asyncio, "create_subprocess_exec", forbidden)):
        player = Replayer(workflows=WORKFLOWS, plugins=[PydanticAIPlugin()])
        for history in histories:
            await player.replay_workflow(history)
    assert await ledger_snapshot(batch) == before


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


async def execute(path: Path) -> dict:
    value = preflight(path)
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
            worker = subprocess.Popen([sys.executable, "-m", "infosec_harness.workflows.worker"],
                cwd=ROOT, env=dict(os.environ), stdout=log, stderr=log, start_new_session=True)
        client = await connect()
        batch = await _submit([FindingInput.model_validate(value["finding"])], "frozen-real-graph-" + value["phase"], "temporal")
        report["batch_id"] = batch
        handle = client.get_workflow_handle("batch:" + batch)
        outputs = await asyncio.wait_for(handle.result(), timeout=value["duration_seconds"])
        assert isinstance(outputs, list) and len(outputs) == 1
        observed = TriageRunOutput.model_validate(outputs[0])
        write_private(directory / "workflow-result.json", observed.model_dump(mode="json"))
        summaries = await store.list_runs(batch_id=batch)
        assert len(summaries) == 1
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://qualification.local") as api:
            response = await api.get("/api/runs/" + summaries[0]["id"])
            assert response.status_code == 200
            detail = response.json()
        assert detail["finding"]["fingerprint"] == observed.finding.fingerprint
        assert detail["result"] == observed.result.model_dump(mode="json")
        write_private(directory / "persisted-api-result.json", detail)
        report.update(run_id=summaries[0]["id"], query_api="passed", temporal_visibility=(await handle.describe()).status.name,
            actual_runsc_oracle="passed" if oracle_passed(detail, observed.prepared_status) else "failed")
        histories = await histories_for(client, "batch:" + batch)
        for index, history in enumerate(histories.values()):
            (directory / f"history-{index}.json").write_text(history.to_json())
        report["production_histories"] = len(histories)
        await replay(list(histories.values()), batch)
        report["replay"] = "passed"
        report["expected_verdict"] = "passed" if observed.result.verdict.label.value == "potentially_exploitable" else "failed"
        report["graph"] = "passed" if oracle_passed(detail, observed.prepared_status) and report["expected_verdict"] == "passed" else "failed"
    except Exception as error:
        report["failure_class"] = type(error).__name__
    finally:
        if client is not None and batch is not None:
            if not histories:
                with suppress(Exception):
                    histories = await histories_for(client, "batch:" + batch)
            clean = True
            for identity in histories or {"batch:" + batch: None}:
                handle = client.get_workflow_handle(identity)
                try:
                    status = (await handle.describe()).status.name
                    if status == "RUNNING":
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
            report["workflow_cleanup"] = "passed" if clean else "failed"
        if worker is not None:
            with suppress(ProcessLookupError):
                os.killpg(worker.pid, signal.SIGTERM)
            try:
                await asyncio.to_thread(worker.wait, timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(worker.pid, signal.SIGKILL)
                await asyncio.to_thread(worker.wait, timeout=10)
            report["worker_cleanup"] = "passed" if worker.poll() is not None else "failed"
        report["elapsed_seconds"] = time.monotonic() - started
        write_private(directory / "report.json", report)
    return report
