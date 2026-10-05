#!/usr/bin/env python3
"""Run real HTTPS/PostgreSQL broker fixtures; native lifecycle is explicitly mocked."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import uuid
from contextlib import suppress
from pathlib import Path
from urllib.parse import quote

import asyncpg
from broker_ledger_check import read_environment

from infosec_harness.qualification.broker.service import (
    AGENTS,
    environment,
    free_port,
    generate_pki,
    private_write,
    settings_files,
    wait_port,
)

ROOT = Path(__file__).resolve().parent.parent


async def run(env_file: Path, *, temporal: bool) -> int:
    run_id = uuid.uuid4().hex
    database = "brokerservice_" + run_id
    directory = Path(tempfile.mkdtemp(prefix="broker-service-", dir="/private/tmp"))
    directory.chmod(0o700)
    report = {"run_id": run_id, "layer_b": "failed", "layer_d": "not_checked", "layer_d_services": "not_checked",
        "native_openshell": "not_checked", "native_adapter": "explicit test-only shim",
        "provider": "local counted HTTPS mock", "paid_dispatches": 0,
        "database": database, "database_cleanup": "not_checked", "process_cleanup": "not_checked"}
    admin = None
    created = False
    processes = []
    sensitive = []
    pytest_process = None
    try:
        values = read_environment(env_file)
        password = values["HARNESS_POSTGRES_PASSWORD"]
        port = int(values["HARNESS_POSTGRES_PORT"])
        admin = await asyncpg.connect(host="127.0.0.1", port=port, user="harness", password=password,
                                      database="postgres", timeout=10)
        report["postgresql_version"] = await admin.fetchval("SHOW server_version")
        await admin.execute(f'CREATE DATABASE "{database}"')
        created = True
        pki = generate_pki(directory)
        provider_port, controller_port = free_port(), free_port()
        catalog = settings_files(directory, pki, controller_port, provider_port)
        repo = directory / "repo"
        repo.mkdir()
        (repo / "sample.py").write_text("def sample(value):\n    return value\n")
        manifest_path = directory / "manifest.json"
        manifest = {**catalog, "run_id": run_id, "directory": str(directory), "manifest": str(manifest_path),
            "provider_port": provider_port, "controller_port": controller_port, "pki": pki,
            "repo": str(repo), "worker_key": secrets.token_hex(32), "canary": secrets.token_hex(32),
            "database_url": f"postgresql+asyncpg://harness:{quote(password, safe='')}@127.0.0.1:{port}/{database}",
            "temporal_address": "127.0.0.1:7365", "task_queue": "brokerqualification-" + run_id}
        private_write(manifest_path, manifest)
        sensitive = [password, quote(password, safe=""), manifest["worker_key"], manifest["canary"], manifest["database_url"]]
        runtime_environment = environment(manifest)
        for role, listener in (("provider", provider_port), ("controller", controller_port)):
            with open(directory / f"{role}.log", "ab") as log:
                process = subprocess.Popen([sys.executable, "-m", "infosec_harness.qualification.broker.service",
                    role, "--manifest", str(manifest_path)], cwd=ROOT, env=runtime_environment,
                    stdout=log, stderr=log, start_new_session=True)
            processes.append(process)
            await wait_port(listener, process=process)
        selected = ["tests/runtime/test_broker_service_integration.py"]
        if temporal:
            selected.append("tests/runtime/test_broker_temporal_integration.py")
        pytest_process = await asyncio.create_subprocess_exec(sys.executable, "-m", "pytest", *selected,
            "-o", "addopts=", "-q", "--tb=short", "--show-capture=no", cwd=ROOT, env=runtime_environment,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        output, _ = await asyncio.wait_for(pytest_process.communicate(), timeout=300)
        text = output.decode(errors="replace")
        for secret in sensitive:
            text = text.replace(secret, "[REDACTED]")
        print(text[-40000:], end="")
        report["pytest_exit_code"] = pytest_process.returncode
        cases = directory / "cases.jsonl"
        report["cases"] = [json.loads(line) for line in cases.read_text().splitlines()] if cases.exists() else []
        events = directory / "upstream.jsonl"
        report["dispatches"] = len(events.read_text().splitlines()) if events.exists() else 0
        names = {case["case"] for case in report["cases"]}
        required_b = {"tls_hmac_denials", "registered_local_tool_structured_output",
            "executor_lost_ack_saved_result", "executor_before_commit_unknown",
            "concurrent_http_duplicate", "close_and_retained_result",
            "canary_scanner_positive_control", "actual_eval_issuance_tool_structured_cleanup", "local_prepare_triage_broker_graph"}
        required_b.update("registered_agent:" + agent for agent in AGENTS)
        complete = pytest_process.returncode == 0 and "skipped" not in text
        report["layer_b"] = "passed" if complete and required_b.issubset(names) else "failed"
        if temporal:
            qualified = complete and required_b.issubset(names) and {
                "temporal_worker_kill_saved_result_retry_replay", "temporal_all_registered_agents_replay",
                "direct_stub_history_broker_config_replay"}.issubset(names)
            report["layer_d_services"] = "passed" if qualified else "failed"
            report["layer_d"] = "partial" if qualified else "failed"
        conflicts = directory / "conflict-fields.jsonl"
        if conflicts.exists():
            report["retry_conflicts"] = [json.loads(line) for line in conflicts.read_text().splitlines()]
        for path in directory.glob("*.log"):
            contents = path.read_text(errors="replace")
            for secret in sensitive:
                contents = contents.replace(secret, "[REDACTED]")
            if contents:
                report.setdefault("diagnostics", {})[path.name] = contents[-2000:]
    except Exception as exc:
        report["failure_class"] = type(exc).__name__
        for path in directory.glob("*.log"):
            contents = path.read_text(errors="replace")
            for secret in sensitive:
                contents = contents.replace(secret, "[REDACTED]")
            if contents:
                report.setdefault("diagnostics", {})[path.name] = contents[-3000:]
    finally:
        if pytest_process is not None and pytest_process.returncode is None:
            pytest_process.kill()
            await pytest_process.wait()
        for process in reversed(processes):
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
        for process in processes:
            try:
                await asyncio.to_thread(process.wait, timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                await asyncio.to_thread(process.wait, timeout=5)
        # Executors inherit the controller's group; inspect only this run's recorded PIDs.
        pids = directory / "pids.jsonl"
        active = []
        report["service_pids"] = [process.pid for process in processes]
        if pids.exists():
            for line in pids.read_text().splitlines():
                item = json.loads(line)
                if item["role"] == "temporal-worker":
                    with suppress(ProcessLookupError):
                        os.killpg(item["pid"], signal.SIGKILL)
                status = subprocess.run(["ps", "-p", str(item["pid"]), "-o", "stat="], capture_output=True, text=True).stdout.strip()
                if status and not status.startswith("Z"):
                    active.append(item["pid"])
        report["process_cleanup"] = "failed" if active else "passed"
        report["active_fixture_pids"] = active
        if admin is not None:
            try:
                if created:
                    await admin.execute(f'DROP DATABASE "{database}" WITH (FORCE)')
                report["database_cleanup"] = "passed" if created else "not_applicable"
            except Exception as exc:
                report["database_cleanup"] = "failed"
                report["cleanup_failure_class"] = type(exc).__name__
            await admin.close()
        destination = ROOT / ".harness" / "reports" / "credential-broker" / f"service-{run_id}.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.rmtree(directory)
            report["private_fixture_cleanup"] = "passed"
        except OSError as exc:
            report["private_fixture_cleanup"] = "failed"
            report["private_cleanup_failure_class"] = type(exc).__name__
        destination.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        print(json.dumps(report, sort_keys=True))
        print(f"Report: {destination}")
    success = report["layer_b"] == "passed" and report["database_cleanup"] == report["process_cleanup"] == report["private_fixture_cleanup"] == "passed"
    if temporal:
        success = success and report["layer_d_services"] == "passed"
    return 0 if success else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, default=ROOT / ".harness" / "dev.env")
    parser.add_argument("--temporal", action="store_true")
    arguments = parser.parse_args()
    return asyncio.run(run(arguments.env_file, temporal=arguments.temporal))


if __name__ == "__main__":
    raise SystemExit(main())
