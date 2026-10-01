#!/usr/bin/env python3
"""Qualify ledger concurrency and abrupt process recovery on an isolated PostgreSQL DB.

Use only a fresh uniquely named database owned by this invocation. Never migrate or
truncate the harness database. Credentials are read locally and never printed.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import shlex
import sys
import uuid
from pathlib import Path
from urllib.parse import quote

import asyncpg

ROOT = Path(__file__).resolve().parent.parent


def read_environment(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, raw = line.split("=", 1)
        parsed = shlex.split(raw)
        if len(parsed) == 1:
            values[key.strip()] = parsed[0]
    return values


async def qualify(env_file: Path, host: str) -> int:
    run_id = uuid.uuid4().hex
    database = f"brokerqualification_{run_id}"
    report = {"run_id": run_id, "gate": "postgresql-ledger-recovery", "status": "failed",
              "database": database, "cleanup": "not_checked", "provider_dispatches": 0,
              "provider_scope": "no provider or sandbox calls", "process_exit_code": None}
    sources = ("src/infosec_harness/inference/ledger.py",
               "src/infosec_harness/inference/admission.py",
               "src/infosec_harness/inference/protocol.py",
               "src/infosec_harness/persistence/migrations/versions/0005_inference_request_ledger.py")
    report["source_digests"] = {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
                                for path in sources}
    connection = None
    process = None
    created = False
    password = ""
    try:
        settings = read_environment(env_file)
        password = settings["HARNESS_POSTGRES_PASSWORD"]
        port = int(settings["HARNESS_POSTGRES_PORT"])
        connection = await asyncpg.connect(host=host, port=port, user="harness",
                                           password=password, database="postgres", timeout=10)
        report["postgresql_version"] = await connection.fetchval("SHOW server_version")
        # Identifier comes only from this invocation's UUID, never user/runtime data.
        await connection.execute(f'CREATE DATABASE "{database}"')
        created = True
        environment = dict(os.environ)
        environment["HARNESS_DATABASE_URL"] = (
            f"postgresql+asyncpg://harness:{quote(password, safe='')}@{host}:{port}/{database}")
        environment["HARNESS_MODEL_MODE"] = "stub"
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "pytest", "tests/test_inference_ledger.py",
            "tests/test_broker_admission.py", "-o", "addopts=", "-q",
            "--tb=short", "--show-capture=no",
            cwd=ROOT, env=environment, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        output, _ = await asyncio.wait_for(process.communicate(), timeout=120)
        text = output.decode(errors="replace")
        # Defense in depth against dependency diagnostics containing connection material.
        for sensitive in (environment["HARNESS_DATABASE_URL"], password, quote(password, safe="")):
            text = text.replace(sensitive, "[REDACTED]")
        print(text[-8000:], end="")
        report["process_exit_code"] = process.returncode
        counts = re.search(r"(\d+) passed", text)
        report["passed_cases"] = int(counts.group(1)) if counts else 0
        if process.returncode == 0 and report["passed_cases"]:
            report["status"] = "passed"
    except Exception as exc:
        # Do not emit connection strings, credentials, or dependency exception messages.
        report["failure_class"] = type(exc).__name__
    finally:
        if process is not None and process.returncode is None:
            process.kill()
            await process.wait()
        if connection is not None:
            try:
                if created:
                    await connection.execute(f'DROP DATABASE "{database}" WITH (FORCE)')
                report["cleanup"] = "passed" if created else "not_applicable"
            except Exception as exc:
                report["cleanup"] = "failed"
                report["cleanup_failure_class"] = type(exc).__name__
                report["status"] = "failed"
            finally:
                await connection.close()
        destination = ROOT / ".harness" / "reports" / "credential-broker" / f"pg-ledger-{run_id}.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        print(json.dumps(report, sort_keys=True))
        print(f"Report: {destination}")
    return 0 if report["status"] == "passed" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, default=ROOT / ".harness" / "dev.env")
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()
    return asyncio.run(qualify(args.env_file, args.host))


if __name__ == "__main__":
    raise SystemExit(main())
