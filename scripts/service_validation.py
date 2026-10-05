#!/usr/bin/env python3
"""Read-only service validation, with an explicitly requested one-call model check."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx
from pydantic import TypeAdapter
from ui_deployment_smoke import MAX_RESPONSE_BYTES, base_url
from ui_deployment_smoke import check as check_ui

from infosec_harness.api.contracts import RuntimeStatus
from infosec_harness.api.evidence_io import reject_duplicate_fields
from infosec_harness.api.model_observation import ModelConnectionReceipt

ROOT = Path(__file__).resolve().parents[1]
STATES = {"passed", "failed", "not_checked"}
CHECK_NAMES = ("database", "workflow_pollers", "activity_pollers", "profile_identity")


def gate(status, detail):
    if status not in STATES:
        raise ValueError("invalid gate")
    return {"status": status, "detail": detail}


def output_path(path: Path) -> Path:
    path = path.absolute()
    if (
        any(part.is_symlink() for part in (path, *path.parents))
        or (path.exists() and not path.is_file())
        or any(parent.exists() and not parent.is_dir() for parent in path.parents)
    ):
        raise ValueError("unsafe output")
    return path


def private_json(path: Path, value: dict):
    """Atomic private output; refuse symlink paths, never publish a partial receipt."""
    path = output_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".validation-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def managed_check(subcommand, args, timeout):
    """Exec `harness ops <subcommand>` in the running worker; Compose never restarts it."""
    project = os.environ.get("COMPOSE_PROJECT_NAME", "")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", project):
        raise ValueError("managed project unavailable")
    shim = ROOT / ".harness/bin/docker"
    if not shim.is_file():
        raise ValueError("managed runtime unavailable")
    command = [
        str(shim),
        "compose",
        "-f",
        "docker-compose.yml",
        "-f",
        "docker-compose.dev.yml",
        "--project-name",
        project,
        "--env-file",
        ".harness/dev.env",
        "exec",
        "-T",
        "worker",
        "harness",
        "ops",
        subcommand,
        *args,
    ]
    result = subprocess.run(
        command,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=timeout + 15,
        check=False,
    )
    if len(result.stdout) > 32768:
        raise ValueError("oversized worker response")
    value = json.loads(result.stdout, object_pairs_hook=reject_duplicate_fields)
    if not isinstance(value, dict):
        raise ValueError("invalid worker response")
    checks = value.get("checks", {})
    if result.returncode != 0 and (
        value.get("status") == "passed"
        or (
            isinstance(checks, dict)
            and checks
            and all(
                isinstance(row, dict) and row.get("status") == "passed" for row in checks.values()
            )
        )
    ):
        raise ValueError("contradictory worker response")
    return value


def public_profile(value):
    """Project identities only; never echo worker output or configuration fields."""
    result = {}
    for name, size in (
        ("source_commit", 40),
        ("model_config_sha256", 64),
        ("broker_config_sha256", 64),
    ):
        field = value.get(name)
        result[name] = (
            field
            if isinstance(field, str) and re.fullmatch(r"[a-f0-9]{" + str(size) + "}", field)
            else None
        )
    result["mode"] = value.get("mode") if value.get("mode") in {"live", "stub"} else "unknown"
    result["transport"] = (
        value.get("transport") if value.get("transport") in {"direct", "brokered"} else "unknown"
    )
    names = value.get("model_names", [])
    if (
        not isinstance(names, list)
        or len(names) > 32
        or any(
            not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z0-9._:/-]{1,200}", name)
            for name in names
        )
    ):
        names = []
    result["model_names"] = sorted(set(names))
    return result


def api_profile(api_url, timeout):
    with (
        httpx.Client(trust_env=False, follow_redirects=False, timeout=timeout) as client,
        client.stream("GET", base_url(api_url) + "/api/runtime-status") as response,
    ):
        response.raise_for_status()
        body = bytearray()
        for chunk in response.iter_bytes():
            body.extend(chunk)
            if len(body) > MAX_RESPONSE_BYTES:
                raise ValueError("oversized API response")
    return RuntimeStatus.model_validate_json(body)


def validated_receipt(value, profile):
    if not isinstance(value, dict) or set(value) != set(ModelConnectionReceipt.__annotations__):
        raise ValueError("invalid receipt fields")
    receipt = TypeAdapter(ModelConnectionReceipt).validate_python(value, strict=True)
    if receipt["version"] != 1 or receipt["status"] != "passed" or receipt["mode"] != "live":
        raise ValueError("invalid connectivity receipt")
    for key in (
        "source_commit",
        "mode",
        "transport",
        "model_config_sha256",
        "broker_config_sha256",
    ):
        if receipt[key] != profile[key]:
            raise ValueError("profile mismatch")
    if profile["source_commit"] is None or profile["model_config_sha256"] is None:
        raise ValueError("missing identity")
    checked = datetime.fromisoformat(receipt["checked_at"])
    now = datetime.now(UTC)
    if checked.tzinfo is None or checked > now or (now - checked).total_seconds() > 3600:
        raise ValueError("invalid receipt time")
    return receipt


async def validate(args):
    checks = {}
    report = {
        "version": 1,
        "checked_at": datetime.now(UTC).isoformat(),
        "scope": "service_connectivity",
        "qualification": "not_checked",
        "checks": checks,
        "model_requested": args.model,
        "finding_submissions": 0,
        "recovery_actions": 0,
    }
    if args.offline:
        for name in (*CHECK_NAMES, "ui_api", "profile_consistency", "model_connectivity"):
            checks[name] = gate(
                "not_checked", "Offline validation does not contact services or models."
            )
        report["status"] = "not_checked"
        return report, None
    try:
        if args.managed_worker:
            runtime = await asyncio.to_thread(
                managed_check,
                "readiness",
                [
                    "--timeout",
                    str(args.timeout),
                    "--worker-hostname",
                    args.worker_hostname or "current",
                ],
                args.timeout * 4,
            )
        else:
            from infosec_harness.operations.readiness import check_runtime

            runtime = await check_runtime(
                timeout=args.timeout, worker_hostname=args.worker_hostname
            )
        profile = public_profile(runtime["profile"])
        report["profile"] = profile
        for name in CHECK_NAMES:
            checks[name] = gate(
                runtime["checks"][name]["status"],
                {
                    "database": "Configured database connection and migration head.",
                    "workflow_pollers": "Recent workflow pollers"
                    + (
                        " for the selected worker."
                        if args.managed_worker or args.worker_hostname
                        else "; worker identity not checked."
                    ),
                    "activity_pollers": "Recent activity pollers"
                    + (
                        " for the selected worker."
                        if args.managed_worker or args.worker_hostname
                        else "; worker identity not checked."
                    ),
                    "profile_identity": "Source, configuration hashes and resolved model names.",
                }[name],
            )
    except Exception:
        profile = public_profile({})
        report["profile"] = profile
        for name in CHECK_NAMES:
            checks[name] = gate("failed", "Configured worker validation could not be completed.")
    if checks["profile_identity"]["status"] == "passed" and not (
        profile["source_commit"]
        and profile["model_config_sha256"]
        and profile["model_names"]
        and profile["mode"] in {"live", "stub"}
        and profile["transport"] in {"direct", "brokered"}
        and (profile["transport"] != "brokered" or profile["broker_config_sha256"])
    ):
        checks["profile_identity"] = gate(
            "not_checked", "Source or configuration identity is unavailable."
        )
    try:
        await asyncio.to_thread(
            check_ui,
            args.api_url,
            args.web_url,
            timeout=args.timeout,
            expected_source_commit=args.expected_source_commit,
        )
        checks["ui_api"] = gate("passed", "Actual contracts, UI assets and same-origin API proxy.")
        api = await asyncio.to_thread(api_profile, args.api_url, args.timeout)
        consistent = (
            api.api_source_commit == profile["source_commit"]
            and profile["source_commit"] is not None
            and api.model_mode == profile["mode"]
            and api.assessment_transport == profile["transport"]
            and sorted(api.model_names) == profile["model_names"]
            and bool(profile["model_names"])
        )
        checks["profile_consistency"] = gate(
            "passed" if consistent else "failed",
            "API and checked worker source, model names, mode and transport must agree.",
        )
    except Exception:
        checks["ui_api"] = gate("failed", "UI/API deployment check could not be completed.")
        checks["profile_consistency"] = gate(
            "not_checked", "API/worker profile comparison is unavailable."
        )
    receipt = None
    checks["model_connectivity"] = gate("not_checked", "Inference was not requested.")
    if args.model:
        # A mismatch must never authorize a request against an unintended profile.
        if (
            checks["profile_identity"]["status"] != "passed"
            or checks["profile_consistency"]["status"] != "passed"
        ):
            checks["model_connectivity"] = gate(
                "not_checked", "Resolve profile identity and API/worker mismatch before inference."
            )
        else:
            try:
                if args.managed_worker:
                    model = await asyncio.to_thread(
                        managed_check,
                        "model-connectivity",
                        ["--model", "--timeout", str(args.model_timeout)],
                        args.model_timeout,
                    )
                else:
                    from infosec_harness.operations.model_connectivity import check_model

                    model = await check_model(timeout=args.model_timeout)
                state = model["status"]
                if state == "passed":
                    if type(model.get("requests")) is not int or model["requests"] != 1:
                        raise ValueError("invalid request count")
                    receipt = validated_receipt(model["receipt"], profile)
                checks["model_connectivity"] = gate(
                    state,
                    "One structured-output request to the configured verdict backend; brokered/stub or unsupported profiles remain not checked.",
                )
                report["model_requests"] = (
                    model.get("requests") if type(model.get("requests")) is int else None
                )
            except Exception:
                checks["model_connectivity"] = gate(
                    "failed",
                    "Explicit model connectivity check failed; provider error details are not published.",
                )
    selected = [v["status"] for k, v in checks.items() if k != "model_connectivity" or args.model]
    report["status"] = (
        "failed"
        if "failed" in selected
        else "not_checked"
        if "not_checked" in selected
        else "passed"
    )
    return report, receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    parser.add_argument("--web-url", default="http://127.0.0.1:8080")
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--model-timeout", type=float, default=90)
    parser.add_argument(
        "--model",
        action="store_true",
        help="Explicitly request one structured-output inference check.",
    )
    parser.add_argument(
        "--managed-worker",
        action="store_true",
        help="Read the running checkout-owned worker's actual configuration.",
    )
    parser.add_argument("--worker-hostname")
    parser.add_argument("--expected-source-commit")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--report", type=Path)
    parser.add_argument(
        "--connectivity-receipt",
        type=Path,
        help="Explicitly publish an exact-profile receipt after successful inference.",
    )
    args = parser.parse_args(argv)
    if not 1 <= args.timeout <= 60 or not 1 <= args.model_timeout <= 300:
        parser.error("timeouts must be 1..60 seconds and model timeout 1..300 seconds")
    if args.connectivity_receipt and not args.model:
        parser.error("--connectivity-receipt requires --model")
    if (
        args.report
        and args.connectivity_receipt
        and os.path.abspath(args.report) == os.path.abspath(args.connectivity_receipt)
    ):
        parser.error("report and connectivity receipt need distinct paths")
    destination = (
        args.report
        or ROOT / ".harness/reports/service-validation" / f"validation-{uuid4().hex}.json"
    )
    try:
        output_path(destination)
        if args.connectivity_receipt:
            output_path(args.connectivity_receipt)
        base_url(args.api_url)
        base_url(args.web_url)
    except (OSError, ValueError):
        parser.error("invalid validation endpoint or output path")
    report, receipt = asyncio.run(validate(args))
    report["report_file"] = str(destination)
    try:
        if args.connectivity_receipt and receipt is not None:
            private_json(args.connectivity_receipt, receipt)
    except (OSError, ValueError):
        report["checks"]["receipt_publication"] = gate(
            "failed", "Connectivity receipt could not be published safely."
        )
        report["status"] = "failed"
    try:
        private_json(destination, report)
    except (OSError, ValueError):
        report["checks"]["report_publication"] = gate(
            "failed", "Validation output could not be published safely."
        )
        report["status"] = "failed"
    print(json.dumps(report, sort_keys=True, allow_nan=False))
    return {"passed": 0, "failed": 1, "not_checked": 2}[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
