#!/usr/bin/env python3
"""Wait for the full stack and seed/verify the deterministic Temporal demonstration."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
import time
import uuid
from datetime import timedelta
from urllib import error, request

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from temporalio.client import Client, WorkflowExecutionStatus
from temporalio.service import RPCError

LABEL = "HARNESS ONBOARDING DEMO — STUB JUDGMENT"


def request_json(url: str, *, body: dict | None = None, timeout: float = 10) -> object:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    http_request = request.Request(
        url, data=data, headers=headers, method="POST" if data else "GET"
    )
    with request.urlopen(http_request, timeout=timeout) as response:
        return json.load(response)


def wait_url(url: str, label: str, *, timeout: int = 300) -> None:
    deadline = time.monotonic() + timeout
    last_error = "not attempted"
    while time.monotonic() < deadline:
        try:
            with request.urlopen(url, timeout=5) as response:
                if 200 <= response.status < 400:
                    print(f"readiness: {label} ready at {url}")
                    return
        except (OSError, error.URLError) as exc:
            last_error = str(exc)
        time.sleep(2)
    raise RuntimeError(f"{label} readiness timed out at {url}: {last_error}")


def check_s3(endpoint_url: str) -> None:
    access_key = os.environ.get("HARNESS_MINIO_ACCESS_KEY")
    secret_key = os.environ.get("HARNESS_MINIO_SECRET_KEY")
    if not access_key or not secret_key:
        raise RuntimeError("generated artifact-storage credentials are missing")
    client = boto3.client(
        "s3",
        endpoint_url=endpoint_url,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name="us-east-1",
        config=Config(s3={"addressing_style": "path"}),
    )
    bucket = f"harness-dev-{hashlib.sha256(access_key.encode()).hexdigest()[:16]}"
    try:
        client.head_bucket(Bucket=bucket)
        persisted = True
    except ClientError as exc:
        status = int(exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0))
        if status not in {404, 400}:
            raise
        client.create_bucket(Bucket=bucket)
        persisted = False

    sentinel_key = "bootstrap/persistence-sentinel.txt"
    if persisted:
        sentinel = client.get_object(Bucket=bucket, Key=sentinel_key)["Body"].read()
        if sentinel != b"harness-managed-runtime\n":
            raise RuntimeError("artifact-storage persistence sentinel has unexpected content")
    else:
        client.put_object(
            Bucket=bucket, Key=sentinel_key, Body=b"harness-managed-runtime\n"
        )

    key = f"bootstrap/roundtrip-{uuid.uuid4().hex}.txt"
    payload = b"harness-s3-roundtrip\n"
    client.put_object(Bucket=bucket, Key=key, Body=payload)
    observed = client.get_object(Bucket=bucket, Key=key)["Body"].read()
    client.delete_object(Bucket=bucket, Key=key)
    if observed != payload:
        raise RuntimeError("artifact-storage put/get returned different bytes")
    state = "preserved from an earlier run" if persisted else "created"
    print(f"artifact smoke: S3 put/get/delete passed; persistence sentinel {state}")


def prior_demo(api_url: str) -> str | None:
    batches = request_json(f"{api_url}/api/batches")
    if not isinstance(batches, list):
        return None
    for batch in batches:
        if batch.get("label") == LABEL and batch.get("status") == "complete":
            batch_id = str(batch["id"])
            detail = request_json(f"{api_url}/api/batches/{batch_id}")
            try:
                validate_completed_demo(api_url, batch_id, detail)
            except RuntimeError:
                continue
            return batch_id
    return None


def submit_demo(api_url: str) -> str:
    payload = {
        "mode": "temporal",
        "label": LABEL,
        "findings": [
            {
                "title": "Controlled SQL interpolation fixture (stub demonstration)",
                "repo_url": "/app/deploy/dev-runtime/fixture",
                "revision": "HEAD",
                "file_path": "app.py",
                "start_line": 5,
                "cwe": "CWE-89",
                "severity": "high",
            }
        ],
    }
    response = request_json(f"{api_url}/api/batches", body=payload, timeout=30)
    if not isinstance(response, dict) or not response.get("batch_id"):
        raise RuntimeError(f"API did not return a batch id: {response!r}")
    return str(response["batch_id"])


def validate_completed_demo(api_url: str, batch_id: str, batch: object) -> None:
    if not isinstance(batch, dict):
        raise RuntimeError(f"terminal demo batch has invalid detail: {batch!r}")
    operations = (batch.get("budget") or {}).get("operations") or []
    if not operations:
        raise RuntimeError("terminal demo batch has no root budget operations")
    runs = request_json(f"{api_url}/api/runs?batch_id={batch_id}")
    if not isinstance(runs, list) or len(runs) != 1:
        raise RuntimeError(f"terminal demo batch has unexpected run list: {runs!r}")
    run_status = runs[0].get("status")
    if run_status not in {"complete", "needs_info"}:
        raise RuntimeError(f"demo run ended in unexpected state {run_status!r}")
    detail = request_json(f"{api_url}/api/runs/{runs[0]['id']}")
    if not isinstance(detail, dict):
        raise RuntimeError(f"demo run detail has an invalid shape: {detail!r}")
    environment = ((detail.get("evidence") or {}).get("manifest") or {}).get(
        "environment"
    ) or {}
    if environment.get("status") != "ready":
        raise RuntimeError(
            "demo reached a terminal state without a ready sandbox environment: "
            f"{detail!r}"
        )
    executions = (detail.get("evidence") or {}).get("executions") or []
    if not executions:
        raise RuntimeError("demo completed without recorded sandbox probe execution")


def wait_batch(api_url: str, batch_id: str, *, timeout: int = 1200) -> None:
    deadline = time.monotonic() + timeout
    last: object = None
    while time.monotonic() < deadline:
        last = request_json(f"{api_url}/api/batches/{batch_id}")
        if isinstance(last, dict):
            status = last.get("status")
            if status == "complete":
                validate_completed_demo(api_url, batch_id, last)
                print(f"temporal smoke: batch {batch_id} completed and persisted one stub result")
                return
            if status in {"failed", "cancelled"}:
                raise RuntimeError(f"demo batch entered terminal failure state: {last!r}")
        time.sleep(3)
    raise RuntimeError(f"demo batch {batch_id} did not complete within {timeout}s; last={last!r}")


async def check_visibility(address: str, batch_id: str, *, timeout: float = 120) -> None:
    """Require the completed demo in the index used by Temporal UI, not only in history."""
    client = await asyncio.wait_for(Client.connect(address), timeout=10)
    deadline = time.monotonic() + timeout
    workflow_id = f"batch:{batch_id}"
    query = "WorkflowId = '" + workflow_id.replace("'", "''") + "'"
    last_error = "completed workflow not indexed"
    while time.monotonic() < deadline:
        try:
            async for workflow in client.list_workflows(
                query=query, limit=1, rpc_timeout=timedelta(seconds=10)
            ):
                if workflow.id == workflow_id and workflow.status == WorkflowExecutionStatus.COMPLETED:
                    print(f"temporal visibility: completed demo {workflow_id} is queryable")
                    return
        except RPCError as exc:
            last_error = str(exc)
        await asyncio.sleep(2)
    raise RuntimeError(f"Temporal visibility did not index {workflow_id}: {last_error}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--web-url", required=True)
    parser.add_argument("--minio-url", required=True)
    parser.add_argument("--temporal-address", required=True)
    args = parser.parse_args()
    try:
        wait_url(f"{args.api_url}/api/health", "API")
        wait_url(args.web_url, "web")
        wait_url(args.minio_url, "artifact storage")
        check_s3(args.minio_url.removesuffix("/minio/health/ready"))
        batch_id = prior_demo(args.api_url) or submit_demo(args.api_url)
        wait_batch(args.api_url, batch_id)
        asyncio.run(check_visibility(args.temporal_address, batch_id))
    except (
        RuntimeError,
        RPCError,
        OSError,
        error.URLError,
        json.JSONDecodeError,
        BotoCoreError,
        ClientError,
    ) as exc:
        print(f"full-stack smoke failed: {exc}", file=sys.stderr)
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
