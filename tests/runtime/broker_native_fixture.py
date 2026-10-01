"""Mock-only native acceptance fixture using the production controller and ledger.

An operator supplies reviewed native deployment/contract JSON and test CA files.
Only three static, bounded mock invocations are registered; no arbitrary root issuance.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import time
from pathlib import Path

from pydantic_ai import Agent
from sqlalchemy import select

from infosec_harness.inference import admission
from infosec_harness.inference.auth import AUTH_HEADER, sign_request
from infosec_harness.inference.controller import Controller
from infosec_harness.inference.http_service import JsonChannel
from infosec_harness.inference.openshell import NativeDeploymentConfig
from infosec_harness.inference.protocol import (
    BrokerError,
    ExecutorContract,
    InvocationRequest,
    ReservationBinding,
    canonical_bytes,
)
from infosec_harness.inference.transport import BrokerModel
from infosec_harness.persistence import budgets, db

CONFIGURATION = "native-fixture-config"
AGENT = "context"
WORKER_KEY = b"native-test-only-worker-key-000000000000"


def configuration():
    value = json.loads(Path(os.environ["IH_NATIVE_FIXTURE_CONFIG"]).read_text())
    contract = ExecutorContract.model_validate(value["contract"])
    if (
        contract.backend != "mock"
        or contract.model != "g0-fixture-model"
        or contract.endpoint != "https://192.168.5.15:18443/v1"
        or contract.provider_binding != "ih-g0-canary"
    ):
        raise BrokerError("policy", "Fixture accepts only its private mock provider")
    if value.get("fixture", "frozen") not in {"frozen", "temporal", "temporal-rerun"}:
        raise BrokerError("identity")
    return value


def reference(value=None):
    value = configuration() if value is None else value
    selector = value.get("fixture", "frozen")
    return InvocationRequest(
        mode="temporal" if selector.startswith("temporal") else "local",
        root_id=f"native-fixture-{selector}-root",
        run_id=f"native-fixture-{selector}-run",
        invocation_id="native-fixture-invocation",
        operation_id="native-fixture-operation",
        agent=AGENT,
        configuration_digest=CONFIGURATION,
        contract=ExecutorContract.model_validate(value["contract"]),
    )


def controller_factory():
    value = configuration()
    native = NativeDeploymentConfig.model_validate(value["native"])
    expected = reference(value)
    contract = expected.contract
    adapter = native.build()
    policy = admission.ReservationPolicy(
        AGENT,
        contract.profile,
        contract.digest,
        CONFIGURATION,
        10000,
        32,
        0,
        input_per_mtok=0,
        output_per_mtok=0,
    )

    async def issue(request):
        if request != expected:
            raise BrokerError("identity")
        await db.create_all()
        async with db.session() as session:
            root = await session.get(db.BudgetLedger, expected.root_id)
            if root is not None:
                existing = (
                    root.state.get("operations", {})
                    .get(expected.operation_id, {})
                    .get("broker_binding")
                )
                if existing:
                    return ReservationBinding.model_validate(existing)
            else:
                state = budgets.initial_state(
                    {"requests": 4, "tokens": 40000, "cost_usd": 0}, elapsed_seconds=600
                )
                state["agent_config_digests"] = {AGENT: CONFIGURATION}
                state["broker_run_id"] = expected.run_id
                session.add(db.BudgetLedger(root_id=expected.root_id, state=state))
                await session.commit()
        await budgets.reserve(
            expected.root_id,
            expected.operation_id,
            {"requests": 4, "tokens": 40000, "cost_usd": 0},
            AGENT,
            CONFIGURATION,
            run_id=expected.run_id,
            invocation_id=expected.invocation_id,
        )
        binding = ReservationBinding(
            root_id=expected.root_id,
            run_id=expected.run_id,
            invocation_id=expected.invocation_id,
            operation_id=expected.operation_id,
            agent=AGENT,
            contract_digest=contract.digest,
            expires_at=time.time() + 300,
        )
        await admission.bind_reservation(binding, configuration_digest=CONFIGURATION)
        return binding

    core = Controller(
        adapter=adapter,
        policies={(AGENT, contract.digest): policy},
        worker_key=WORKER_KEY,
        issue_invocation=issue,
        executor_channel=JsonChannel(
            ca_file=str(native.gateway_ca),
            cert=(str(native.gateway_client_certificate), str(native.gateway_client_key)),
            gateway_origin=native.gateway,
            service_domain=native.service_domain,
        ),
    )
    if expected.mode == "temporal":
        # Test-only ACK fault: the production core has already read its committed ledger.
        original = core.handle
        directory = Path(os.environ["IH_NATIVE_FIXTURE_CONFIG"]).parent
        marker, release = (
            directory / "p4-native-d-committed.json",
            directory / "p4-native-d-release",
        )

        async def delayed(path, body, headers):
            response = await original(path, body, headers)
            if path == "/v1/infer":
                try:
                    fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                except FileExistsError:
                    return response
                with os.fdopen(fd, "wb") as output:
                    output.write(
                        canonical_bytes(
                            {"request_id": response["request_id"], "state": "completed"}
                        )
                    )
                    output.flush()
                    os.fsync(output.fileno())
                deadline = time.monotonic() + 60
                while not release.exists() and time.monotonic() < deadline:
                    await asyncio.sleep(0.05)
            return response

        core.handle = delayed
    return core


async def post(channel, origin, path, body):
    return await channel.post(
        origin + path,
        body,
        {AUTH_HEADER: sign_request(WORKER_KEY, "POST", path, body, int(time.time()) + 30)},
    )


async def issue_binding():
    value = configuration()
    channel = JsonChannel(ca_file=value["controller_ca"])
    body = canonical_bytes(reference(value).model_dump(mode="json"))
    return ReservationBinding.model_validate(
        await post(channel, value["controller_origin"], "/v1/invocations", body)
    )


async def worker():
    value = configuration()
    binding = await issue_binding()
    os.environ["IH_NATIVE_WORKER_KEY"] = WORKER_KEY.decode()
    model = BrokerModel(
        contract=reference(value).contract,
        binding=binding,
        controller_url=value["controller_origin"],
        secret_env="IH_NATIVE_WORKER_KEY",
        ca_file=value["controller_ca"],
        client_cert=None,
        client_key=None,
        request_identity=lambda: "native-fixture-step",
    )
    result = await Agent(model=model, output_type=str, model_settings={"max_tokens": 32}).run(
        "native fixture"
    )
    assert result.output == "g0-fixture-response"
    print("NATIVE_PRODUCTION_WORKER_AGENT_OK")


async def prove():
    value, expected = configuration(), reference()
    channel, origin = JsonChannel(ca_file=value["controller_ca"]), value["controller_origin"]
    directory = Path(os.environ["IH_NATIVE_FIXTURE_CONFIG"]).parent
    before = json.loads((directory / "p4-mock-stats.json").read_text())
    async with db.session() as session:
        rows = list((await session.scalars(select(db.InferenceRequestRecord))).all())
        rows = [
            row
            for row in rows
            if row.state == "completed" and row.request["binding"]["root_id"] == expected.root_id
        ]
        assert len(rows) == 1
        row = rows[0]
        request = row.request
    body = canonical_bytes(request)
    try:
        await channel.post(
            origin + "/v1/infer", body, {AUTH_HEADER: f"v1:{int(time.time()) + 30}:" + "0" * 64}
        )
    except BrokerError as error:
        assert error.code == "auth"
    else:
        raise AssertionError("Unsigned ingress accepted")
    claim = canonical_bytes({"request": request, "lease_id": row.lease_id})
    try:
        await channel.post(
            origin + "/v1/ledger/claim", claim, {"Authorization": "Bearer " + WORKER_KEY.decode()}
        )
    except BrokerError as error:
        assert error.code == "auth"
    else:
        raise AssertionError("Worker key accepted on executor ledger channel")
    result = await post(channel, origin, "/v1/results", body)
    assert (
        result["request_id"] == row.request_id
        and result["usage"]["input_tokens"] == 3
        and result["usage"]["output_tokens"] == 2
    )
    close = canonical_bytes({"run_id": expected.run_id, "root_id": expected.root_id})
    assert (await post(channel, origin, "/v1/runs/close", close))["state"] == "closed"
    assert await post(channel, origin, "/v1/results", body) == result
    assert (await post(channel, origin, "/v1/runs/close", close))["state"] == "closed"
    assert json.loads((directory / "p4-mock-stats.json").read_text()) == before
    proof = {
        "fixture": value.get("fixture", "frozen"),
        "completed": True,
        "request": request,
        "result": result,
        "worker_auth_denied": True,
        "worker_ledger_auth_denied": True,
        "closed": True,
        "saved_after_close": True,
        "provider_counts": before,
    }
    (directory / f"p4-{value.get('fixture', 'frozen')}-proof.json").write_text(
        json.dumps(proof, sort_keys=True)
    )
    print("NATIVE_AUTH_COMMIT_CLOSE_SAVED_RESULT_OK")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("worker", "prove"))
    args = parser.parse_args()
    asyncio.run(worker() if args.mode == "worker" else prove())
