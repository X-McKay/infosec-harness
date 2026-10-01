from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from pydantic_ai.messages import ModelResponse, TextPart
from test_broker_executor import request_fixture

from infosec_harness.inference.admission import ReservationPolicy
from infosec_harness.inference.auth import AUTH_HEADER, sign_request
from infosec_harness.inference.codec import encode_response
from infosec_harness.inference.controller import Controller
from infosec_harness.inference.ledger import StoredDisposition
from infosec_harness.inference.openshell import Lease, LeaseStore, NativeSpec, OpenShellAdapter
from infosec_harness.inference.policy import policy_digest
from infosec_harness.inference.protocol import (
    BrokerError,
    DispatchPermit,
    InferenceResult,
    canonical_bytes,
    digest,
)


def controller_fixture(tmp_path):
    request, settings = request_fixture()
    lease = Lease(
        "lease",
        "deployment",
        "run",
        request.contract,
        "v1",
        "ih-name",
        settings.ingress_key_hex,
        "ledger-token",
        native_id="native-id",
        status="ready",
    )
    events = []
    rows = {}

    async def get(identity):
        return rows.get(identity)

    async def admit(request, *, lease_id, allocation):
        events.append("admit")
        rows.setdefault(
            request.request_id, StoredDisposition(request, lease_id, "accepted", None, allocation)
        )
        return rows[request.request_id]

    async def claim(identity, *, lease_id):
        stored = rows[identity]
        if stored.state != "accepted":
            raise BrokerError("pending")
        rows[identity] = replace(stored, state="dispatch_intent")
        return DispatchPermit(request_id=identity, lease_id=lease_id, fence="fence")

    async def complete(result, *, permit):
        stored = rows[result.request_id]
        if stored.state != "dispatch_intent":
            raise BrokerError("completion_unknown")
        rows[result.request_id] = replace(stored, state="completed", result=result)
        return rows[result.request_id]

    async def recover(identity, *, lease_id):
        events.append("recover")
        stored = rows[identity]
        rows[identity] = replace(stored, state="completion_unknown")
        return rows[identity]

    async def ensure(run, contract):
        events.append("ensure")
        return lease

    async def verify(lease):
        events.append("verify")
        return {"native_id": "native-id"}

    async def revoke(lease):
        events.append("revoke")
        lease.status = "deleted"

    adapter = SimpleNamespace(
        leases={"lease": lease},
        deployment="deployment",
        lock=asyncio.Lock(),
        ensure=ensure,
        verify=verify,
        revoke=revoke,
        service_url=lambda lease: "https://gateway.test/s/ih-name/infer/v1/infer",
    )
    ledger = SimpleNamespace(get=get, admit=admit, claim=claim, complete=complete, recover=recover)
    policy = ReservationPolicy("verdict", "test", request.contract.digest, "config", 10000, 16, 0)
    core = Controller(
        adapter=adapter,
        policies={("verdict", request.contract.digest): policy},
        worker_key=b"a" * 32,
        ledger=ledger,
        clock=lambda: 100,
    )
    return core, request, lease, events, rows


@pytest.mark.asyncio
async def test_controller_worker_auth_precedes_native_provisioning(tmp_path):
    core, request, _, events, _ = controller_fixture(tmp_path)
    with pytest.raises(BrokerError, match="auth"):
        await core.handle("/v1/infer", canonical_bytes(request.model_dump(mode="json")), {})
    assert events == []


@pytest.mark.asyncio
async def test_saved_result_returned_without_reprovision_or_redispatch(tmp_path):
    core, request, lease, events, rows = controller_fixture(tmp_path)
    result = InferenceResult(
        request_id=request.request_id,
        response=encode_response(ModelResponse(parts=[TextPart("saved")], model_name="test-model")),
    )
    rows[request.request_id] = StoredDisposition(request, lease.lease_id, "completed", result, {})
    assert await core.infer(request) == result
    assert events == []


@pytest.mark.asyncio
async def test_mutated_duplicate_conflicts_before_native_or_send(tmp_path):
    core, request, lease, events, rows = controller_fixture(tmp_path)
    rows[request.request_id] = StoredDisposition(request, lease.lease_id, "accepted", None, {})
    changed = request.model_copy(
        update={"binding": request.binding.model_copy(update={"invocation_id": "other"})}
    )
    with pytest.raises(BrokerError, match="conflict"):
        await core.infer(changed)
    assert events == []


@pytest.mark.asyncio
async def test_lost_executor_ack_recovers_committed_result_without_resend(tmp_path):
    core, request, lease, events, rows = controller_fixture(tmp_path)
    result = InferenceResult(
        request_id=request.request_id,
        response=encode_response(ModelResponse(parts=[TextPart("saved")], model_name="test-model")),
    )

    class Channel:
        async def post(self, *_args, **_kwargs):
            events.append("send")
            rows[request.request_id] = replace(
                rows[request.request_id], state="completed", result=result
            )
            raise BrokerError("unavailable")

    core.channel = Channel()
    assert await core.infer(request) == result
    assert await core.infer(request) == result
    assert events.count("send") == 1
    assert "revoke" not in events


@pytest.mark.asyncio
async def test_ambiguous_executor_failure_revokes_fences_and_never_resends(tmp_path):
    core, request, lease, events, rows = controller_fixture(tmp_path)

    class Channel:
        async def post(self, *_args, **_kwargs):
            events.append("send")
            rows[request.request_id] = replace(rows[request.request_id], state="dispatch_intent")
            raise BrokerError("unavailable")

    core.channel = Channel()
    with pytest.raises(BrokerError, match="completion_unknown"):
        await core.infer(request)
    with pytest.raises(BrokerError, match="completion_unknown"):
        await core.infer(request)
    assert events.count("send") == 1
    assert events.index("revoke") < events.index("recover")
    assert rows[request.request_id].state == "completion_unknown"


@pytest.mark.asyncio
async def test_ledger_claim_rejects_same_request_id_with_altered_full_payload(tmp_path):
    core, request, lease, events, rows = controller_fixture(tmp_path)
    rows[request.request_id] = StoredDisposition(request, lease.lease_id, "accepted", None, {})
    changed = request.model_copy(
        update={"binding": request.binding.model_copy(update={"invocation_id": "different"})}
    )
    body = canonical_bytes({"request": changed.model_dump(mode="json"), "lease_id": lease.lease_id})
    with pytest.raises(BrokerError, match="identity"):
        await core.handle("/v1/ledger/claim", body, {"Authorization": "Bearer ledger-token"})
    assert rows[request.request_id].state == "accepted"
    assert events == []


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/v1/ledger/claim", "/v1/ledger/complete", "/admin"])
async def test_worker_key_cannot_claim_ledger_or_invoke_admin(tmp_path, path):
    core, _, _, events, _ = controller_fixture(tmp_path)
    with pytest.raises(BrokerError):
        await core.handle(
            path, b"{}", {AUTH_HEADER: sign_request(b"a" * 32, "POST", "/v1/infer", b"{}", 130)}
        )
    assert events == []


def native_fixture(tmp_path):
    request, _ = request_fixture()
    policy = {
        "version": 1,
        "landlock": {"compatibility": "hard_requirement"},
        "network_policies": {},
    }
    contract = request.contract.model_copy(update={"policy_digest": policy_digest(policy)})
    provider_profile = {"id": "provider-profile", "resource_version": 1}
    ledger_profile = {"id": "ledger-profile", "resource_version": 1}
    spec = NativeSpec(
        policy,
        "https://controller.test",
        "ledger-profile",
        "provider-profile",
        "MOCK_TOKEN",
        "v1",
        10000,
        16,
        1,
        digest(provider_profile),
        digest(ledger_profile),
        "provider-observed-id",
    )
    lease = Lease(
        "12345678-1234-1234-1234-123456789abc",
        "deployment",
        "run",
        contract,
        "v1",
        "owned",
        "12" * 32,
        "native-ledger-key",
        native_id="observed-id",
        status="ready",
        ledger_native_id="ledger-observed-id",
    )
    detail = {
        "id": lease.native_id,
        "labels": lease.labels(),
        "phase": "Ready",
        "policy_source": "sandbox",
        "policy": policy,
        "configuration_admission": {"state": "accepted"},
    }
    host = {
        "Runtime": "runc",
        "NetworkMode": "none",
        "Privileged": False,
        "CapDrop": ["ALL"],
        "SecurityOpt": ["no-new-privileges:true"],
    }
    workload = {
        "Image": contract.executor_image,
        "State": {"Running": True},
        "HostConfig": host,
        "Mounts": [],
        "Config": {"User": "65532:65532", "Labels": {"openshell.ai/isolation-role": "sandbox"}},
    }
    supervisor = {
        "Image": contract.supervisor_image,
        "State": {"Running": True},
        "Config": {"Labels": {"openshell.ai/isolation-role": "supervisor"}},
    }
    calls = []

    class CLI:
        gateway = "https://gateway.test"
        workspace = "default"
        service_domain = "openshell.localhost"

        async def run(self, args, **kwargs):
            calls.append((args, kwargs))
            if args[:2] == ["service", "list"]:
                return json.dumps(
                    {
                        "next_page_token": "",
                        "services": [
                            {
                                "sandbox": lease.name,
                                "service": "infer",
                                "target_port": 8765,
                                "url": f"https://default--{lease.name}--infer.openshell.localhost:443/",
                                "workspace": "default",
                            }
                        ],
                    }
                )
            if args[:2] == ["sandbox", "get"]:
                return json.dumps(detail)
            if args[:3] == ["sandbox", "provider", "list"]:
                return json.dumps(
                    {
                        "providers": [
                            {"name": contract.provider_binding, "type": "provider-profile"},
                            {"name": f"ih-ledger-{lease.lease_id}", "type": "ledger-profile"},
                        ],
                        "next_page_token": "",
                    }
                )
            if args[:3] == ["provider", "profile", "export"]:
                return json.dumps(
                    provider_profile if args[3] == "provider-profile" else ledger_profile
                )
            if args[:2] == ["provider", "list"]:
                return json.dumps(
                    {
                        "providers": [
                            {
                                "name": contract.provider_binding,
                                "id": "provider-observed-id",
                                "type": "provider-profile",
                                "workspace": "default",
                                "resource_version": 1,
                            },
                            {
                                "name": "ih-ledger-" + lease.lease_id,
                                "id": lease.ledger_native_id,
                                "type": "ledger-profile",
                                "workspace": "default",
                                "resource_version": 1,
                                "credential_keys": ["IH_LEDGER_TOKEN"],
                            },
                        ],
                        "next_page_token": "",
                    }
                )
            if args[:2] == ["sandbox", "exec"]:
                return json.dumps({"uid": 65532, "nnp": "1", "seccomp": "2"})
            raise AssertionError(args)

        async def containers(self, _identity):
            return [workload, supervisor]

    store = LeaseStore(tmp_path / "leases")
    store.save(lease)
    adapter = OpenShellAdapter(
        CLI(), store=store, deployment="deployment", specs={contract.digest: spec}
    )
    return adapter, adapter.leases[lease.lease_id], detail, workload, supervisor, calls


@pytest.mark.asyncio
async def test_native_readiness_requires_live_policy_images_and_process_proof(tmp_path):
    adapter, lease, _, _, _, calls = native_fixture(tmp_path)
    proof = await adapter.verify(lease)
    assert proof["executor_image"] == lease.contract.executor_image
    assert any(args[:2] == ["sandbox", "exec"] for args, _ in calls)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault",
    [
        "not_ready",
        "global_policy",
        "broader_policy",
        "missing_admission",
        "wrong_executor_image",
        "wrong_supervisor_image",
        "privileged",
        "host_bind",
        "daemon_socket",
        "wrong_runtime",
        "wrong_uid",
    ],
)
async def test_native_mismatch_is_fail_closed(tmp_path, fault):
    adapter, lease, detail, workload, supervisor, _ = native_fixture(tmp_path)
    if fault == "not_ready":
        detail["phase"] = "Error"
    if fault == "global_policy":
        detail["policy_source"] = "global"
    if fault == "broader_policy":
        detail["policy"] = {"broader": True}
    if fault == "missing_admission":
        detail["configuration_admission"] = {}
    if fault == "wrong_executor_image":
        workload["Image"] = "sha256:" + "f" * 64
    if fault == "wrong_supervisor_image":
        supervisor["Image"] = "sha256:" + "f" * 64
    if fault == "privileged":
        workload["HostConfig"]["Privileged"] = True
    if fault == "host_bind":
        workload["Mounts"] = [{"Type": "bind", "Destination": "/host"}]
    if fault == "daemon_socket":
        workload["Mounts"] = [{"Type": "volume", "Destination": "/docker.sock"}]
    if fault == "wrong_runtime":
        workload["HostConfig"]["Runtime"] = "runsc"
    if fault == "wrong_uid":
        workload["Config"]["User"] = "0:0"
    with pytest.raises(BrokerError):
        await adapter.verify(lease)


@pytest.mark.asyncio
async def test_foreign_lease_cannot_be_revoked(tmp_path):
    adapter, lease, _, _, _, calls = native_fixture(tmp_path)
    foreign = replace(lease, deployment="foreign")
    with pytest.raises(BrokerError, match="identity"):
        await adapter.revoke(foreign)
    assert calls == []


def test_private_lease_store_roundtrip_and_no_public_secret_repr(tmp_path):
    adapter, lease, *_ = native_fixture(tmp_path)
    assert lease.ingress_key_hex not in repr(lease)
    assert lease.ledger_key not in repr(lease)
    path = adapter.store.directory / f"{lease.lease_id}.json"
    assert path.stat().st_mode & 0o777 == 0o600
    path.chmod(0o644)
    with pytest.raises(BrokerError):
        adapter.store.load()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "state",
    [
        "completed",
        "accepted",
        "dispatch_intent",
        "completion_unknown",
        "failed_before_dispatch",
        "absent",
    ],
)
async def test_read_only_results_after_expiry_never_provision_admit_or_dispatch(tmp_path, state):
    core, request, lease, events, rows = controller_fixture(tmp_path)
    request = request.model_copy(
        update={"binding": request.binding.model_copy(update={"expires_at": 99})}
    )
    result = InferenceResult(
        request_id=request.request_id,
        response=encode_response(ModelResponse(parts=[TextPart("saved")], model_name="test-model")),
    )
    if state != "absent":
        rows[request.request_id] = StoredDisposition(
            request, lease.lease_id, state, result if state == "completed" else None, {}
        )
    body = canonical_bytes(request.model_dump(mode="json"))
    headers = {AUTH_HEADER: sign_request(b"a" * 32, "POST", "/v1/results", body, 130)}
    if state == "completed":
        assert await core.handle("/v1/results", body, headers) == result.model_dump(mode="json")
    else:
        with pytest.raises(BrokerError) as exc:
            await core.handle("/v1/results", body, headers)
        assert (
            exc.value.code
            == {
                "accepted": "pending",
                "dispatch_intent": "pending",
                "completion_unknown": "completion_unknown",
                "failed_before_dispatch": "expired",
                "absent": "identity",
            }[state]
        )
    assert events == []


@pytest.mark.asyncio
async def test_run_close_authenticates_owner_then_fences_before_native_cleanup(tmp_path):
    core, request, lease, events, rows = controller_fixture(tmp_path)
    store = LeaseStore(tmp_path / "closure")
    core.adapter.store = store

    async def owner(run_id, root_id):
        if (run_id, root_id) != ("run", "root"):
            raise BrokerError("identity")
        events.append("owner")

    async def fence(run_id):
        assert store.is_run_revoked(run_id)
        events.append("fence")

    core.ledger.validate_run_owner = owner
    core.ledger.revoke_run = fence
    body = canonical_bytes({"run_id": "run", "root_id": "root"})
    headers = {AUTH_HEADER: sign_request(b"a" * 32, "POST", "/v1/runs/close", body, 130)}
    assert await core.handle("/v1/runs/close", body, headers) == {
        "run_id": "run",
        "state": "closed",
    }
    assert events == ["owner", "fence", "revoke"]
    assert LeaseStore(store.directory).is_run_revoked("run")
    events.clear()
    await core.handle("/v1/runs/close", body, headers)
    assert events == ["owner", "fence"]


@pytest.mark.asyncio
async def test_foreign_run_close_has_no_fence_or_native_mutation(tmp_path):
    core, _, _, events, _ = controller_fixture(tmp_path)
    core.adapter.store = LeaseStore(tmp_path / "closure")

    async def reject(*args):
        raise BrokerError("identity")

    core.ledger.validate_run_owner = reject
    body = canonical_bytes({"run_id": "foreign", "root_id": "root"})
    with pytest.raises(BrokerError, match="identity"):
        await core.handle(
            "/v1/runs/close",
            body,
            {AUTH_HEADER: sign_request(b"a" * 32, "POST", "/v1/runs/close", body, 130)},
        )
    assert events == []
    assert not core.adapter.store.is_run_revoked("foreign")


@pytest.mark.asyncio
async def test_persistent_closed_run_cannot_reprovision_after_controller_restart(tmp_path):
    adapter, lease, _, _, _, calls = native_fixture(tmp_path)
    adapter.store.revoke_run(lease.run_id)
    adapter = OpenShellAdapter(
        adapter.cli,
        store=LeaseStore(adapter.store.directory),
        deployment=adapter.deployment,
        specs=adapter.specs,
    )
    with pytest.raises(BrokerError, match="identity"):
        await adapter.ensure(lease.run_id, lease.contract)
    assert calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["detach", "delete", "provider"])
async def test_partial_owned_cleanup_is_retryable_without_early_deleted_ack(tmp_path, failure):
    adapter, lease, _, _, _, _ = native_fixture(tmp_path)
    lease.ledger_native_id = "scoped-provider-id"
    state = {"sandbox": True, "attached": True, "provider": True, "failed": False}
    actions = []

    async def run(args, **kwargs):
        if args[:2] == ["sandbox", "list"]:
            return json.dumps(
                {
                    "next_page_token": "",
                    "sandboxes": (
                        [{"id": lease.native_id, "name": lease.name, "labels": lease.labels()}]
                        if state["sandbox"]
                        else []
                    ),
                }
            )
        if args[:3] == ["sandbox", "provider", "list"]:
            return json.dumps(
                {
                    "next_page_token": "",
                    "providers": (
                        [{"name": lease.contract.provider_binding}] if state["attached"] else []
                    ),
                }
            )
        if args[:2] == ["provider", "list"]:
            return json.dumps(
                {
                    "next_page_token": "",
                    "providers": (
                        [
                            {
                                "name": "ih-ledger-" + lease.lease_id,
                                "id": lease.ledger_native_id,
                                "type": "ledger-profile",
                                "workspace": "default",
                                "credential_keys": ["IH_LEDGER_TOKEN"],
                            }
                        ]
                        if state["provider"]
                        else []
                    ),
                }
            )
        action = (
            "detach"
            if args[:3] == ["sandbox", "provider", "detach"]
            else "delete"
            if args[:2] == ["sandbox", "delete"]
            else "provider"
        )
        actions.append(action)
        if action == failure and not state["failed"]:
            state["failed"] = True
            raise BrokerError("unavailable")
        state[{"detach": "attached", "delete": "sandbox", "provider": "provider"}[action]] = False
        return ""

    async def containers(identity):
        assert identity == lease.native_id
        return ["running"] if state["sandbox"] else []

    adapter.cli.run, adapter.cli.containers = run, containers
    lease.status = "quarantined"
    with pytest.raises(BrokerError, match="unavailable"):
        await adapter.revoke(lease)
    assert lease.status != "deleted"
    assert adapter.store.load()[0].status != "deleted"
    await adapter.revoke(lease)
    assert lease.status == "deleted"
    assert not state["sandbox"] and not state["provider"]
    assert actions.count(failure) == 2
    assert adapter.store.load()[0].status == "deleted"


@pytest.mark.asyncio
async def test_cleanup_without_corroborated_provider_id_requires_manual_reconciliation(tmp_path):
    adapter, lease, _, _, _, calls = native_fixture(tmp_path)

    async def run(args, **kwargs):
        calls.append((args, kwargs))
        if args[:2] == ["sandbox", "list"]:
            return json.dumps({"sandboxes": [], "next_page_token": ""})
        if args[:2] == ["provider", "list"]:
            return json.dumps(
                {
                    "providers": [
                        {
                            "name": "ih-ledger-" + lease.lease_id,
                            "id": "uncorroborated",
                            "type": "ledger-profile",
                            "workspace": "default",
                            "credential_keys": ["IH_LEDGER_TOKEN"],
                        }
                    ],
                    "next_page_token": "",
                }
            )
        raise AssertionError("No deletion may be authorized by a provider name alone")

    async def empty(identity):
        return []

    adapter.cli.run, adapter.cli.containers = run, empty
    lease.ledger_native_id = ""
    with pytest.raises(BrokerError, match="identity"):
        await adapter.revoke(lease)
    assert lease.status == "sandbox_deleted"
    assert not any(args[:2] == ["provider", "delete"] for args, _ in calls)


@pytest.mark.asyncio
async def test_close_during_preflight_cannot_publish_or_create_an_executor(tmp_path):
    adapter, lease, _, _, _, calls = native_fixture(tmp_path)
    adapter.leases.clear()
    entered, resume = asyncio.Event(), asyncio.Event()

    async def preflight():
        entered.set()
        await resume.wait()

    async def version(args, **kwargs):
        assert args == ["--version"]
        return "openshell 0.1.2"

    async def fence(run):
        assert adapter.store.is_run_revoked(run)

    adapter.cli.preflight, adapter.cli.run = preflight, version
    core = Controller(
        adapter=adapter, policies={}, worker_key=b"a" * 32, ledger=SimpleNamespace(revoke_run=fence)
    )
    create = asyncio.create_task(adapter.ensure(lease.run_id, lease.contract))
    await entered.wait()
    close = asyncio.create_task(core.revoke_run(lease.run_id))
    await asyncio.sleep(0)
    assert adapter.store.is_run_revoked(lease.run_id)
    assert not close.done()
    resume.set()
    with pytest.raises(BrokerError, match="identity"):
        await create
    await close
    assert adapter.leases == {} and calls == []
