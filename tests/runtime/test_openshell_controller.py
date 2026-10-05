from __future__ import annotations

import asyncio
import json
from contextlib import suppress
from dataclasses import replace
from types import SimpleNamespace

import pytest
from pydantic_ai.messages import ModelResponse, TextPart
from test_broker_executor import request_fixture

from infosec_harness.inference.catalog.policy import policy_digest
from infosec_harness.inference.controller.admission import ReservationPolicy
from infosec_harness.inference.controller.ledger import StoredDisposition
from infosec_harness.inference.controller.service import Controller
from infosec_harness.inference.native.openshell import (
    Lease,
    LeaseStore,
    NativeSpec,
    OpenShellAdapter,
    OwnedLeases,
)
from infosec_harness.inference.wire.auth import AUTH_HEADER, sign_request
from infosec_harness.inference.wire.codec import encode_response
from infosec_harness.inference.wire.protocol import (
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
        if stored.state == "dispatch_intent":
            rows[identity] = replace(stored, state="completion_unknown")
        return rows[identity]

    async def fail_before_dispatch(identity, *, lease_id):
        events.append("fail_before_dispatch")
        stored = rows[identity]
        if stored.state == "dispatch_intent":
            raise BrokerError("completion_unknown")
        if stored.state == "accepted":
            rows[identity] = replace(stored, state="failed_before_dispatch")
        return rows[identity]

    async def ensure(run, contract):
        events.append("ensure")
        return lease

    async def verify(lease):
        events.append("verify")
        return {"native_id": lease.native_id, "policy_digest": lease.contract.policy_digest,
                "executor_image": lease.contract.executor_image,
                "supervisor_image": lease.contract.supervisor_image,
                "profile": lease.contract.profile, "credential_revision": lease.credential_revision}

    async def revoke(lease):
        events.append("revoke")
        lease.status = "deleted"

    class Adapter(OwnedLeases):
        deployment = "deployment"

        def __init__(self):
            self.leases = {"lease": lease}
            self.lock = asyncio.Lock()
            self.store = LeaseStore(tmp_path / "fixture-leases")
            self.ensure, self.verify, self.revoke = ensure, verify, revoke

        def service_url(self, _lease):
            return "https://gateway.test/s/ih-name/infer/v1/infer"

    adapter = Adapter()
    ledger = SimpleNamespace(get=get, admit=admit, claim=claim, complete=complete, recover=recover,
                             fail_before_dispatch=fail_before_dispatch)
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
    # Durable fencing must precede potentially slow native cleanup.
    assert events.index("recover") < events.index("revoke")
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
        ledger_profile="ledger-profile",
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
    attached = [
        {"name": contract.provider_binding, "type": "provider-profile", "id": "provider-observed-id"},
        {"name": f"ih-ledger-{lease.lease_id}", "type": "ledger-profile", "id": "ledger-observed-id"},
    ]
    providers = [
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
    ]

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
                        "providers": attached,
                        "next_page_token": "",
                    }
                )
            if args[:3] == ["provider", "profile", "export"]:
                return json.dumps(
                    provider_profile if args[3] == "provider-profile" else ledger_profile
                )
            if args[:2] == ["provider", "list"]:
                return json.dumps({"providers": providers, "next_page_token": ""})
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
    adapter.fixture = SimpleNamespace(attached=attached, providers=providers)
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
@pytest.mark.parametrize("fault", ["provider_id", "ledger_id", "missing_id", "extra", "duplicate"])
async def test_attachment_is_verified_by_native_id_not_name(tmp_path, fault):
    """A provider attached under the expected name and type but another identity is unverified."""
    adapter, lease, *_ = native_fixture(tmp_path)
    attached = adapter.fixture.attached
    if fault == "provider_id":
        attached[0]["id"] = "foreign-provider-id"
    if fault == "ledger_id":
        attached[1]["id"] = "foreign-ledger-id"
    if fault == "missing_id":
        del attached[0]["id"]
    if fault == "extra":
        attached.append({"name": "other", "type": "provider-profile", "id": "other-id"})
    if fault == "duplicate":
        attached.append(dict(attached[0]))
    with pytest.raises(BrokerError, match="policy"):
        await adapter.verify(lease)


@pytest.mark.asyncio
@pytest.mark.parametrize("index,category", [(0, "provider_identity"), (1, "ledger_provider_identity")])
async def test_duplicate_provider_name_is_ambiguous_even_when_one_record_matches(
        tmp_path, caplog, index, category):
    """The first matching name must never be selected from a duplicated inventory."""
    adapter, lease, *_ = native_fixture(tmp_path)
    providers = adapter.fixture.providers
    providers.append({**providers[index], "id": "shadow-id"})
    with pytest.raises(BrokerError, match="identity"):
        await adapter.verify(lease)
    assert f"IH_NATIVE_IDENTITY_FAILURE boundary=native_verify category={category}" in caplog.text


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

    async def fence(run_id, *, root_id):
        assert store.is_run_revoked(run_id) and root_id == "root"
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


def owned_cleanup_fixture(tmp_path, failure):
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
        if action == "detach":
            assert kwargs["timeout"] == 30.0
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
    return adapter, lease, state, actions


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["delete", "provider"])
async def test_partial_owned_cleanup_is_retryable_without_early_deleted_ack(tmp_path, failure):
    adapter, lease, state, actions = owned_cleanup_fixture(tmp_path, failure)
    with pytest.raises(BrokerError, match="unavailable"):
        await adapter.revoke(lease)
    assert lease.status != "deleted"
    assert adapter.store.load()[0].status != "deleted"
    await adapter.revoke(lease)
    assert actions.count(failure) == 2
    assert lease.status == "deleted"
    assert not state["sandbox"] and not state["provider"]
    # A deleted lease's secret record is retired to a secret-free archive entry.
    assert adapter.store.load() == [] and adapter.is_deleted(lease.lease_id)
    archived = (adapter.store.archive / f"{lease.lease_id}.json").read_text()
    assert lease.ledger_key not in archived and lease.ingress_key_hex not in archived
    await adapter.revoke(lease)  # Idempotent after retirement.
    assert actions.count(failure) == 2


async def test_detach_timeout_destroys_owned_sandbox_and_verifies_final_absence(tmp_path, caplog):
    adapter, lease, state, actions = owned_cleanup_fixture(tmp_path, "detach")
    await adapter.revoke(lease)
    assert actions == ["detach", "delete", "provider"]
    assert "IH_NATIVE_CLEANUP_FAILURE stage=provider_detach category=unavailable action=destroy_owned_sandbox" in caplog.text
    assert lease.status == "deleted" and adapter.store.load() == []
    assert not state["sandbox"] and not state["provider"]



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

    async def fence(run, *, root_id):
        assert adapter.store.is_run_revoked(run)

    adapter.cli.preflight, adapter.cli.run = preflight, version
    core = Controller(
        adapter=adapter, policies={}, worker_key=b"a" * 32, ledger=SimpleNamespace(revoke_run=fence)
    )
    create = asyncio.create_task(adapter.ensure(lease.run_id, lease.contract))
    await entered.wait()
    close = asyncio.create_task(core.revoke_run(lease.run_id, "root"))
    await asyncio.sleep(0)
    assert adapter.store.is_run_revoked(lease.run_id)
    assert not close.done()
    resume.set()
    with pytest.raises(BrokerError, match="identity"):
        await create
    await close
    assert adapter.leases == {} and calls == []


async def test_controller_wall_timeout_fences_claimed_request_without_redispatch(tmp_path, monkeypatch):
    from infosec_harness.inference.controller import service as module

    core, request, lease, events, rows = controller_fixture(tmp_path)
    async def interrupted(_):
        await core.ledger.admit(request, lease_id=lease.lease_id, allocation={})
        await core.ledger.claim(request.request_id, lease_id=lease.lease_id)
        await asyncio.sleep(1)
        raise AssertionError("Controller wall deadline must cancel this work")
    monkeypatch.setattr(module, "CONTROLLER_TIMEOUT_S", 0.02)
    monkeypatch.setattr(core, "_infer", interrupted)
    with pytest.raises(BrokerError, match="completion_unknown"):
        await core.infer(request)
    assert rows[request.request_id].state == "completion_unknown"
    assert lease.status == "deleted"
    assert events.count("revoke") == events.count("recover") == 1


async def test_controller_cancellation_retains_unknown_and_revokes_owner(tmp_path, monkeypatch):
    core, request, lease, events, rows = controller_fixture(tmp_path)
    claimed = asyncio.Event()
    async def interrupted(_):
        await core.ledger.admit(request, lease_id=lease.lease_id, allocation={})
        await core.ledger.claim(request.request_id, lease_id=lease.lease_id)
        claimed.set()
        await asyncio.sleep(1)
    monkeypatch.setattr(core, "_infer", interrupted)
    task = asyncio.create_task(core.infer(request))
    await claimed.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert rows[request.request_id].state == "completion_unknown"
    assert lease.status == "deleted"
    assert events.count("revoke") == events.count("recover") == 1


@pytest.mark.parametrize("cancel", [False, True])
async def test_interrupted_accepted_request_fences_delayed_claim_before_cleanup(tmp_path, monkeypatch, cancel):
    from infosec_harness.inference.controller import service as module

    core, request, lease, events, rows = controller_fixture(tmp_path)
    admitted, cleanup_started, release_cleanup = asyncio.Event(), asyncio.Event(), asyncio.Event()
    async def interrupted(_):
        await core.ledger.admit(request, lease_id=lease.lease_id, allocation={"tokens": 17})
        admitted.set()
        await asyncio.sleep(1)
    async def cleanup(_):
        cleanup_started.set()
        await release_cleanup.wait()
    monkeypatch.setattr(module, "CONTROLLER_TIMEOUT_S", 0.02)
    monkeypatch.setattr(core, "_infer", interrupted)
    monkeypatch.setattr(core.adapter, "revoke", cleanup)
    task = asyncio.create_task(core.infer(request))
    await admitted.wait()
    if cancel:
        task.cancel()
    await cleanup_started.wait()
    assert rows[request.request_id].state == "failed_before_dispatch"
    assert rows[request.request_id].allocation == {"tokens": 17}
    with pytest.raises(BrokerError):
        await core.ledger.claim(request.request_id, lease_id=lease.lease_id)
    release_cleanup.set()
    with pytest.raises(asyncio.CancelledError if cancel else BrokerError):
        await task
    assert events.count("fail_before_dispatch") == 1 and "recover" not in events


async def test_preclaim_fence_racing_claim_retains_unknown_before_cleanup(tmp_path, monkeypatch):
    from infosec_harness.inference.controller import service as module

    core, request, lease, events, rows = controller_fixture(tmp_path)
    original = core.ledger.fail_before_dispatch
    async def claim_race(*args, **kwargs):
        await core.ledger.claim(request.request_id, lease_id=lease.lease_id)
        return await original(*args, **kwargs)
    async def interrupted(_):
        await core.ledger.admit(request, lease_id=lease.lease_id, allocation={"tokens": 17})
        await asyncio.sleep(1)
    async def cleanup(_):
        assert rows[request.request_id].state == "completion_unknown"
        events.append("revoke")
    monkeypatch.setattr(module, "CONTROLLER_TIMEOUT_S", 0.02)
    monkeypatch.setattr(core, "_infer", interrupted)
    monkeypatch.setattr(core.ledger, "fail_before_dispatch", claim_race)
    monkeypatch.setattr(core.adapter, "revoke", cleanup)
    with pytest.raises(BrokerError, match="completion_unknown"):
        await core.infer(request)
    assert rows[request.request_id].allocation == {"tokens": 17}
    assert events.count("recover") == events.count("revoke") == 1


async def test_reconciliation_cutoff_does_not_join_slow_cancel_cleanup_or_accumulate_duplicates(tmp_path, monkeypatch):
    import time

    from infosec_harness.inference.controller import service as module

    core, request, lease, events, rows = controller_fixture(tmp_path)
    cleanup_release, cleanup_cancelled = asyncio.Event(), asyncio.Event()
    async def interrupted(_):
        await core.ledger.admit(request, lease_id=lease.lease_id, allocation={"tokens": 17})
        if rows[request.request_id].state == "accepted":
            await core.ledger.claim(request.request_id, lease_id=lease.lease_id)
        await asyncio.sleep(1)
    async def cleanup(_):
        events.append("revoke")
        try:
            await asyncio.sleep(1)
        finally:
            cleanup_cancelled.set()
            # Model a native subprocess finally block that does not finish promptly.
            while not cleanup_release.is_set():
                with suppress(asyncio.CancelledError):
                    await cleanup_release.wait()
    monkeypatch.setattr(module, "CONTROLLER_TIMEOUT_S", 0.02)
    monkeypatch.setattr(module, "RECONCILIATION_TIMEOUT_S", 0.02)
    monkeypatch.setattr(core, "_infer", interrupted)
    monkeypatch.setattr(core.adapter, "revoke", cleanup)
    try:
        for _ in range(2):
            started = time.monotonic()
            with pytest.raises(BrokerError, match="completion_unknown"):
                await core.infer(request)
            assert time.monotonic() - started < 0.2
            assert rows[request.request_id].state == "completion_unknown"
            assert rows[request.request_id].allocation == {"tokens": 17}
        await cleanup_cancelled.wait()
        assert len(core._reconciliation_tasks) == 1
        assert events.count("revoke") == events.count("recover") == 1
    finally:
        tasks = [entry[1] for entry in core._reconciliation_tasks.values()]
        cleanup_release.set()
        await asyncio.gather(*tasks, return_exceptions=True)
    assert not core._reconciliation_tasks


async def test_preclaim_fence_racing_saved_completion_returns_exact_result(tmp_path, monkeypatch):
    from infosec_harness.inference.controller import service as module

    core, request, lease, events, rows = controller_fixture(tmp_path)
    result = InferenceResult(request_id=request.request_id,
        response=encode_response(ModelResponse(parts=[TextPart("saved")])),
        usage={})
    async def completed_race(identity, *, lease_id):
        rows[identity] = replace(rows[identity], state="completed", result=result)
        return rows[identity]
    async def interrupted(_):
        await core.ledger.admit(request, lease_id=lease.lease_id, allocation={"tokens": 17})
        await asyncio.sleep(1)
    monkeypatch.setattr(module, "CONTROLLER_TIMEOUT_S", 0.02)
    monkeypatch.setattr(core, "_infer", interrupted)
    monkeypatch.setattr(core.ledger, "fail_before_dispatch", completed_race)
    assert await core.infer(request) is result
    assert "recover" not in events and "revoke" not in events
    assert rows[request.request_id].allocation == {"tokens": 17}


async def test_mapped_channel_wall_timeout_fences_delayed_remote_claim(tmp_path):
    core, request, lease, events, rows = controller_fixture(tmp_path)
    async def failed_channel(*args, **kwargs):
        assert rows[request.request_id].state == "accepted"
        raise BrokerError("unavailable")  # JsonChannel maps its wall timeout to this code.
    core.channel = SimpleNamespace(post=failed_channel)
    with pytest.raises(BrokerError, match="unavailable"):
        await core.infer(request)
    assert rows[request.request_id].state == "failed_before_dispatch"
    assert lease.status == "deleted"
    with pytest.raises(BrokerError):
        await core.ledger.claim(request.request_id, lease_id=lease.lease_id)
    assert events.index("fail_before_dispatch") < events.index("revoke")


async def test_uncommitted_native_success_ack_fences_delayed_claim(tmp_path):
    core, request, lease, events, rows = controller_fixture(tmp_path)
    async def uncommitted_ack(*args, **kwargs):
        return {}
    core.channel = SimpleNamespace(post=uncommitted_ack)
    with pytest.raises(BrokerError, match="completion_unknown"):
        await core.infer(request)
    assert rows[request.request_id].state == "failed_before_dispatch"
    assert lease.status == "deleted"
    with pytest.raises(BrokerError):
        await core.ledger.claim(request.request_id, lease_id=lease.lease_id)
    assert events.index("fail_before_dispatch") < events.index("revoke")


async def test_outer_wall_during_mapped_channel_cleanup_does_not_leak_child_cancellation(tmp_path, monkeypatch):
    from infosec_harness.inference.controller import service as module

    core, request, lease, events, rows = controller_fixture(tmp_path)
    cleanup_started = asyncio.Event()
    async def unavailable_after_claim(*args, **kwargs):
        await core.ledger.claim(request.request_id, lease_id=lease.lease_id)
        raise BrokerError("unavailable")
    async def slow_cleanup(_):
        cleanup_started.set()
        await asyncio.sleep(1)
    monkeypatch.setattr(module, "CONTROLLER_TIMEOUT_S", 0.02)
    monkeypatch.setattr(module, "RECONCILIATION_TIMEOUT_S", 0.2)
    monkeypatch.setattr(core.adapter, "revoke", slow_cleanup)
    core.channel = SimpleNamespace(post=unavailable_after_claim)
    with pytest.raises(BrokerError, match="completion_unknown"):
        await core.infer(request)
    assert cleanup_started.is_set()
    assert rows[request.request_id].state == "completion_unknown"
    assert events.count("recover") == 1
    assert not core._reconciliation_tasks


@pytest.mark.parametrize("detach_code", ["identity", "policy"])
async def test_detach_corroboration_failure_never_falls_back_to_delete(tmp_path, detach_code):
    adapter, lease, _, _, _, _ = native_fixture(tmp_path)
    actions = []
    async def run(args, **kwargs):
        actions.append(args[:3])
        if args[:2] == ["sandbox", "list"]:
            return json.dumps({"sandboxes": [{"id": lease.native_id, "name": lease.name, "labels": lease.labels()}]})
        if args[:3] == ["sandbox", "provider", "list"]:
            return json.dumps({"providers": [{"name": lease.contract.provider_binding}]})
        if args[:3] == ["sandbox", "provider", "detach"]:
            raise BrokerError(detach_code)
        raise AssertionError("Corroboration failure cannot delete any resource")
    adapter.cli.run = run
    with pytest.raises(BrokerError, match=detach_code):
        await adapter.revoke(lease)
    assert lease.status == adapter.store.load()[0].status == "revoked"
    assert ["sandbox", "delete", lease.name] not in actions


@pytest.mark.parametrize("foreign_after_detach", [False, True])
async def test_unavailable_detach_failed_delete_or_changed_ownership_remains_revoked(tmp_path, foreign_after_detach, caplog):
    adapter, lease, _, _, _, _ = native_fixture(tmp_path)
    actions = []
    detached = False
    async def run(args, **kwargs):
        nonlocal detached
        actions.append(args[:3])
        if args[:2] == ["sandbox", "list"]:
            identity = "foreign-native-id" if detached and foreign_after_detach else lease.native_id
            return json.dumps({"sandboxes": [{"id": identity, "name": lease.name, "labels": lease.labels()}]})
        if args[:3] == ["sandbox", "provider", "list"]:
            return json.dumps({"providers": [{"name": lease.contract.provider_binding}]})
        if args[:3] == ["sandbox", "provider", "detach"]:
            detached = True
            raise BrokerError("unavailable", "synthetic-private-credential")
        if args[:2] == ["sandbox", "delete"]:
            raise BrokerError("unavailable")
        raise AssertionError("Failed deletion cannot proceed to credential deletion")
    adapter.cli.run = run
    with pytest.raises(BrokerError, match="identity" if foreign_after_detach else "unavailable"):
        await adapter.revoke(lease)
    assert lease.status == adapter.store.load()[0].status == "revoked"
    assert (["sandbox", "delete", lease.name] in actions) is (not foreign_after_detach)
    assert not any(args[:2] == ["provider", "delete"] for args in actions)
    assert "synthetic-private" not in caplog.text


@pytest.mark.parametrize("fault", ["id", "name", "labels"])
async def test_foreign_native_ownership_never_detaches_or_deletes(tmp_path, fault):
    adapter, lease, _, _, _, _ = native_fixture(tmp_path)
    actions = []
    detail = {"id": lease.native_id, "name": lease.name, "labels": lease.labels()}
    detail[fault] = {} if fault == "labels" else "foreign"
    async def run(args, **kwargs):
        actions.append(args[:2])
        assert args[:2] == ["sandbox", "list"]
        return json.dumps({"sandboxes": [detail]})
    adapter.cli.run = run
    with pytest.raises(BrokerError, match="identity"):
        await adapter.revoke(lease)
    assert actions == [["sandbox", "list"]]


async def test_detach_timeout_delete_ack_with_remaining_container_cannot_ack_deleted(tmp_path, monkeypatch):
    from infosec_harness.inference.native import openshell as module

    adapter, lease, state, actions = owned_cleanup_fixture(tmp_path, "detach")
    async def containers(identity):
        assert identity == lease.native_id
        return ["still-running"]
    times = iter([0.0, 31.0])
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: next(times)))
    adapter.cli.containers = containers
    with pytest.raises(BrokerError, match="unavailable"):
        await adapter.revoke(lease)
    assert actions == ["detach", "delete"]
    assert lease.status == adapter.store.load()[0].status == "revoked"
    assert state["provider"] is True


async def test_remote_diagnostic_survives_completion_unknown_reconciliation(tmp_path):
    core, request, lease, events, rows = controller_fixture(tmp_path)
    diagnostic = {"boundary": "provider_request", "category": "wall_timeout"}

    async def interrupted_channel(*args, **kwargs):
        await core.ledger.claim(request.request_id, lease_id=lease.lease_id)
        raise BrokerError("completion_unknown", diagnostic=diagnostic)

    core.channel = SimpleNamespace(post=interrupted_channel)
    with pytest.raises(BrokerError) as error:
        await core.infer(request)
    assert error.value.code == "completion_unknown"
    assert error.value.diagnostic == diagnostic
    assert rows[request.request_id].state == "completion_unknown"
    assert lease.status == "deleted"
    assert events.count("recover") == events.count("revoke") == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["extra", "duplicate_workload", "missing_supervisor"])
async def test_native_readiness_requires_exactly_one_workload_and_supervisor(tmp_path, change):
    adapter, lease, _, workload, supervisor, _ = native_fixture(tmp_path)
    observed = {
        "extra": [workload, supervisor, {**workload, "Config": {"Labels": {}}}],
        "duplicate_workload": [workload, workload, supervisor],
        "missing_supervisor": [workload],
    }[change]

    async def containers(_identity):
        return observed

    adapter.cli.containers = containers
    with pytest.raises(BrokerError, match="policy"):
        await adapter.verify(lease)


@pytest.mark.asyncio
async def test_malformed_native_output_fails_closed_without_raw_parse_errors(tmp_path):
    adapter, lease, _, _, _, _ = native_fixture(tmp_path)

    async def garbage(args, **kwargs):
        return "not-json" if args[:2] == ["sandbox", "list"] else "[]"

    adapter.cli.run = garbage
    with pytest.raises(BrokerError, match="policy"):
        await adapter.revoke(lease)
    assert lease.status == "ready"


@pytest.mark.asyncio
async def test_revoke_uses_persisted_inputs_after_operator_spec_removal(tmp_path):
    adapter, lease, state, actions = owned_cleanup_fixture(tmp_path, failure=None)
    adapter.specs = {}
    await adapter.revoke(lease)
    assert lease.status == "deleted" and actions == ["detach", "delete", "provider"]
    assert not state["provider"]


def test_lease_state_machine_rejects_regressions(tmp_path):
    adapter, lease, *_ = native_fixture(tmp_path)
    with pytest.raises(BrokerError, match="identity"):
        adapter._transition(lease, "creating")
    adapter._transition(lease, "revoked")
    with pytest.raises(BrokerError, match="identity"):
        adapter._transition(lease, "ready")
    assert LeaseStore(adapter.store.directory).load()[0].status == "revoked"


@pytest.mark.asyncio
async def test_ready_lease_reverification_does_not_hold_the_global_lock(tmp_path):
    adapter, lease, *_ = native_fixture(tmp_path)
    entered, release = asyncio.Event(), asyncio.Event()
    original = adapter.verify

    async def slow_verify(target):
        entered.set()
        await release.wait()
        return await original(target)

    adapter.verify = slow_verify
    task = asyncio.create_task(adapter.ensure(lease.run_id, lease.contract))
    await entered.wait()
    assert not adapter.lock.locked()  # Other runs may provision or close meanwhile.
    release.set()
    assert await task is lease


@pytest.mark.asyncio
async def test_startup_reconciliation_drives_recovered_leases_toward_deletion(tmp_path, caplog):
    adapter, lease, state, actions = owned_cleanup_fixture(tmp_path, failure=None)
    open_ready = replace(lease, lease_id="22345678-1234-1234-1234-123456789abc", status="ready",
                         run_id="open-run")
    interrupted = replace(lease, lease_id="32345678-1234-1234-1234-123456789abc",
                          status="creating", native_id="", ledger_native_id="")
    for record in (lease, open_ready, interrupted):
        adapter.store.save(record)
    restarted = OpenShellAdapter(adapter.cli, store=LeaseStore(adapter.store.directory),
                                 deployment=adapter.deployment, specs=adapter.specs)
    await restarted.reconcile_recovered()
    assert lease.lease_id not in restarted.leases and restarted.is_deleted(lease.lease_id)
    assert restarted.leases[open_ready.lease_id].status == "ready"
    # Interrupted creation with verified absence of every owned resource is retired.
    assert restarted.is_deleted(interrupted.lease_id)
    assert "IH_NATIVE_RECONCILIATION_FAILURE" not in caplog.text


@pytest.mark.asyncio
async def test_startup_reconciliation_never_adopts_uncorroborated_creation(tmp_path, caplog):
    adapter, lease, *_ = native_fixture(tmp_path)
    interrupted = replace(lease, lease_id="42345678-1234-1234-1234-123456789abc",
                          status="creating", native_id="", ledger_native_id="")
    adapter.store.save(interrupted)
    calls = []

    async def run(args, **kwargs):
        calls.append(args)
        if args[:2] == ["sandbox", "list"]:
            # A selector match exists, but its creation receipt was never persisted.
            return json.dumps({"next_page_token": "", "sandboxes": [
                {"id": "unknown", "name": interrupted.name, "labels": interrupted.labels()}]})
        raise AssertionError(args)

    adapter.cli.run = run
    restarted = OpenShellAdapter(adapter.cli, store=LeaseStore(adapter.store.directory),
                                 deployment=adapter.deployment, specs=adapter.specs)
    await restarted.reconcile_recovered()
    assert restarted.leases[interrupted.lease_id].status == "quarantined"
    assert all(args[:2] == ["sandbox", "list"] for args in calls)
    assert "IH_NATIVE_RECONCILIATION_FAILURE state=quarantined category=identity" in caplog.text


@pytest.mark.asyncio
async def test_startup_reconciliation_revokes_ready_lease_of_a_closed_run(tmp_path):
    adapter, lease, _, actions = owned_cleanup_fixture(tmp_path, failure=None)
    lease.status = "ready"
    adapter.store.save(lease)
    adapter.store.revoke_run(lease.run_id)
    restarted = OpenShellAdapter(adapter.cli, store=LeaseStore(adapter.store.directory),
                                 deployment=adapter.deployment, specs=adapter.specs)
    await restarted.reconcile_recovered()
    assert restarted.is_deleted(lease.lease_id) and "delete" in actions


@pytest.mark.asyncio
async def test_ledger_database_fault_is_unavailable_but_bad_request_is_identity(tmp_path):
    core, request, lease, _, rows = controller_fixture(tmp_path)

    async def broken(_identity):
        raise OSError("database host secret")

    core.ledger.get = broken
    core.adapter.leases[lease.lease_id].ledger_key = "ledger-token"
    headers = {"Authorization": "Bearer ledger-token"}
    body = canonical_bytes({"request": request.model_dump(mode="json"), "lease_id": "lease"})
    with pytest.raises(BrokerError) as error:
        await core.handle("/v1/ledger/claim", body, headers)
    assert error.value.code == "unavailable" and "secret" not in str(error.value)
    with pytest.raises(BrokerError) as error:
        await core.handle("/v1/ledger/claim", canonical_bytes({"lease_id": "lease"}), headers)
    assert error.value.code == "identity"


@pytest.mark.asyncio
@pytest.mark.parametrize("token", ["lédger-token", "ledger-token\udcff", "\u0000"])
async def test_non_ascii_bearer_is_an_auth_failure_not_a_server_fault(tmp_path, token):
    """A malformed ledger credential is classified as auth before any comparison or ledger read."""
    core, request, lease, events, _ = controller_fixture(tmp_path)
    body = canonical_bytes({"request": request.model_dump(mode="json"), "lease_id": lease.lease_id})
    with pytest.raises(BrokerError) as error:
        await core.handle("/v1/ledger/claim", body, {"Authorization": "Bearer " + token})
    assert error.value.code in {"auth"}
    assert events == []


@pytest.mark.asyncio
async def test_new_request_renders_and_authorizes_once(tmp_path, monkeypatch):
    """Admission is rendered once per request and its allocation is the one admitted."""
    from infosec_harness.inference.controller import service as module

    core, request, lease, events, rows = controller_fixture(tmp_path)
    calls = []
    original = module.authorize

    async def counted(*args):
        calls.append(args[0].request_id)
        return await original(*args)

    async def committed(*_args, **_kwargs):
        rows[request.request_id] = replace(rows[request.request_id], state="completed",
            result=InferenceResult(request_id=request.request_id,
                response=encode_response(ModelResponse(parts=[TextPart("ok")]))))
        return {}

    monkeypatch.setattr(module, "authorize", counted)
    core.channel = SimpleNamespace(post=committed)
    assert (await core.infer(request)).request_id == request.request_id
    assert calls == [request.request_id]
    assert rows[request.request_id].allocation["requests"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("state,code", [("dispatch_intent", "pending"),
                                        ("completion_unknown", "completion_unknown"),
                                        ("failed_before_dispatch", "expired")])
async def test_infer_and_results_share_one_saved_disposition_mapping(tmp_path, state, code):
    core, request, lease, events, rows = controller_fixture(tmp_path)
    rows[request.request_id] = StoredDisposition(request, lease.lease_id, state, None, {})
    with pytest.raises(BrokerError) as inferred:
        await core.infer(request)
    body = canonical_bytes(request.model_dump(mode="json"))
    headers = {AUTH_HEADER: sign_request(b"a" * 32, "POST", "/v1/results", body, 130)}
    with pytest.raises(BrokerError) as read:
        await core.handle("/v1/results", body, headers)
    assert inferred.value.code == read.value.code == code
    assert "ensure" not in events and "admit" not in events


def test_production_controller_factory_imports_and_fails_closed_without_operator_file(
        tmp_path, monkeypatch):
    """The controller CLI resolves its factory by import path; it never starts unconfigured."""
    import importlib

    module, attribute = "infosec_harness.inference.controller.deployment", "controller_factory"
    factory = getattr(importlib.import_module(module), attribute)
    for value in (None, "relative.yaml", str(tmp_path / "absent.yaml")):
        if value is None:
            monkeypatch.delenv("HARNESS_BROKER_NATIVE_CONFIG", raising=False)
        else:
            monkeypatch.setenv("HARNESS_BROKER_NATIVE_CONFIG", value)
        with pytest.raises(BrokerError, match="policy"):
            factory()


def test_contract_inventory_covers_every_registered_agent(monkeypatch, capsys):
    import sys

    from infosec_harness.agents.registry import BINDINGS
    from infosec_harness.inference.controller import deployment

    monkeypatch.setattr(sys, "argv", ["deployment", "--print-contracts"])
    deployment.main()
    printed = json.loads(capsys.readouterr().out)
    assert set(printed) == set(BINDINGS)
    assert all(row["transport"] in {"direct", "brokered"} for row in printed.values())
    monkeypatch.setattr(sys, "argv", ["deployment"])
    with pytest.raises(SystemExit):
        deployment.main()
