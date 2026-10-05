"""Public status privacy and isolated operational-population regressions."""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from infosec_harness.agents.registry import BINDINGS
from infosec_harness.api import broker_observation, evidence_io, status
from infosec_harness.api.evidence_io import read_bytes
from infosec_harness.persistence import db
from infosec_harness.persistence.run_telemetry import RunTelemetry


def safe(value):
    text = json.dumps(value)
    assert all(secret not in text for secret in ("PRIVATE_SENTINEL", "password=", "/secret/"))


def ref(tmp_path, name, value):
    path = tmp_path / name
    data = json.dumps(value).encode()
    path.write_bytes(data)
    return {"file": str(path), "sha256": hashlib.sha256(data).hexdigest()}


def test_component_qualification_is_not_served():
    """The service cannot measure component qualification, so it publishes no such view."""
    from infosec_harness.api.app import app

    assert "/api/qualification" not in app.openapi()["paths"]


@pytest.mark.parametrize("kind", ["duplicate", "symlink", "drift"])
def test_reader_rejects_ambiguous_or_changed_evidence(tmp_path, kind):
    path = tmp_path / "evidence.json"
    path.write_text('{"version":1,"version":2}' if kind == "duplicate" else "{}")
    if kind == "symlink":
        link = tmp_path / "link.json"
        link.symlink_to(path)
        path = link
    with pytest.raises(ValueError):
        evidence_io.read_evidence(path, "0" * 64 if kind == "drift" else None)


@pytest.mark.parametrize(
    "change", ["naive", "future", "lifetime", "extra", "status", "catalog", "version", "provenance"]
)
def test_invalid_measurement_metadata_rejected(tmp_path, monkeypatch, change):
    catalog = tmp_path / "catalog.yaml"
    catalog.write_text("actual catalog")
    now = datetime.now(UTC)
    value = {
        "version": 1,
        "checked_at": (now - timedelta(seconds=10)).isoformat(),
        "valid_until": (now + timedelta(seconds=100)).isoformat(),
        "status": "passed",
        "catalog_sha256": hashlib.sha256(catalog.read_bytes()).hexdigest(),
        "dependencies": {str(catalog): hashlib.sha256(catalog.read_bytes()).hexdigest()},
        "evidence": {"unscoped": {"file": "/secret/proof", "sha256": "0" * 64}},
    }
    if change == "naive":
        value["checked_at"] = now.replace(tzinfo=None).isoformat()
    elif change == "future":
        value["checked_at"] = (now + timedelta(seconds=10)).isoformat()
    elif change == "lifetime":
        value["valid_until"] = (now + timedelta(days=10)).isoformat()
    elif change == "extra":
        value["private"] = "PRIVATE_SENTINEL"
    elif change == "status":
        value["status"] = "ready-by-name"
    elif change == "catalog":
        value["catalog_sha256"] = "0" * 64
    elif change == "version":
        value["version"] = True
    # The provenance case intentionally has only arbitrary status=passed proof JSON.
    # That must never establish actual measured owner/health/all11 readiness.
    monkeypatch.setattr(
        broker_observation,
        "get_settings",
        lambda: SimpleNamespace(
            broker_config=catalog, qualification_observation_max_age_seconds=3600
        ),
    )
    monkeypatch.setattr(broker_observation, "_observation", lambda: value)
    monkeypatch.setattr(broker_observation, "read_reference", lambda r: {"status": "passed"})
    with pytest.raises((ValueError, TypeError, KeyError)):
        broker_observation.broker_measurement()


async def test_db_unavailable_is_not_zero_holds(monkeypatch):
    def fail():
        raise RuntimeError("PRIVATE_SENTINEL password=credential /secret/db")

    monkeypatch.setattr(db, "session", fail)
    monkeypatch.setattr(
        status,
        "get_settings",
        lambda: SimpleNamespace(
            broker_config="configured",
            environment="test",
            model_mode="live",
            database_url="sqlite+aiosqlite://",
            temporal_tls=False,
            git_commit_sha="a" * 40,
        ),
    )
    monkeypatch.setattr(broker_observation, "get_settings", status.get_settings)
    result = await status.runtime_status()
    assert result.broker.status == "not_checked"
    assert result.broker.unresolved_requests is None
    assert result.broker.conservatively_closed_requests is None
    safe(result.model_dump())


@pytest.fixture
async def population_client(tmp_path, monkeypatch):
    from infosec_harness.api.app import app

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'isolated.sqlite'}")
    async with engine.begin() as connection:
        await connection.run_sync(db.Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(db, "session", sessions)
    async with sessions() as session:
        for population in ("operational", "demo", "unmeasured"):
            session.add(db.Batch(id=population, finding_count=1))
            session.add(
                db.TriageRun(
                    id=population,
                    batch_id=population,
                    fingerprint=population,
                    repo_url="/test/repo",
                    revision="test",
                    title=population,
                    telemetry=None if population == "unmeasured" else RunTelemetry.accepted(
                        population, datetime.now(UTC)).stored(),
                )
            )
        await session.commit()
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            yield client
    finally:
        await engine.dispose()


async def test_operational_population_filters_list_count_and_details(population_client):
    client = population_client
    params = {"population": "operational"}
    response = await client.get("/api/batches", params=params)
    assert response.status_code == 200
    assert [row["id"] for row in response.json()] == ["operational"]
    page = (await client.get("/api/run-page", params=params)).json()
    assert page["total"] == 1
    assert [row["id"] for row in page["items"]] == ["operational"]
    for population in ("demo", "unmeasured"):
        for endpoint in (f"/api/runs/{population}", f"/api/batches/{population}"):
            assert (await client.get(endpoint, params=params)).status_code == 404
    assert (await client.get("/api/runs/operational", params=params)).status_code == 200
    assert [
        row["id"] for row in (await client.get("/api/run-page", params={"population": "demo"})
                              ).json()["items"]
    ] == ["demo"]
    # Unfiltered reads still return a run stored without telemetry.
    assert (await client.get("/api/runs/unmeasured")).json()["telemetry"] is None


async def test_stale_measurement_does_not_promote_reachable_channel(monkeypatch):
    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def execute(self, statement):
            return SimpleNamespace(all=lambda: [(SimpleNamespace(), None)] * 16)

    async def reachable():
        return True

    monkeypatch.setattr(db, "session", Session)
    monkeypatch.setattr(
        status,
        "get_settings",
        lambda: SimpleNamespace(
            broker_config="configured",
            environment="test",
            model_mode="live",
            database_url="sqlite+aiosqlite://",
            temporal_tls=False,
            git_commit_sha="a" * 40,
        ),
    )
    monkeypatch.setattr(
        broker_observation,
        "broker_measurement",
        lambda: ({"checked_at": "2026-01-01T00:00:00+00:00", "status": "passed"}, True),
    )
    monkeypatch.setattr(broker_observation, "admission_reachable", reachable)
    monkeypatch.setattr(broker_observation, "get_settings", status.get_settings)
    result = await status.runtime_status()
    assert result.broker.status == "not_checked"
    assert result.broker.unresolved_requests == 16
    assert result.broker.stale is True


@pytest.fixture
def verified_measurement(tmp_path, monkeypatch):
    """Synthetic trusted evidence with actual file hashes and explicit linked identities."""
    import copy

    root = tmp_path / "checkout"
    inference = root / "src/infosec_harness/inference"
    inference.mkdir(parents=True)
    modules = {}
    for name in ("controller/service.py", "native/openshell.py", "worker/transport.py"):
        path = inference / name
        path.parent.mkdir(exist_ok=True)
        path.write_text(f"# synthetic {name}\n")
        modules[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    for relative in broker_observation.CONTROLLER_SHARED_MODULES:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# synthetic {relative}\n")
        modules[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    catalog = tmp_path / "catalog.yaml"
    catalog.write_text("synthetic operator catalog")
    catalog_hash = hashlib.sha256(catalog.read_bytes()).hexdigest()
    source = "a" * 40
    owner = {
        "status": "passed",
        "source_end_commit": source,
        "owned_container_ids": {"ih-live-controller": "c" * 64},
        "loaded_controller_adapter_source_sha256": {
            name: modules[f"src/infosec_harness/inference/{name}"]
            for name in ("controller/service.py", "native/openshell.py", "worker/transport.py")
        },
        "candidate_config_files_sha256": {str(catalog): catalog_hash},
    }
    owner_ref = ref(tmp_path, "owner.json", owner)
    health = {
        "status": "passed",
        "source_commit": source,
        "new_owner_sha256": owner_ref["sha256"],
        "new_controller_id": "c" * 64,
        "controller_configuration_sha256": "d" * 64,
        "actual_tls_unsigned_401": {"status": 401, "tls_verified": True, "no_admission": True},
        "loaded_module_attestation": modules,
    }
    ready = {
        "status": "passed",
        "source_commit": source,
        "owner_sha256": owner_ref["sha256"],
        "registered_contracts": 11,
        "native_inventory": 0,
        "owned_test_leases_deleted": True,
        "loaded_module_sha256_start_end_equal": dict(
            owner["loaded_controller_adapter_source_sha256"]
        ),
    }
    from infosec_harness.inference.catalog import profiles

    profile = SimpleNamespace(
        executor_image="sha256:" + "e" * 64,
        supervisor_image="sha256:" + "f" * 64,
        policy_digest="1" * 64,
    )
    monkeypatch.setattr(
        profiles,
        "load_broker_config",
        lambda _, **__: SimpleNamespace(profile_for_agent=lambda agent: (agent, profile)),
    )
    ready["native_observations"] = {
        agent: {
            "state": "ready",
            "contract_digest": hashlib.sha256(agent.encode()).hexdigest(),
            "profile": agent,
            "executor_image": profile.executor_image,
            "supervisor_image": profile.supervisor_image,
            "policy_digest": profile.policy_digest,
        }
        for agent in BINDINGS
    }
    ready["issued_owned_readiness_leases"] = {
        f"lease-{agent}": {"agent": agent, "contract_digest": row["contract_digest"]}
        for agent, row in ready["native_observations"].items()
    }
    now = datetime.now(UTC)
    value = {
        "version": 1,
        "checked_at": (now - timedelta(seconds=5)).isoformat(),
        "valid_until": (now + timedelta(seconds=60)).isoformat(),
        "status": "passed",
        "catalog_sha256": catalog_hash,
        "dependencies": {str(root / name): sha for name, sha in modules.items()},
        "evidence": {
            "owner": owner_ref,
            "health": ref(tmp_path, "health.json", health),
            "readiness": ref(tmp_path, "readiness.json", ready),
        },
    }
    monkeypatch.setattr(broker_observation, "source_checkout", lambda: root)
    monkeypatch.setattr(
        broker_observation,
        "get_settings",
        lambda: SimpleNamespace(
            broker_config=catalog, qualification_observation_max_age_seconds=3600
        ),
    )

    def install(observation):
        measurement = ref(tmp_path, "observation.json", observation)["file"]
        monkeypatch.setattr(broker_observation, "_observation",
                            lambda: evidence_io.read_evidence(measurement))

    install(value)
    return copy.deepcopy(value), install


def test_scoped_measurement_positive_uses_real_hashes(verified_measurement):
    value, _ = verified_measurement
    measured, stale = broker_observation.broker_measurement()
    assert measured == value
    assert stale is False


@pytest.mark.parametrize(
    "target,field,bad",
    [
        ("health", "source_commit", "b" * 40),
        ("health", "new_owner_sha256", "0" * 64),
        ("readiness", "owner_sha256", "0" * 64),
        ("readiness", "registered_contracts", True),
        ("readiness", "registered_contracts", 10),
        ("readiness", "native_inventory", 1),
        ("readiness", "owned_test_leases_deleted", False),
        ("readiness", "loaded_module_sha256_start_end_equal", False),
    ],
)
def test_authenticated_evidence_identity_and_readiness_drift(
    verified_measurement, tmp_path, target, field, bad
):
    value, install = verified_measurement
    proof = json.loads(read_bytes(value["evidence"][target]["file"]))
    proof[field] = bad
    value["evidence"][target] = ref(tmp_path, f"modified-{target}.json", proof)
    install(value)
    with pytest.raises(ValueError):
        broker_observation.broker_measurement()


def test_measurement_byte_drift_rejects_even_linked_proofs(verified_measurement):
    value, _ = verified_measurement
    from pathlib import Path

    Path(next(iter(value["dependencies"]))).write_text("changed measured code")
    with pytest.raises(ValueError):
        broker_observation.broker_measurement()


def test_valid_but_expired_measurement_is_stale(verified_measurement):
    value, install = verified_measurement
    now = datetime.now(UTC)
    value["checked_at"] = (now - timedelta(seconds=100)).isoformat()
    value["valid_until"] = (now - timedelta(seconds=1)).isoformat()
    install(value)
    assert broker_observation.broker_measurement()[1] is True


@pytest.mark.parametrize(
    "response_body,expected",
    [
        (b'{"error":"auth"}', True),
        (b'{"error":"auth","private":"PRIVATE_SENTINEL"}', False),
        (b'{"error":"auth","error":"auth"}', False),
        (b"x" * 1025, False),
        (None, False),
    ],
)
async def test_probe_is_unsigned_bounded_and_does_not_load_client_keys(
    tmp_path, monkeypatch, response_body, expected
):
    import asyncio

    from infosec_harness.inference.catalog import profiles

    catalog, ca = tmp_path / "catalog", tmp_path / "ca"
    catalog.write_bytes(b"catalog")
    ca.write_bytes(b"ca")
    channel = SimpleNamespace(
        url="https://controller.example",
        ca_file=str(ca),
        client_cert="/secret/client.pem",
        client_key="/secret/key.pem",
    )
    monkeypatch.setattr(
        profiles, "load_broker_config", lambda _, **__: SimpleNamespace(controller=channel)
    )
    monkeypatch.setattr(broker_observation, "get_settings", lambda: SimpleNamespace(broker_config=catalog))
    monkeypatch.setattr(broker_observation, "_probe_cache", None)
    monkeypatch.setattr(broker_observation, "_probe_lock", asyncio.Lock())

    class Context:
        def load_cert_chain(self, *args, **kwargs):
            pytest.fail("probe loaded client private credentials")

    monkeypatch.setattr(broker_observation.ssl, "create_default_context", lambda **kwargs: Context())
    observed = []
    deadlines = []
    original_timeout = asyncio.timeout

    def bounded_timeout(seconds):
        deadlines.append(seconds)
        return original_timeout(0.01 if response_body is None else seconds)

    monkeypatch.setattr(broker_observation.asyncio, "timeout", bounded_timeout)

    class SlowResponse(httpx.AsyncByteStream):
        async def __aiter__(self):
            await asyncio.sleep(0.05)
            yield b'{"error":"auth"}'

    def handle(request):
        observed.append(request)
        assert request.method == "POST"
        assert request.url == "https://controller.example/v1/infer"
        assert request.content == b"{}"
        assert "authorization" not in request.headers
        assert not any("auth" in k.lower() for k in request.headers)
        return (
            httpx.Response(401, stream=SlowResponse())
            if response_body is None
            else httpx.Response(401, content=response_body)
        )

    actual_client = httpx.AsyncClient

    def client(**kwargs):
        assert kwargs["trust_env"] is False
        assert kwargs["follow_redirects"] is False
        assert kwargs["timeout"] == 3
        kwargs.pop("verify")
        return actual_client(transport=httpx.MockTransport(handle), **kwargs)

    monkeypatch.setattr(broker_observation.httpx, "AsyncClient", client)
    assert await broker_observation.admission_reachable() is expected
    assert await broker_observation.admission_reachable() is expected
    assert len(observed) == 1  # Cached observations do not repeat the admission probe.
    assert deadlines == [3]  # Whole-stream wall bound, not only per-chunk I/O deadlines.


@pytest.mark.parametrize(
    "change", ["cid", "native_agent", "native_image", "lease_contract", "missing_module"]
)
def test_current_measurement_rejects_exact_runtime_and_contract_drift(
    verified_measurement, tmp_path, change
):
    value, install = verified_measurement
    target = "health" if change in {"cid", "missing_module"} else "readiness"
    proof = json.loads(read_bytes(value["evidence"][target]["file"]))
    if change == "cid":
        proof["new_controller_id"] = "9" * 64
    elif change == "missing_module":
        proof["loaded_module_attestation"].pop("src/infosec_harness/inference/worker/transport.py")
    elif change == "native_agent":
        proof["native_observations"].pop("intake")
    elif change == "native_image":
        proof["native_observations"]["intake"]["executor_image"] = "sha256:" + "9" * 64
    else:
        proof["issued_owned_readiness_leases"]["lease-intake"]["contract_digest"] = "9" * 64
    value["evidence"][target] = ref(tmp_path, f"changed-{target}.json", proof)
    install(value)
    with pytest.raises(ValueError):
        broker_observation.broker_measurement()


def test_adapter_digest_map_mismatch_is_rejected(verified_measurement, tmp_path):
    value, install = verified_measurement
    proof = json.loads(read_bytes(value["evidence"]["readiness"]["file"]))
    proof["loaded_module_sha256_start_end_equal"]["worker/transport.py"] = "0" * 64
    value["evidence"]["readiness"] = ref(tmp_path, "drifted-adapter-map.json", proof)
    install(value)
    with pytest.raises(ValueError):
        broker_observation.broker_measurement()


@pytest.mark.parametrize("corruption", ["nested_duplicate", "malformed"])
async def test_extracted_projections_share_fail_closed_file_reader(tmp_path, monkeypatch, corruption):
    """An ambiguous or malformed observation file is unchecked, never echoed."""
    proof = tmp_path / "PRIVATE_SENTINEL-proof.json"
    proof.write_text('{"status":"passed","status":"passed"}' if corruption == "nested_duplicate" else '{}')
    settings = SimpleNamespace(broker_observation=proof, broker_config=tmp_path / "catalog")
    monkeypatch.setattr(broker_observation, "get_settings", lambda: settings)

    class Session:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return None
        async def execute(self, statement):
            return SimpleNamespace(all=lambda: [(SimpleNamespace(), None)] * 16)

    async def unexpected_probe():
        pytest.fail("invalid evidence invoked a live controller probe")

    monkeypatch.setattr(db, "session", Session)
    monkeypatch.setattr(broker_observation, "admission_reachable", unexpected_probe)
    broker = await broker_observation.broker_status()
    assert broker.status == "not_checked"
    assert broker.unresolved_requests == 16
    assert broker.checked_at is None
    safe(broker.model_dump())


@pytest.mark.parametrize("corruption", [None, "bare_status", "missing_marker", "changed_request", "wrong_basis"])
async def test_audited_unknown_closures_remain_distinct_and_invalid_closures_unresolved(
    tmp_path, monkeypatch, corruption,
):
    from copy import deepcopy

    from infosec_harness.persistence import budgets, reconciliation

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'closure-status.sqlite'}")
    async with engine.begin() as connection:
        await connection.run_sync(db.Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(db, "session", sessions)
    limits = {"requests": 1, "tokens": 100, "cost_usd": 1}
    state = budgets.initial_state(limits)
    state["deadline_at"] = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    state["broker_revoked_runs"] = ["run"]
    binding = {"root_id": "root", "operation_id": "op", "run_id": "run"}
    state["operations"] = {"op": {
        "status": "uncertain", "reserved": limits, "broker_owned": True,
        "broker_revoked": True, "run_id": "run", "broker_binding": binding,
        "broker_allocated": limits,
    }}
    try:
        async with sessions() as session:
            root = db.BudgetLedger(root_id="root", state=state)
            row = db.InferenceRequestRecord(
                request_id="unknown", root_id="root", operation_id="op", lease_id="lease",
                state="completion_unknown", request={"binding": binding}, allocation=limits,
            )
            session.add_all([root, row])
            await session.commit()
            authorization = reconciliation.ClosureRequest(
                root_id="root", operation_id="op", expected_root_revision=root.revision,
                expected_root_sha256=reconciliation.row_sha256(root),
                expected_request_sha256={row.request_id: reconciliation.row_sha256(row)},
                unknown_request_ids=[row.request_id], source_commit="a" * 40,
                evidence_sha256={"approved_snapshot": "b" * 64}, reason="loss_accepted",
            )
            original_request_hash = reconciliation.row_sha256(row)
        await reconciliation.close_unknown(authorization)
        if corruption:
            async with sessions() as session:
                root = await session.get(db.BudgetLedger, "root")
                changed = deepcopy(root.state)
                operation = changed["operations"]["op"]
                if corruption == "bare_status":
                    operation.pop("unknown_reconciliation")
                elif corruption == "missing_marker":
                    operation["unknown_reconciliation"].pop("charged")
                elif corruption == "wrong_basis":
                    operation["unknown_reconciliation"]["accounting_basis"] = "observed_usage"
                elif corruption == "changed_request":
                    row = await session.get(db.InferenceRequestRecord, "unknown")
                    row.lease_id = "changed"
                root.state = changed
                await session.commit()
        monkeypatch.setattr(broker_observation, "get_settings", lambda: SimpleNamespace(broker_config="configured"))
        def unavailable():
            raise ValueError("No readiness measurement")
        monkeypatch.setattr(broker_observation, "broker_measurement", unavailable)
        result = await broker_observation.broker_status()
        assert result.unresolved_requests == (1 if corruption else 0)
        assert result.conservatively_closed_requests == (0 if corruption else 1)
        # Closing and displaying accounting never fabricates a provider result.
        async with sessions() as session:
            row = await session.get(db.InferenceRequestRecord, "unknown")
            assert row.state == "completion_unknown" and row.result is None
            if corruption != "changed_request":
                assert reconciliation.row_sha256(row) == original_request_hash
        safe(result.model_dump())
    finally:
        await engine.dispose()
