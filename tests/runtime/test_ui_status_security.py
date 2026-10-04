"""Public status privacy and isolated operational-population regressions."""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from infosec_harness.api import status
from infosec_harness.persistence import db
from infosec_harness.qualification.ledger import digest


def safe(value):
    text = json.dumps(value)
    assert all(secret not in text for secret in ("PRIVATE_SENTINEL", "password=", "/secret/"))


def ref(tmp_path, name, value):
    path = tmp_path / name
    data = json.dumps(value).encode()
    path.write_bytes(data)
    return {"file": str(path), "sha256": hashlib.sha256(data).hexdigest()}


def test_missing_evidence_has_eleven_unchecked_components(monkeypatch):
    monkeypatch.setattr(status, "get_settings", lambda: SimpleNamespace(qualification_bundle=None))
    result = status.qualification_status().model_dump()
    assert result["status"] == "not_checked"
    assert len(result["components"]) == 11
    assert all(row["status"] == "not_checked" for row in result["components"])
    safe(result)


@pytest.mark.parametrize("kind", [ValueError, OSError, TypeError, KeyError])
def test_errors_never_echo_private_messages(monkeypatch, kind):
    def fail():
        raise kind("PRIVATE_SENTINEL password=credential /secret/evidence")

    monkeypatch.setattr(status, "_bundle", fail)
    result = status.qualification_status().model_dump()
    assert result["status"] == "not_checked"
    safe(result)


@pytest.mark.parametrize("kind", ["duplicate", "symlink", "drift"])
def test_reader_rejects_ambiguous_or_changed_evidence(tmp_path, kind):
    path = tmp_path / "evidence.json"
    path.write_text('{"version":1,"version":2}' if kind == "duplicate" else "{}")
    if kind == "symlink":
        link = tmp_path / "link.json"
        link.symlink_to(path)
        path = link
    with pytest.raises(ValueError):
        status._read(path, "0" * 64 if kind == "drift" else None)


def test_matching_commit_label_does_not_override_dependency_drift(tmp_path, monkeypatch):
    path = tmp_path / "runtime.py"
    path.write_text("changed runtime")
    evidence = ref(tmp_path, "witness.json", {"n": 9, "passed": 9})
    rows, components, selection = [], {}, {}
    for agent in status.AGENT_BINDINGS:
        row = {
            "component": agent,
            "scope": "agent_semantics",
            "measured_status": "passed",
            "measured_source_commit": "a" * 40,
            "dependencies": {"runtime": {"source": "0" * 64}},
            "evidence": {"completion_witness": evidence},
        }
        row["id"] = digest(row)
        rows.append(row)
        selection[agent] = row["id"]
        components[agent] = {"runtime": {"source": {"file": str(path)}}}
    bundle = {
        "version": 1,
        "ledger": ref(tmp_path, "ledger.json", {"version": 1, "records": rows}),
        "current": ref(
            tmp_path,
            "current.json",
            {"qualification_candidate_commit": "a" * 40, "components": components},
        ),
        "reviews": ref(tmp_path, "reviews.json", {}),
        "selection": selection,
        "broker_observation": None,
    }
    monkeypatch.setattr(status, "_bundle", lambda: bundle)
    monkeypatch.setattr(status, "get_settings", lambda: SimpleNamespace(git_commit_sha="a" * 40))
    result = status.qualification_status()
    assert result.status == "not_checked"
    assert all(row.status == "not_checked" for row in result.components)
    safe(result.model_dump())


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
        status,
        "get_settings",
        lambda: SimpleNamespace(
            broker_config=catalog, qualification_observation_max_age_seconds=3600
        ),
    )
    monkeypatch.setattr(status, "_bundle", lambda: {"broker_observation": "measurement"})
    monkeypatch.setattr(
        status, "_ref", lambda r: value if r == "measurement" else {"status": "passed"}
    )
    with pytest.raises((ValueError, TypeError, KeyError)):
        status._measurement()


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
    result = await status.runtime_status()
    assert result.broker.status == "not_checked"
    assert result.broker.unresolved_requests is None
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
        for population in ("operational", "demo", "legacy"):
            session.add(db.Batch(id=population, finding_count=1))
            session.add(
                db.TriageRun(
                    id=population,
                    batch_id=population,
                    fingerprint=population,
                    repo_url="/test/repo",
                    revision="test",
                    title=population,
                    telemetry={} if population == "legacy" else {"population": population},
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
    for endpoint in ("/api/runs", "/api/batches"):
        response = await client.get(endpoint, params=params)
        assert response.status_code == 200
        assert [row["id"] for row in response.json()] == ["operational"]
    page = (await client.get("/api/run-page", params=params)).json()
    assert page["total"] == 1
    assert [row["id"] for row in page["items"]] == ["operational"]
    for population in ("demo", "legacy"):
        for endpoint in (f"/api/runs/{population}", f"/api/batches/{population}"):
            assert (await client.get(endpoint, params=params)).status_code == 404
    assert (await client.get("/api/runs/operational", params=params)).status_code == 200
    assert [
        row["id"] for row in (await client.get("/api/runs", params={"population": "demo"})).json()
    ] == ["demo"]


async def test_stale_measurement_does_not_promote_reachable_channel(monkeypatch):
    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def scalar(self, statement):
            return 16

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
        status,
        "_measurement",
        lambda: ({"checked_at": "2026-01-01T00:00:00+00:00", "status": "passed"}, True),
    )
    monkeypatch.setattr(status, "_admission_reachable", reachable)
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
    for name in ("controller.py", "openshell.py", "transport.py"):
        path = inference / name
        path.write_text(f"# synthetic {name}\n")
        modules[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
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
            for name in ("controller.py", "openshell.py", "transport.py")
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
    from infosec_harness.inference import profiles

    profile = SimpleNamespace(
        executor_image="sha256:" + "e" * 64,
        supervisor_image="sha256:" + "f" * 64,
        policy_digest="1" * 64,
    )
    monkeypatch.setattr(
        profiles,
        "load_broker_config",
        lambda _: SimpleNamespace(profile_for_agent=lambda agent: (agent, profile)),
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
        for agent in status.AGENT_BINDINGS
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
    monkeypatch.setattr(status, "source_checkout", lambda: root)
    monkeypatch.setattr(
        status,
        "get_settings",
        lambda: SimpleNamespace(
            broker_config=catalog, qualification_observation_max_age_seconds=3600
        ),
    )

    def install(observation):
        measurement = ref(tmp_path, "observation.json", observation)
        monkeypatch.setattr(status, "_bundle", lambda: {"broker_observation": measurement})

    install(value)
    return copy.deepcopy(value), install


def test_scoped_measurement_positive_uses_real_hashes(verified_measurement):
    value, _ = verified_measurement
    measured, stale = status._measurement()
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
    proof = json.loads(status.read_bytes(value["evidence"][target]["file"]))
    proof[field] = bad
    value["evidence"][target] = ref(tmp_path, f"modified-{target}.json", proof)
    install(value)
    with pytest.raises(ValueError):
        status._measurement()


def test_measurement_byte_drift_rejects_even_linked_proofs(verified_measurement):
    value, _ = verified_measurement
    from pathlib import Path

    Path(next(iter(value["dependencies"]))).write_text("changed measured code")
    with pytest.raises(ValueError):
        status._measurement()


def test_valid_but_expired_measurement_is_stale(verified_measurement):
    value, install = verified_measurement
    now = datetime.now(UTC)
    value["checked_at"] = (now - timedelta(seconds=100)).isoformat()
    value["valid_until"] = (now - timedelta(seconds=1)).isoformat()
    install(value)
    assert status._measurement()[1] is True


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

    from infosec_harness.inference import profiles

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
        profiles, "load_broker_config", lambda _: SimpleNamespace(controller=channel)
    )
    monkeypatch.setattr(status, "get_settings", lambda: SimpleNamespace(broker_config=catalog))
    monkeypatch.setattr(status, "_probe_cache", None)
    monkeypatch.setattr(status, "_probe_lock", asyncio.Lock())

    class Context:
        def load_cert_chain(self, *args, **kwargs):
            pytest.fail("probe loaded client private credentials")

    monkeypatch.setattr(status.ssl, "create_default_context", lambda **kwargs: Context())
    observed = []
    deadlines = []
    original_timeout = asyncio.timeout

    def bounded_timeout(seconds):
        deadlines.append(seconds)
        return original_timeout(0.01 if response_body is None else seconds)

    monkeypatch.setattr(status.asyncio, "timeout", bounded_timeout)

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

    monkeypatch.setattr(status.httpx, "AsyncClient", client)
    assert await status._admission_reachable() is expected
    assert await status._admission_reachable() is expected
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
    proof = json.loads(status.read_bytes(value["evidence"][target]["file"]))
    if change == "cid":
        proof["new_controller_id"] = "9" * 64
    elif change == "missing_module":
        proof["loaded_module_attestation"].pop("src/infosec_harness/inference/transport.py")
    elif change == "native_agent":
        proof["native_observations"].pop("intake")
    elif change == "native_image":
        proof["native_observations"]["intake"]["executor_image"] = "sha256:" + "9" * 64
    else:
        proof["issued_owned_readiness_leases"]["lease-intake"]["contract_digest"] = "9" * 64
    value["evidence"][target] = ref(tmp_path, f"changed-{target}.json", proof)
    install(value)
    with pytest.raises(ValueError):
        status._measurement()


def test_adapter_digest_map_mismatch_is_rejected(verified_measurement, tmp_path):
    value, install = verified_measurement
    proof = json.loads(status.read_bytes(value["evidence"]["readiness"]["file"]))
    proof["loaded_module_sha256_start_end_equal"]["transport.py"] = "0" * 64
    value["evidence"]["readiness"] = ref(tmp_path, "drifted-adapter-map.json", proof)
    install(value)
    with pytest.raises(ValueError):
        status._measurement()


@pytest.mark.parametrize("witness_key", ["completion_witness", "cardinality"])
def test_verified_legacy_cardinality_projects_cohort_counts(tmp_path, monkeypatch, witness_key):
    # Both existing evidence-key generations refer to the same measured n/passed shape.
    dependency = tmp_path / "runtime.py"
    dependency.write_bytes(b"unchanged source bytes")
    measured_sha = hashlib.sha256(dependency.read_bytes()).hexdigest()
    witness = ref(
        tmp_path, "complete-cardinality.json", {"status": "complete", "n": 11, "passed": 11}
    )
    records, components, selection = [], {}, {}
    for agent in status.AGENT_BINDINGS:
        record = {
            "component": agent,
            "scope": "agent_semantics",
            "measured_status": "passed",
            "measured_source_commit": "a" * 40,
            "dependencies": {"runtime": {"source": measured_sha}},
            "evidence": {witness_key: witness},
        }
        record["id"] = digest(record)
        records.append(record)
        selection[agent] = record["id"]
        components[agent] = {"runtime": {"source": {"file": str(dependency)}}}
    bundle = {
        "version": 1,
        "ledger": ref(tmp_path, "ledger-positive.json", {"version": 1, "records": records}),
        "current": ref(
            tmp_path,
            "current-positive.json",
            {"qualification_candidate_commit": "a" * 40, "components": components},
        ),
        "reviews": ref(tmp_path, "reviews-positive.json", {}),
        "selection": selection,
        "broker_observation": None,
    }
    monkeypatch.setattr(status, "_bundle", lambda: bundle)
    monkeypatch.setattr(status, "get_settings", lambda: SimpleNamespace(git_commit_sha="a" * 40))
    result = status.qualification_status()
    assert result.status == "passed"
    assert len(result.components) == 11
    assert all(
        row.status == "passed" and row.cases == 11 and row.passed_cases == 11
        for row in result.components
    )
    safe(result.model_dump())
