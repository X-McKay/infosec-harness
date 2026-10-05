"""Profile-bound operator receipts cannot promote configuration to measured connectivity."""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from infosec_harness.agents import models, registry
from infosec_harness.api import model_observation as status


@pytest.fixture
def receipt(tmp_path, monkeypatch):
    config = tmp_path / "models.yaml"
    config.write_text("public profile")
    path = tmp_path / "observation.json"
    settings = SimpleNamespace(
        model_mode="live",
        model_connection_observation=path,
        models_config=config,
        broker_config=None,
        git_commit_sha="a" * 40,
    )
    monkeypatch.setattr(status, "get_settings", lambda: settings)
    monkeypatch.setattr(models, "resolve_config",
                        lambda *args, **kwargs: SimpleNamespace(resolved_model="gateway:Qwen"))
    monkeypatch.setattr(registry, "load_spec", lambda name: SimpleNamespace(model="sonnet"))
    value = {
        "version": 1,
        "checked_at": datetime.now(UTC).isoformat(),
        "source_commit": "a" * 40,
        "model_config_sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
        "broker_config_sha256": None,
        "mode": "live",
        "transport": "direct",
        "status": "passed",
    }
    path.write_text(json.dumps(value))
    return path, value, settings


def test_exact_profile_recorded_check_passes_without_provider_call(receipt):
    names, observed = status.model_runtime()
    assert names == ["gateway:Qwen"]
    assert observed.status == "passed" and observed.checked_at
    assert "not a continuous health probe" in observed.detail


@pytest.mark.parametrize(
    "change",
    ["profile", "source", "transport", "mode", "future", "naive", "extra", "version", "duplicate"],
)
def test_changed_or_invalid_receipt_never_promotes_or_leaks(receipt, change):
    path, value, settings = receipt
    if change == "profile":
        settings.models_config.write_text("changed")
    elif change == "source":
        value["source_commit"] = "b" * 40
    elif change == "transport":
        value["transport"] = "brokered"
    elif change == "mode":
        value["mode"] = "stub"
    elif change == "future":
        value["checked_at"] = (datetime.now(UTC) + timedelta(seconds=5)).isoformat()
    elif change == "naive":
        value["checked_at"] = datetime.now().isoformat()
    elif change == "extra":
        value["private"] = "PRIVATE_SENTINEL"
    elif change == "version":
        value["version"] = True
    path.write_text(json.dumps(value) if change != "duplicate" else '{"version":1,"version":1}')
    _, observed = status.model_runtime()
    assert observed.status == "not_checked" and observed.checked_at is None
    assert "PRIVATE_SENTINEL" not in observed.model_dump_json()


def test_expired_success_is_not_current_connectivity(receipt):
    path, value, _ = receipt
    value["checked_at"] = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    path.write_text(json.dumps(value))
    _, observed = status.model_runtime()
    assert observed.status == "not_checked" and observed.checked_at and "expired" in observed.detail


def test_stub_has_no_measured_provider_check(receipt):
    _, _, settings = receipt
    settings.model_mode = "stub"
    assert status.model_runtime()[1].status == "not_checked"


def test_broker_catalog_is_part_of_recorded_profile(receipt, tmp_path):
    path, value, settings = receipt
    catalog = tmp_path / "broker.yaml"
    catalog.write_text("public catalog")
    settings.broker_config = catalog
    value["transport"] = "brokered"
    value["broker_config_sha256"] = hashlib.sha256(catalog.read_bytes()).hexdigest()
    path.write_text(json.dumps(value))
    assert status.model_runtime()[1].status == "passed"
    catalog.write_text("changed controller policy")
    assert status.model_runtime()[1].status == "not_checked"
