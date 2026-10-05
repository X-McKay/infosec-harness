"""An OpenAI-compatible backend never falls back to a default endpoint.

The OpenAI client sends requests to api.openai.com when given no base_url, so a catalogue entry
without an endpoint must refuse to resolve rather than quietly route prompts elsewhere.
"""

from types import SimpleNamespace

import pytest
import yaml

from infosec_harness.agents import models
from infosec_harness.resources import models_config


@pytest.fixture
def live(tmp_path, monkeypatch):
    path = tmp_path / "models.yaml"
    path.write_text(yaml.safe_dump({
        "default_backend": "gateway",
        "model_catalog": {"sonnet": {"gateway": "served-model"}},
        "backends": {"gateway": {"kind": "openai_compatible", "prices": {
            "served-model": {"input_per_mtok": 0, "output_per_mtok": 0}}}},
    }))
    settings = SimpleNamespace(model_mode="live", models_config=path, model_base_url=None)
    monkeypatch.setattr(models, "get_settings", lambda: settings)
    monkeypatch.delenv("HARNESS_MODEL_BACKEND", raising=False)
    models.load_models_config.cache_clear()
    yield settings
    models.load_models_config.cache_clear()


def test_the_packaged_catalogue_names_no_endpoint():
    packaged = yaml.safe_load(models_config().read_text())
    for name, backend in packaged["backends"].items():
        assert "base_url" not in backend, f"{name} ships an endpoint"


def test_an_unconfigured_endpoint_refuses_to_resolve(live):
    with pytest.raises(models.ModelEndpointUnconfigured, match="HARNESS_MODEL_BASE_URL"):
        models.resolve_config("context", "sonnet")


def test_the_operator_endpoint_fills_the_gap(live):
    live.model_base_url = "https://gateway.example/v1"
    models.load_models_config.cache_clear()
    resolved = models.resolve_config("context", "sonnet")
    assert resolved.endpoint == "https://gateway.example/v1"
    assert resolved.resolved_model == "gateway:served-model"
