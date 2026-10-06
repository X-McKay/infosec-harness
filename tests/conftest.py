"""Deterministic tests use fake models and isolated state; Temporal tests use a real server."""
import importlib
import os
import shutil
import sys
import tomllib
from pathlib import Path

import pydantic_ai.models
import pytest

from infosec_harness.config import reset_settings

ROOT = Path(__file__).resolve().parents[1]
pydantic_ai.models.ALLOW_MODEL_REQUESTS = False


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path, monkeypatch):
    for key in tuple(os.environ):
        if key.startswith("HARNESS_") and not key.startswith("HARNESS_TEST_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("HARNESS_WORKSPACE_DIR", str(tmp_path / "workspace"))
    reset_settings()
    yield
    reset_settings()


@pytest.fixture
def temporal_cli():
    found = shutil.which("temporal")
    version = tomllib.loads((ROOT / ".mise.toml").read_text())["tools"]["http:temporal"]["version"]
    managed = ROOT / ".harness/mise/installs/http-temporal" / version / "temporal"
    if not found and managed.is_file():
        found = str(managed)
    if not found:
        if os.environ.get("HARNESS_TEST_REQUIRE_TEMPORAL") == "1":
            pytest.fail("Pinned Temporal CLI is required for durable qualification")
        pytest.skip("Pinned Temporal CLI unavailable; durable qualification not checked")
    return found


def load_script(name: str):
    """Import one trusted repository utility without shadowing installed packages."""
    scripts = ROOT / "scripts"
    if str(scripts) not in sys.path:
        sys.path.append(str(scripts))
    module = importlib.import_module(name)
    if Path(module.__file__).resolve() != scripts / f"{name}.py":
        raise ImportError(f"Unexpected utility module: {name}")
    return module
