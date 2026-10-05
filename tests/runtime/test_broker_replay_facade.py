"""Broker-mode registration keeps historical intake generations read-only."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

from infosec_harness.inference.profiles import registered_agents

ROOT = Path(__file__).resolve().parents[2]


def _broker_configuration(directory: Path) -> tuple[Path, Path]:
    models = {
        "backends": {
            "qualification": {
                "transport": "brokered",
                "kind": "openai_compatible",
                "base_url": "https://provider.example/v1",
                "prices": {
                    "qualification-model": {
                        "input_per_mtok": 1.0,
                        "output_per_mtok": 1.0,
                    }
                },
            }
        },
        "default_backend": "qualification",
        "model_catalog": {
            tier: {"qualification": "qualification-model"} for tier in ("sonnet", "opus", "haiku")
        },
        "model_policies": {
            "balanced-v1": "sonnet",
            "reasoning-v1": "opus",
            "fast-v1": "haiku",
        },
    }
    limits = {
        "max_requests": 100,
        "max_input_tokens": 1_000_000,
        "max_output_tokens": 1_000_000,
        "max_cost_usd": 100.0,
        "max_duration_seconds": 3600.0,
    }
    broker = {
        "version": 1,
        "enabled": True,
        "controller": {
            "url": "https://broker.example",
            "hmac_env": "BROKER_TEST_HMAC_KEY",
        },
        "profiles": {
            "qualification": {
                "backend_name": "qualification",
                "endpoint": "https://provider.example/v1",
                "provider_binding": "qualification-provider",
                "provider_env": "QUALIFICATION_PROVIDER",
                "ledger_origin": "https://broker.example",
                "ledger_profile": "qualification-ledger",
                "executor_image": "sha256:" + "1" * 64,
                "supervisor_image": "sha256:" + "2" * 64,
                "approved_policy": {"version": 1, "network_policies": {}},
                "inspection": [],
            }
        },
        "agent_profiles": {agent: "qualification" for agent in registered_agents()},
        "root_limits": limits,
        "agent_limits": {agent: limits for agent in registered_agents()},
    }
    models_path = directory / "models.yaml"
    broker_path = directory / "broker.yaml"
    models_path.write_text(yaml.safe_dump(models), encoding="utf-8")
    broker_path.write_text(yaml.safe_dump(broker), encoding="utf-8")
    return models_path, broker_path


def test_durable_import_keeps_retained_intake_generations_replay_only(tmp_path: Path) -> None:
    models_path, broker_path = _broker_configuration(tmp_path)
    child = r"""
import asyncio, json
from infosec_harness.agents.durable import INTAKE_GENERATIONS
from infosec_harness.agents import models as model_factory
from infosec_harness.agents.registry import _resolve_agent_model
from infosec_harness.agents.replay_only import ReplayOnlyModel, RetainedModelUnavailable
from infosec_harness.inference.unbound import UnboundBrokerModel
from infosec_harness.inference.transport import BrokerModel
from infosec_harness.inference.protocol import ReservationBinding
from pydantic_ai.models import ModelRequestParameters
import time

assert set(INTAKE_GENERATIONS) == {"bare", "quoted", "atomic_v3", "atomic"}
for key in ("bare", "quoted"):
    generation = INTAKE_GENERATIONS[key]
    assert generation.config.model.broker_contract is None

def unexpected_resolver(*args, **kwargs):
    raise AssertionError("retained intake reached a live model resolver")
resolve = model_factory.resolve
resolve_intake_atomic = model_factory.resolve_intake_atomic
model_factory.resolve = unexpected_resolver
model_factory.resolve_intake_atomic = unexpected_resolver

async def unexpected_unbound_request(*args, **kwargs):
    raise AssertionError("retained intake reached its unbound model request")
UnboundBrokerModel.request = unexpected_unbound_request

async def verify_retained():
    for key in ("bare", "quoted"):
        generation = INTAKE_GENERATIONS[key]
        model = _resolve_agent_model(
            "intake", "sonnet", durable=True, atomic_intake=False,
            replay_only=True, deps=None,
        )
        assert isinstance(model, ReplayOnlyModel)
        assert isinstance(model.wrapped, UnboundBrokerModel)
        try:
            await model.request([], None, ModelRequestParameters())
        except RetainedModelUnavailable:
            pass
        else:
            raise AssertionError("retained model request was not denied")

asyncio.run(verify_retained())
model_factory.resolve = resolve
model_factory.resolve_intake_atomic = resolve_intake_atomic

atomic = INTAKE_GENERATIONS["atomic"]
contract = atomic.config.model.broker_contract
assert contract is not None and contract.atomic_intake is True
binding = ReservationBinding(
    root_id="root-test", run_id="run-test", invocation_id="invocation-test",
    operation_id="operation-test", agent="intake", contract_digest=contract.digest,
    expires_at=time.time() + 300,
)
model = _resolve_agent_model(
    "intake", "sonnet", durable=True, atomic_intake=True,
    replay_only=False,
    deps=type("Deps", (), {"broker_binding": binding, "broker_contract": contract})(),
)
assert isinstance(model, BrokerModel)
assert model.contract == contract and model.contract.atomic_intake is True
print(json.dumps({"retained": ["bare", "quoted"], "retained_contracts": [False, False],
                  "retained_requests_denied": True, "atomic_contract": True,
                  "atomic_model": type(model).__name__}, sort_keys=True))
"""
    env = os.environ.copy()
    env.update(
        HARNESS_MODEL_MODE="live",
        HARNESS_MODELS_CONFIG=str(models_path),
        HARNESS_BROKER_CONFIG=str(broker_path),
        PYTHONPATH=str(ROOT / "src"),
        PYDANTIC_AI_NO_BANNER="1",
    )
    result = subprocess.run(
        [sys.executable, "-c", child],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    assert json.loads(result.stdout) == {
        "atomic_contract": True,
        "atomic_model": "BrokerModel",
        "retained": ["bare", "quoted"],
        "retained_contracts": [False, False],
        "retained_requests_denied": True,
    }
