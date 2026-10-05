"""Eval build adapters preserve the production sandbox-image dependency."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from infosec_harness.agents.capabilities import run_in_sandbox
from infosec_harness.evals.adapters import build_repair_adapter, partial_build_adapter
from infosec_harness.sandbox import docker
from infosec_harness.sandbox.process import ProcessResult


def _case(image: str = "perl:5.40") -> dict:
    return {
        "name": "sandbox-image-binding",
        "payload": {
            "failed_spec": {
                "base_image": image,
                "system_packages": [],
                "install_commands": [],
                "test_command": "perl {test_file}",
            }
        },
        "expect_mentions": "DBD::SQLite",
        "expected": "addressed",
    }


@pytest.mark.parametrize("adapter", [build_repair_adapter, partial_build_adapter])
async def test_build_adapter_sandbox_tool_receives_failed_specs_image(adapter, monkeypatch):
    seen = []

    async def fake_run_shell(image, command, **kwargs):
        seen.append((image, command, kwargs))
        return ProcessResult(0, "available", "", False, 0.01)

    monkeypatch.setattr(docker, "run_shell", fake_run_shell)
    deps = adapter(_case()).deps
    ctx = SimpleNamespace(deps=deps, run_id="eval-run", tool_call_id="probe-1")

    result = await run_in_sandbox(ctx, "perl -MDBI -e 1")

    assert seen == [
        (
            "perl:5.40",
            "perl -MDBI -e 1",
            {"timeout": 180, "idempotency_key": "eval-run:probe-1:v1"},
        )
    ]
    assert "[exit code: 0]" in result


@pytest.mark.parametrize("adapter", [build_repair_adapter, partial_build_adapter])
@pytest.mark.parametrize(
    "failed_spec",
    [None, {}, {"base_image": "", "test_command": "perl {test_file}"}],
)
def test_build_adapter_rejects_missing_or_malformed_failed_spec(adapter, failed_spec):
    case = _case()
    case["payload"]["failed_spec"] = failed_spec

    with pytest.raises(ValueError, match=r"failed_spec.*(valid EnvironmentSpec|must not be blank)"):
        adapter(case)
