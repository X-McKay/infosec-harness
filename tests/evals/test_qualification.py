"""Qualification report shape with a fake runtime. Only `harness qualify` is native evidence."""

import asyncio
import json
from types import SimpleNamespace

import pytest

from infosec_harness.config import Settings
from infosec_harness.contracts import WorkerIdentity
from infosec_harness.evals import qualification

SOURCE = b"native-roundtrip\n"
IDENTITY = WorkerIdentity(
    fingerprint="a" * 64, code_sha256="b" * 64, config_sha256="c" * 64, dependencies={}
)


class Runtime:
    """Records calls; ``fail`` names one (method, profile) step that raises or misbehaves."""

    def __init__(self, calls, fail=None):
        self.calls, self.fail = calls, fail or (None, None)
        self.executions = 0

    def _maybe_fail(self, method, profile):
        if self.fail == (method, profile):
            raise RuntimeError(f"fixture {method} failed in {profile}")

    async def create(self, run_id, *, profile):
        self.calls.append(("create", profile))
        self._maybe_fail("create", profile)
        if self.fail == ("reuse", profile) and ("create", profile) in self.calls[:-1]:
            return SimpleNamespace(id=profile + "-replaced")
        return SimpleNamespace(id=profile)

    async def upload(self, sandbox, source, destination):
        assert source.is_dir()
        assert (source / "input.txt").read_bytes() == SOURCE
        self.calls.append(("upload", sandbox.id, destination))

    async def execute(self, sandbox, command, **kwargs):
        assert "/workspace/qualification/input.txt" in command[-1]
        self.calls.append(("execute", sandbox.id))
        self.executions += 1
        if self.fail == ("cancel", sandbox.id):
            raise asyncio.CancelledError
        stdout = SOURCE.decode()
        if self.fail == ("roundtrip", sandbox.id):
            stdout = "attacker text"
        if self.fail == ("saved", sandbox.id) and self.executions % 2 == 0:
            stdout += "changed"
        return SimpleNamespace(exit_code=0, stdout=stdout, output_truncated=False)

    async def close(self, sandbox):
        self.calls.append(("close", sandbox.id))
        self._maybe_fail("close", sandbox.id)

    async def close_run(self, run_id):
        self.calls.append(("close_run", run_id))
        self._maybe_fail("close_run", None)


@pytest.fixture
def harness(tmp_path, monkeypatch):
    config = tmp_path / "runtime.json"
    config.write_text("{}")
    settings = Settings(openshell_config=config)
    calls = []

    def run(fail=None):
        runtime = Runtime(calls, fail)
        monkeypatch.setattr(qualification, "OpenShell", lambda config: runtime)
        return qualification.qualify_runtime(tmp_path / f"report-{len(calls)}.json", settings)

    monkeypatch.setattr(qualification.OpenShellConfig, "load", lambda path: None)
    monkeypatch.setattr(qualification, "worker_identity", lambda settings: IDENTITY)
    return SimpleNamespace(run=run, calls=calls, tmp_path=tmp_path)


async def test_runtime_qualification_uses_actual_directory_upload_contract(harness):
    result = await harness.run()
    assert result["status"] == "passed"
    uploads = [call[1:] for call in harness.calls if call[0] == "upload"]
    assert uploads == [
        ("workspace", "/workspace/qualification"),
        ("probe", "/workspace/qualification"),
    ]
    closes = [call[1] for call in harness.calls if call[0] in {"close", "close_run"}]
    assert closes == ["workspace", "workspace", "probe", "probe", result["run_id"]]
    assert result["model_calls"] == 0 and result["model_quality"] == "not_checked"
    assert result["profiles"] == {
        profile: dict.fromkeys(qualification.CHECKS, "passed")
        for profile in qualification.PROFILES
    }
    assert result["cleanup"] == "passed"
    # Code provenance: the adapter code and isolation configuration that were exercised.
    assert result["generation"] == "v11"
    assert result["worker_identity"] == IDENTITY.model_dump()


@pytest.mark.parametrize(
    ("fail", "profile", "check", "cleanup"),
    [
        (("create", "workspace"), "workspace", "boundary", "not_applicable"),
        (("create", "probe"), "probe", "boundary", "passed"),
        (("roundtrip", "workspace"), "workspace", "roundtrip", "passed"),
        (("saved", "probe"), "probe", "saved_operation", "passed"),
        (("reuse", "workspace"), "workspace", "sandbox_reuse", "passed"),
        (("close", "probe"), "probe", "cleanup", "passed"),
    ],
)
async def test_failed_check_is_named_and_unreached_checks_stay_unchecked(
    harness, fail, profile, check, cleanup
):
    result = await harness.run(fail)
    assert result["status"] == "failed"
    assert (result["failed_profile"], result["failed_check"]) == (profile, check)
    assert result["error_type"] == "RuntimeError"
    assert profile in result["error"] and len(result["error"]) <= qualification.ERROR_CHARS
    assert "attacker text" not in result["error"]  # Sandbox output never enters the report.
    # Both profiles are always present; checks before the failure passed, after it unchecked.
    order = [(p, c) for p in qualification.PROFILES for c in qualification.CHECKS]
    failed_at = order.index((profile, check))
    for index, (p, c) in enumerate(order):
        expected = "passed" if index < failed_at else "failed" if index == failed_at else (
            "not_checked")
        assert result["profiles"][p][c] == expected, (p, c)
    # Owned cleanup is always reconciled; it is vacuous only if no sandbox was returned.
    assert harness.calls[-1] == ("close_run", result["run_id"])
    assert result["cleanup"] == cleanup
    persisted = json.loads(next(harness.tmp_path.glob("report-*.json")).read_text())
    assert persisted == result


async def test_failed_owned_cleanup_fails_qualification_with_its_reason(harness):
    result = await harness.run(("close_run", None))
    assert result["status"] == "failed" and result["cleanup"] == "failed"
    assert result["cleanup_error_type"] == "RuntimeError"
    assert result["cleanup_error"] == "fixture close_run failed in None"
    # Every profile check still passed; only the final reconcile failed.
    assert all(status == "passed" for row in result["profiles"].values()
               for status in row.values())


async def test_cancellation_is_recorded_and_still_reconciles_owned_cleanup(harness):
    with pytest.raises(asyncio.CancelledError):
        await harness.run(("cancel", "probe"))
    persisted = json.loads(next(harness.tmp_path.glob("report-*.json")).read_text())
    assert persisted["status"] == "cancelled"
    assert (persisted["cancelled_profile"], persisted["cancelled_check"]) == ("probe", "roundtrip")
    assert persisted["profiles"]["probe"]["roundtrip"] == "not_checked"
    assert persisted["cleanup"] == "passed"
    assert harness.calls[-1] == ("close_run", persisted["run_id"])
