"""Explicit operator closure cannot imply inference, relax evidence or hide partial writes."""

from types import SimpleNamespace

import pytest
from conftest import load_script


@pytest.fixture
def closure():
    return load_script("broker_hold_closure")


async def test_dry_run_selects_only_planner(closure, monkeypatch):
    calls = []

    async def plan(op):
        calls.append(op)
        return {"status": "planned"}

    async def mutate(op):
        pytest.fail("Dry run attempted accounting write")

    monkeypatch.setattr(closure, "plan_closure", plan)
    monkeypatch.setattr(closure, "close_unknown", mutate)
    report = await closure.execute(
        SimpleNamespace(operations=["first", "second"], source_commit="a" * 40), apply=False
    )
    assert calls == ["first", "second"]
    assert report["status"] == "passed"
    assert (
        report["provider_calls"]
        == report["request_row_mutations"]
        == report["lease_mutations"]
        == 0
    )
    assert report["qualification"] == "not_checked"


async def test_all_preflighted_before_first_write_and_partial_failure_retained(
    closure, monkeypatch
):
    calls = []

    async def plan(op):
        calls.append(("plan", op))
        return {"status": "planned"}

    async def mutate(op):
        calls.append(("write", op))
        if op == "second":
            raise ValueError("PRIVATE_SENTINEL")
        return {"status": "applied", "root_id": op}

    monkeypatch.setattr(closure, "plan_closure", plan)
    monkeypatch.setattr(closure, "close_unknown", mutate)
    report = await closure.execute(
        SimpleNamespace(operations=["first", "second"], source_commit="a" * 40), apply=True
    )
    assert calls == [("plan", "first"), ("plan", "second"), ("write", "first"), ("write", "second")]
    assert report["status"] == "failed" and report["partial_application"] is True
    assert report["operations"] == [{"status": "applied", "root_id": "first"}]
    assert "PRIVATE_SENTINEL" not in str(report)


@pytest.mark.parametrize("problem", ["existing", "symlink", "ancestor-file"])
def test_unusable_report_refuses_closure_before_loading_evidence(
    closure, monkeypatch, tmp_path, problem
):
    existing = tmp_path / "existing"
    existing.write_text("retained audit")
    report = existing
    if problem == "symlink":
        report = tmp_path / "link"
        report.symlink_to(existing)
    elif problem == "ancestor-file":
        report = existing / "report.json"
    monkeypatch.setattr(
        closure, "frozen_manifest", lambda *a: pytest.fail("Unusable output passed preflight")
    )
    assert (
        closure.main(
            [
                "--manifest",
                str(tmp_path / "manifest"),
                "--manifest-sha256",
                "a" * 64,
                "--report",
                str(report),
                "--apply",
            ]
        )
        == 1
    )
    assert existing.read_text() == "retained audit"


def test_manifest_byte_pin_checked_before_parsing_or_closure(closure, monkeypatch, tmp_path):
    manifest = tmp_path / "manifest"
    manifest.write_text('{"private":"source"}')
    with pytest.raises(ValueError, match="Manifest bytes changed"):
        closure.frozen_manifest(manifest, "a" * 64)


def test_output_creation_failure_prevents_any_accounting_write(closure, monkeypatch, tmp_path):
    monkeypatch.setattr(
        closure.tempfile, "mkstemp", lambda **kw: (_ for _ in ()).throw(OSError("PRIVATE_SENTINEL"))
    )
    monkeypatch.setattr(
        closure,
        "frozen_manifest",
        lambda *a: pytest.fail("Publication creation failure reached closure"),
    )
    report = tmp_path / "report.json"
    assert (
        closure.main(
            [
                "--manifest",
                str(tmp_path / "manifest"),
                "--manifest-sha256",
                "a" * 64,
                "--report",
                str(report),
                "--apply",
            ]
        )
        == 1
    )
    assert not report.exists()


def test_raced_report_is_not_overwritten_and_applied_accounting_is_reported(
    closure, monkeypatch, tmp_path, capsys
):
    destination = tmp_path / "report.json"
    monkeypatch.setattr(closure, "frozen_manifest", lambda *a: object())

    async def applied(manifest, *, apply):
        assert apply
        return {"status": "passed", "operations": [{"status": "applied"}], "provider_calls": 0}

    monkeypatch.setattr(closure, "execute", applied)

    def raced(source, target):
        destination.write_text("other operator audit")
        raise FileExistsError("PRIVATE_SENTINEL")

    monkeypatch.setattr(closure.os, "link", raced)
    assert (
        closure.main(
            [
                "--manifest",
                str(tmp_path / "manifest"),
                "--manifest-sha256",
                "a" * 64,
                "--report",
                str(destination),
                "--apply",
            ]
        )
        == 1
    )
    import json

    report = json.loads(capsys.readouterr().out)
    assert report["accounting_may_have_been_applied"] is True
    assert report["operations"] == [{"status": "applied"}]
    assert "PRIVATE_SENTINEL" not in str(report)
    assert destination.read_text() == "other operator audit"
    assert (tmp_path / ("." + destination.name + ".claim")).exists() is False
    assert report["retained_report_file"]
