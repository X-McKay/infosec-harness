"""Validation orchestration requires explicit inference and preserves output boundaries."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import load_script

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def validation():
    return load_script("service_validation")


@pytest.fixture
def deployment(validation, monkeypatch):
    from infosec_harness.operations import model_connectivity as model
    from infosec_harness.operations import readiness as runtime

    profile = {
        "source_commit": "a" * 40,
        "mode": "live",
        "transport": "direct",
        "model_config_sha256": "b" * 64,
        "broker_config_sha256": None,
        "model_names": ["local:configured-model"],
    }
    result = {
        "profile": profile,
        "checks": {
            name: {"status": "passed", "detail": "not forwarded"} for name in validation.CHECK_NAMES
        },
    }

    async def ready(**kwargs):
        return result

    async def no_inference(**kwargs):
        pytest.fail("implicit inference")

    monkeypatch.setattr(runtime, "check_runtime", ready)
    monkeypatch.setattr(model, "check_model", no_inference)
    monkeypatch.setattr(validation, "check_ui", lambda *a, **k: {"status": "passed"})
    api = SimpleNamespace(
        api_source_commit=profile["source_commit"],
        model_mode="live",
        assessment_transport="direct",
        model_names=profile["model_names"],
    )
    monkeypatch.setattr(validation, "api_profile", lambda *a: api)
    args = SimpleNamespace(
        offline=False,
        managed_worker=False,
        worker_hostname=None,
        timeout=15,
        api_url="http://api.test",
        web_url="http://web.test",
        expected_source_commit=None,
        model=False,
        model_timeout=90,
    )
    return args, result, api, model


async def test_readiness_never_calls_model_and_is_not_qualification(validation, deployment):
    report, receipt = await validation.validate(deployment[0])
    assert report["status"] == "passed" and receipt is None
    assert report["checks"]["model_connectivity"]["status"] == "not_checked"
    assert report["qualification"] == "not_checked"
    assert report["finding_submissions"] == report["recovery_actions"] == 0


async def test_offline_is_incomplete_and_contacts_nothing(validation, deployment, monkeypatch):
    args = deployment[0]
    args.offline = True
    args.model = True
    monkeypatch.setattr(validation, "check_ui", lambda *a, **k: pytest.fail("offline HTTP"))
    report, receipt = await validation.validate(args)
    assert report["status"] == "not_checked" and receipt is None
    assert all(row["status"] == "not_checked" for row in report["checks"].values())


@pytest.mark.parametrize("drift", ["source", "names", "mode", "transport", "missing_hash"])
async def test_profile_drift_prevents_inference(validation, deployment, drift):
    args, result, api, _ = deployment
    args.model = True
    if drift == "source":
        api.api_source_commit = "c" * 40
    elif drift == "names":
        api.model_names = ["different:model"]
    elif drift == "mode":
        api.model_mode = "stub"
    elif drift == "transport":
        api.assessment_transport = "brokered"
    else:
        result["profile"]["model_config_sha256"] = None
    report, receipt = await validation.validate(args)
    assert report["status"] in {"failed", "not_checked"}
    assert report["checks"]["model_connectivity"]["status"] == "not_checked" and receipt is None


def receipt(profile):
    return {
        "version": 1,
        "checked_at": datetime.now(UTC).isoformat(),
        **{
            k: profile[k]
            for k in (
                "source_commit",
                "mode",
                "transport",
                "model_config_sha256",
                "broker_config_sha256",
            )
        },
        "status": "passed",
    }


async def test_explicit_single_request_returns_existing_receipt_contract(
    validation, deployment, monkeypatch
):
    args, result, _, model = deployment
    args.model = True
    value = receipt(result["profile"])
    calls = []

    async def infer(**kwargs):
        calls.append(kwargs)
        return {"status": "passed", "requests": 1, "receipt": value}

    monkeypatch.setattr(model, "check_model", infer)
    report, observed = await validation.validate(args)
    assert report["status"] == "passed" and report["model_requests"] == 1 and observed == value
    assert calls == [{"timeout": 90}]


@pytest.mark.parametrize(
    "bad",
    ["extra", "bool_version", "source", "hash", "future", "naive", "expired", "bool_requests"],
)
async def test_invalid_child_receipt_cannot_be_published(validation, deployment, monkeypatch, bad):
    args, result, _, model = deployment
    args.model = True
    value = receipt(result["profile"])
    requests = 1
    if bad == "extra":
        value["private"] = "PRIVATE_SENTINEL"
    elif bad == "bool_version":
        value["version"] = True
    elif bad == "source":
        value["source_commit"] = "c" * 40
    elif bad == "hash":
        value["model_config_sha256"] = "c" * 64
    elif bad == "future":
        value["checked_at"] = (datetime.now(UTC) + timedelta(minutes=1)).isoformat()
    elif bad == "naive":
        value["checked_at"] = datetime.now().isoformat()
    elif bad == "expired":
        value["checked_at"] = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    else:
        requests = True

    async def infer(**kwargs):
        return {"status": "passed", "requests": requests, "receipt": value}

    monkeypatch.setattr(model, "check_model", infer)
    report, observed = await validation.validate(args)
    assert observed is None and report["checks"]["model_connectivity"]["status"] == "failed"
    assert "PRIVATE_SENTINEL" not in json.dumps(report)


async def test_transport_errors_are_closed_and_usage_stays_unknown(
    validation, deployment, monkeypatch
):
    args, _, _, model = deployment
    args.model = True

    async def infer(**kwargs):
        return {"status": "failed", "requests": None, "detail": "PRIVATE_SENTINEL password=secret"}

    monkeypatch.setattr(model, "check_model", infer)
    report, observed = await validation.validate(args)
    assert report["model_requests"] is None and observed is None and report["status"] == "failed"
    assert "PRIVATE_SENTINEL" not in json.dumps(report)


def test_atomic_outputs_are_private_and_reject_symlinks(validation, tmp_path):
    path = tmp_path / "report.json"
    validation.private_json(path, {"status": "passed"})
    assert json.loads(path.read_text()) == {"status": "passed"}
    assert path.stat().st_mode & 0o777 == 0o600
    link = tmp_path / "receipt.json"
    link.symlink_to(path)
    with pytest.raises(ValueError):
        validation.private_json(link, {"status": "failed"})
    assert json.loads(path.read_text()) == {"status": "passed"}


def test_cli_requires_model_for_receipt_and_rejects_normalized_path_collision(validation, tmp_path):
    with pytest.raises(SystemExit) as e:
        validation.main(["--connectivity-receipt", str(tmp_path / "receipt")])
    assert e.value.code == 2
    with pytest.raises(SystemExit) as e:
        validation.main(
            [
                "--model",
                "--report",
                str(tmp_path / "report"),
                "--connectivity-receipt",
                str(tmp_path / "child/../report"),
            ]
        )
    assert e.value.code == 2


def test_managed_exec_preserves_running_environment_and_rejects_contradictory_success(
    validation, monkeypatch, tmp_path
):
    monkeypatch.setattr(validation, "ROOT", tmp_path)
    shim = tmp_path / ".harness/bin/docker"
    shim.parent.mkdir(parents=True)
    shim.touch()
    monkeypatch.setenv("COMPOSE_PROJECT_NAME", "harness-test")
    commands = []

    def execute(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=1, stdout=b'{"status":"passed"}')

    monkeypatch.setattr(validation.subprocess, "run", execute)
    with pytest.raises(ValueError):
        validation.managed_check("model-connectivity", ["--model"], 90)
    command = commands[0]
    assert command[command.index("exec") :] == [
        "exec",
        "-T",
        "worker",
        "harness",
        "ops",
        "model-connectivity",
        "--model",
    ]
    assert not any(item in command for item in ("up", "restart", "--env", "-e"))


def test_offline_main_report_and_failed_check_do_not_overwrite_receipt(
    validation, tmp_path, monkeypatch
):
    target = tmp_path / "receipt.json"
    target.write_text("retained evidence")
    report = tmp_path / "report.json"
    assert (
        validation.main(
            ["--offline", "--model", "--report", str(report), "--connectivity-receipt", str(target)]
        )
        == 2
    )
    assert target.read_text() == "retained evidence"
    assert json.loads(report.read_text())["status"] == "not_checked"


def test_launcher_validation_has_no_startup_seed_or_restart_path():
    text = (ROOT / "dev").read_text()
    section = text.split("  validate)\n", 1)[1].split("    ;;", 1)[0]
    assert "service_validation.py --managed-worker" in section
    assert all(
        value not in section for value in ("setup", "compose up", "compose restart", "smoke_stack")
    )


def test_unsafe_output_is_rejected_before_explicit_inference(validation, tmp_path, monkeypatch):
    target = tmp_path / "existing"
    target.write_text("existing evidence")
    link = tmp_path / "receipt"
    link.symlink_to(target)

    async def unexpected(args):
        pytest.fail("invalid output authorized a request")

    monkeypatch.setattr(validation, "validate", unexpected)
    with pytest.raises(SystemExit) as exc:
        validation.main(["--model", "--connectivity-receipt", str(link)])
    assert exc.value.code == 2 and target.read_text() == "existing evidence"


def test_receipt_publication_failure_is_retained_in_report(validation, tmp_path, monkeypatch):
    report = tmp_path / "report.json"
    receipt = tmp_path / "receipt.json"

    async def passed(args):
        return {"status": "passed", "checks": {}}, {"status": "passed"}

    original = validation.private_json

    def publish(path, value):
        if path == receipt:
            raise OSError("PRIVATE_SENTINEL")
        original(path, value)

    monkeypatch.setattr(validation, "validate", passed)
    monkeypatch.setattr(validation, "private_json", publish)
    assert (
        validation.main(
            ["--model", "--report", str(report), "--connectivity-receipt", str(receipt)]
        )
        == 1
    )
    retained = json.loads(report.read_text())
    assert (
        retained["status"] == "failed"
        and retained["checks"]["receipt_publication"]["status"] == "failed"
    )
    assert "PRIVATE_SENTINEL" not in json.dumps(retained)


@pytest.mark.parametrize("option", ["--report", "--connectivity-receipt"])
def test_non_directory_output_ancestor_refused_before_inference(
    validation, tmp_path, monkeypatch, option
):
    existing = tmp_path / "existing-file"
    existing.write_text("retained evidence")

    async def unexpected(args):
        pytest.fail("unusable output authorized inference")

    monkeypatch.setattr(validation, "validate", unexpected)
    with pytest.raises(SystemExit) as exc:
        validation.main(["--model", option, str(existing / "new" / "result.json")])
    assert exc.value.code == 2
    assert existing.read_text() == "retained evidence"
