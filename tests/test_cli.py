import json
import logging
import re

import pytest
import typer
from fastapi import HTTPException
from temporalio.service import RPCError, RPCStatusCode
from typer.testing import CliRunner

from infosec_harness import api, cli, config
from infosec_harness.evals import cohort, qualification


@pytest.fixture(autouse=True)
def restore_logging():
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)


def invoke(*args):
    config.reset_settings()  # One CLI process per invocation: settings bind once.
    return CliRunner().invoke(cli.app, list(args))


@pytest.fixture
def evaluations(monkeypatch):
    calls = []
    results = []

    async def evaluate(manifest, output, settings, **options):
        calls.append((output, settings, options))
        result = results.pop(0) if results else {"status": "passed", "kind": "cohort"}
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(cohort, "evaluate_corpus", evaluate)
    return calls, results


def test_settings_file_is_exact_and_not_merged(tmp_path, monkeypatch, evaluations):
    calls, results = evaluations
    monkeypatch.setenv("HARNESS_MODEL_NAME", "from-env")
    monkeypatch.setenv("HARNESS_TEMPORAL_NAMESPACE", "from-env")
    frozen = tmp_path / "settings.json"
    frozen.write_text(json.dumps({"model_name": "from-file"}))
    results.append({"status": "completed", "kind": "diagnostic"})
    invoked = invoke(
        "--settings", str(frozen), "eval", "--allow-inference", "--case", "a", "--case", "b",
        "--keep-going", "--owned-worker", "--parallel", "3",
    )
    assert invoked.exit_code == 0, invoked.output  # A completed diagnostic ran as asked.
    output, settings, options = calls[0]
    assert settings is config.get_settings()
    assert settings.model_name == "from-file"
    assert settings.temporal_namespace == "default"  # Not merged from the environment.
    assert options == {"names": ("a", "b"), "owned_worker": True, "keep_going": True,
                       "parallel": 3}
    assert re.fullmatch(r"\.harness/reports/diagnostic-\d{8}T\d{6}Z\.json", output.as_posix())


def test_environment_is_the_default_and_reports_are_timestamped(monkeypatch, evaluations):
    calls, _results = evaluations
    monkeypatch.setenv("HARNESS_MODEL_NAME", "from-env")
    monkeypatch.setenv("HARNESS_REPORTS_DIR", "elsewhere")
    assert invoke("eval", "--allow-inference").exit_code == 0
    output, settings, options = calls[0]
    assert settings.model_name == "from-env"
    assert re.fullmatch(r"elsewhere/model-\d{8}T\d{6}Z\.json", output.as_posix())
    assert options["names"] == ()


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        (None, "No such file or directory"),
        ("{not json", "Invalid JSON"),
        (json.dumps({"model_nam": "x"}), "model_nam: Extra inputs are not permitted"),
        (json.dumps({"temporal_tls_client_cert": "cert.pem"}), "configured together"),
    ],
)
def test_settings_file_errors_name_the_path(tmp_path, evaluations, document, expected):
    calls, _results = evaluations
    path = tmp_path / "settings.json"
    if document is not None:
        path.write_text(document)
    invoked = invoke("--settings", str(path), "eval", "--allow-inference")
    assert invoked.exit_code == 2, invoked.output
    assert calls == []
    config.reset_settings()
    with pytest.raises(typer.BadParameter) as raised:
        cli.configure(settings=path)
    assert raised.value.message.startswith(f"{path}: ")
    assert expected in raised.value.message


def test_settings_file_errors_never_echo_values(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"temporal_api_kye": "s3cret-value"}))
    invoked = invoke("--settings", str(path), "qualify")
    assert invoked.exit_code == 2
    assert "temporal_api_kye" in invoked.output and "s3cret-value" not in invoked.output


def test_settings_bind_once_per_process(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text("{}")
    config.reset_settings()
    config.get_settings()
    with pytest.raises(RuntimeError, match="already in use; refusing to rebind"):
        config.use_settings_file(path)


def test_eval_requires_allow_inference(evaluations):
    calls, _results = evaluations
    assert invoke("eval").exit_code == 2
    assert calls == []


@pytest.mark.parametrize(
    ("result", "code"),
    [
        ({"status": "passed", "kind": "cohort"}, 0),
        ({"status": "completed", "kind": "diagnostic"}, 0),
        ({"status": "failed", "kind": "diagnostic"}, 1),
        ({"status": "completed", "kind": "cohort"}, 1),  # A cohort passes only on its gates.
        ({"status": "not_checked", "kind": "cohort"}, 1),
        ({"kind": "cohort"}, 1),
        (RuntimeError("Temporal connection refused"), 3),
    ],
)
def test_eval_exit_codes_separate_gates_from_crashes(evaluations, result, code):
    _calls, results = evaluations
    results.append(result)
    invoked = invoke("eval", "--allow-inference")
    assert invoked.exit_code == code, invoked.output
    if code == 3:
        assert invoked.stderr.splitlines()[-1] == "error: RuntimeError: Temporal connection refused"
        assert invoked.stdout == ""
    else:
        assert json.loads(invoked.stdout) == result


def test_qualify_and_replay_exit_codes(tmp_path, monkeypatch):
    outcomes = {"qualify": {"status": "failed"}, "replay": {"status": "passed"}}
    replays = []

    async def qualify_runtime(output):
        return outcomes["qualify"]

    async def replay_history(run_id, settings):
        replays.append(run_id)
        return outcomes["replay"]

    monkeypatch.setattr(qualification, "qualify_runtime", qualify_runtime)
    monkeypatch.setattr(cohort, "replay_history", replay_history)
    assert invoke("qualify").exit_code == 1
    outcomes["qualify"] = {"status": "passed"}
    assert invoke("qualify").exit_code == 0
    output = tmp_path / "replay.json"
    assert invoke("replay", "investigate-v11-a", "--output", str(output)).exit_code == 0
    assert json.loads(output.read_text()) == {"status": "passed"}
    # An existing report is refused before the replay runs.
    refused = invoke("replay", "investigate-v11-b", "--output", str(output))
    assert refused.exit_code == 2
    assert replays == ["investigate-v11-a"]
    outcomes["replay"] = {"status": "failed"}
    assert invoke("replay", "investigate-v11-c").exit_code == 1


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        (HTTPException(404, "Investigation not found"), "error: Investigation not found"),
        (
            RPCError("raw", RPCStatusCode.DEADLINE_EXCEEDED, b""),
            "error: No worker answered within 10s: is `harness worker` serving task queue "
            "investigate-v11?",
        ),
        (RPCError("raw", RPCStatusCode.UNAVAILABLE, b""), "error: Workflow service unavailable "
         "(UNAVAILABLE)"),
    ],
)
def test_report_and_submit_print_one_operator_line(tmp_path, monkeypatch, failure, message):
    async def connect(settings=None):
        return object()

    async def fail(*args):
        raise failure

    monkeypatch.setattr(api, "connect", connect)
    monkeypatch.setattr(api, "run", fail)
    monkeypatch.setattr(api, "submit", fail)
    finding = tmp_path / "finding.json"
    finding.write_text(json.dumps({"title": "SQLi", "repo_url": "repo"}))
    for args in (("report", "investigate-v11-a"), ("submit", str(finding))):
        invoked = invoke(*args)
        assert invoked.exit_code == 3, invoked.output
        assert invoked.stderr == message + "\n"
        assert invoked.stdout == ""


def test_submit_rejects_an_unreadable_finding_before_connecting(tmp_path, monkeypatch):
    connected = []

    async def connect(settings=None):
        connected.append(True)

    monkeypatch.setattr(api, "connect", connect)
    assert invoke("submit", str(tmp_path / "missing.json")).exit_code == 2
    invalid = tmp_path / "finding.json"
    invalid.write_text(json.dumps({"title": ""}))
    invoked = invoke("submit", str(invalid))
    assert invoked.exit_code == 2
    assert "repo_url: Field required" in " ".join(invoked.output.split())
    assert connected == []


def test_logging_is_one_stderr_handler_at_the_configured_level(monkeypatch):
    monkeypatch.setenv("HARNESS_LOG_LEVEL", "DEBUG")
    config.reset_settings()
    cli.configure_logging()
    cli.configure_logging()
    root = logging.getLogger()
    ours = [handler for handler in root.handlers if handler.get_name() == cli.HANDLER_NAME]
    assert len(ours) == 1
    assert ours[0].formatter._fmt == "%(asctime)s %(levelname)s %(name)s %(message)s"
    assert root.level == logging.DEBUG
    assert logging.getLogger("httpx").level == logging.WARNING
