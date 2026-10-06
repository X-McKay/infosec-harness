import asyncio
import hashlib
import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from infosec_harness import cli, config
from infosec_harness.evals import cohort


def test_settings_file_is_exact_and_reports_are_timestamped(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_explicit", None)
    monkeypatch.setenv("HARNESS_MODEL_NAME", "from-env")
    monkeypatch.setenv("HARNESS_TEMPORAL_NAMESPACE", "from-env")
    frozen = tmp_path / "settings.json"
    frozen.write_text(json.dumps({"model_name": "from-file"}))
    typo = tmp_path / "typo.json"
    typo.write_text(json.dumps({"model_nam": "from-file"}))
    assert CliRunner().invoke(cli.app, ["--settings", str(typo), "eval"]).exit_code != 0
    calls = []

    async def evaluate(manifest, output, settings, **options):
        calls.append((output, settings, options))
        return {"status": "completed"}

    monkeypatch.setattr(cohort, "evaluate_corpus", evaluate)
    invoked = CliRunner().invoke(cli.app, [
        "--settings", str(frozen), "eval", "--allow-inference", "--case", "a", "--case", "b",
        "--keep-going", "--owned-worker",
    ])
    assert invoked.exit_code == 1, invoked.output  # A diagnostic is never "passed".
    output, settings, options = calls[0]
    assert settings is config.get_settings()
    assert settings.model_name == "from-file"
    assert settings.temporal_namespace == "default"  # Not merged from the environment.
    assert options == {"names": ("a", "b"), "owned_worker": True, "keep_going": True}
    assert re.fullmatch(r"\.harness/reports/diagnostic-\d{8}T\d{6}Z\.json", output.as_posix())

    monkeypatch.setattr(config, "_explicit", None)
    config.get_settings.cache_clear()
    assert config.get_settings().model_name == "from-env"  # Environment remains the default.
    CliRunner().invoke(cli.app, ["eval", "--allow-inference"])
    assert re.fullmatch(r"\.harness/reports/model-\d{8}T\d{6}Z\.json", calls[1][0].as_posix())
    assert calls[1][2]["names"] == ()


@pytest.mark.requires_temporal
async def test_export_history_writes_the_exact_history_once(temporal_cli, tmp_path, monkeypatch):
    from temporalio.client import WorkflowHistory
    from temporalio.testing import WorkflowEnvironment

    monkeypatch.setattr(config, "_explicit", None)
    monkeypatch.chdir(tmp_path)
    run_id = "investigate-v11-export"
    path = tmp_path / ".harness" / "histories" / f"{run_id}.json"

    async def export(*args: str):
        # The command runs its own event loop, as it does from a shell.
        return await asyncio.to_thread(CliRunner().invoke, cli.app, ["export-history", *args])

    async with await WorkflowEnvironment.start_local(dev_server_existing_path=temporal_cli) as env:
        # No worker polls this queue: the history is a fixed started/scheduled pair.
        await env.client.start_workflow("InvestigationWorkflow", id=run_id, task_queue="idle")
        monkeypatch.setenv("HARNESS_TEMPORAL_ADDRESS", env.client.service_client.config.target_host)
        config.get_settings.cache_clear()

        first = await export(run_id)
        assert first.exit_code == 0, first.output
        data = path.read_bytes()
        expected = await env.client.get_workflow_handle(run_id).fetch_history()
        assert data == expected.to_json().encode()
        summary = json.loads(first.output)
        assert summary == {
            "workflow_id": run_id,
            "history_events": len(WorkflowHistory.from_json(run_id, data.decode()).events),
            "history_sha256": hashlib.sha256(data).hexdigest(),
            "output": str(Path(".harness/histories") / f"{run_id}.json"),
        }
        assert summary["history_events"] >= 2

        again = await export(run_id)  # Never overwritten.
        assert again.exit_code != 0 and path.read_bytes() == data
        unsafe = await export("../escape")  # A run ID never becomes a path by itself.
        assert unsafe.exit_code != 0 and not (tmp_path / ".harness" / "escape.json").exists()
        missing = await export("investigate-v11-missing")
        assert missing.exit_code == 1
        chosen = tmp_path / "evidence" / "copy.json"
        explicit = await export(run_id, "--output", str(chosen))
        assert explicit.exit_code == 0, explicit.output
        assert chosen.read_bytes() == data
    assert sorted(item.name for item in path.parent.iterdir()) == [path.name]
