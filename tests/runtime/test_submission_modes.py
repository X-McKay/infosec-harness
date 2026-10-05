"""Real submissions cannot silently opt out of durable orchestration."""
import pytest
from typer.testing import CliRunner

from infosec_harness.settings import get_settings


async def test_direct_submission_rejects_live_before_running_or_persisting(monkeypatch):
    from infosec_harness.workflows.local_run import LocalModeUnavailable, run_in_process

    monkeypatch.setattr(get_settings(), "model_mode", "live")
    with pytest.raises(LocalModeUnavailable, match="require Temporal"):
        await run_in_process([])


def test_cli_explains_the_stub_only_local_profile(tmp_path, monkeypatch):
    from infosec_harness.cli import app

    monkeypatch.setattr(get_settings(), "model_mode", "live")
    findings = tmp_path / "findings.json"
    findings.write_text("[]")
    result = CliRunner().invoke(app, ["submit", str(findings), "--local"])
    assert result.exit_code == 2
    assert "HARNESS_MODEL_MODE=stub" in result.output
