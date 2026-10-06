import json
import re

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
