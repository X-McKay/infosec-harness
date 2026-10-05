"""The `harness` eval surface a new developer meets: bare commands, batches, releases, baselines.

Everything here runs on stub models. The release refusals are checked on the path where they
fire, before any agent is built or any model is called; the stub runs exercise the plumbing
(one summary table, exit statuses, report locations) and never establish quality.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from typer.testing import CliRunner

from infosec_harness import settings as settings_module
from infosec_harness.cli import app
from infosec_harness.evals import release, reporting
from infosec_harness.evals.provenance import CodeVersion
from infosec_harness.evals.reporting import EvalOutcome, exit_status
from infosec_harness.persistence import db
from infosec_harness.settings import Settings, get_settings

POSTGRES_DEFAULT = Settings.model_fields["database_url"].default


@pytest.fixture
def unconfigured(tmp_path, monkeypatch):
    """Settings as a fresh checkout sees them: no HARNESS_DATABASE_URL from any source."""
    monkeypatch.delenv("HARNESS_DATABASE_URL", raising=False)
    monkeypatch.delenv("HARNESS_ENV_FILE", raising=False)
    monkeypatch.chdir(tmp_path)  # no .env here either
    fresh = Settings()
    assert "database_url" not in fresh.model_fields_set
    monkeypatch.setattr(settings_module, "source_checkout", lambda: tmp_path)
    monkeypatch.setattr(settings_module, "get_settings", lambda: fresh)
    return fresh


# --- One place decides the local database ----------------------------------------------------

def test_an_unconfigured_local_command_uses_the_checkout_database(unconfigured, tmp_path):
    path = settings_module.default_to_local_database()
    assert path == tmp_path / ".harness" / "local.db"
    assert path.parent.is_dir()
    assert unconfigured.database_url == f"sqlite+aiosqlite:///{path}"
    # Said once: the store is now configured, so a second call changes and reports nothing.
    assert settings_module.default_to_local_database() is None


def test_a_configured_database_is_never_replaced(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    explicit = Settings(database_url="postgresql+asyncpg://deployment/db")
    assert settings_module.default_to_local_database(explicit) is None
    assert explicit.database_url == "postgresql+asyncpg://deployment/db"
    monkeypatch.setenv("HARNESS_DATABASE_URL", "sqlite+aiosqlite:///elsewhere.db")
    from_environment = Settings()
    assert settings_module.default_to_local_database(from_environment) is None
    assert from_environment.database_url == "sqlite+aiosqlite:///elsewhere.db"


def test_eval_commands_say_they_use_the_local_database(unconfigured):
    result = CliRunner().invoke(app, ["eval", "results", "--limit", "1"])
    assert result.exit_code == 0, result.output
    assert "HARNESS_DATABASE_URL is unset: using the local database" in result.stderr
    assert unconfigured.database_url.endswith("/.harness/local.db")


def test_migrate_keeps_the_deployment_default_unless_asked_for_local(unconfigured, monkeypatch):
    targets = []
    monkeypatch.setattr(db, "upgrade_to_head", lambda url=None: targets.append(url) or "head")
    result = CliRunner().invoke(app, ["migrate"])
    assert result.exit_code == 0, result.output
    assert targets == [None]
    assert unconfigured.database_url == POSTGRES_DEFAULT
    assert "local database" not in result.stderr

    result = CliRunner().invoke(app, ["migrate", "--local"])
    assert result.exit_code == 0, result.output
    assert targets[-1] == settings_module.local_database_url()
    assert unconfigured.database_url == POSTGRES_DEFAULT


def test_submit_local_defaults_an_unset_mode_to_stub_but_never_overrides_live(
        tmp_path, monkeypatch):
    monkeypatch.delenv("HARNESS_MODEL_MODE", raising=False)
    monkeypatch.delenv("HARNESS_ENV_FILE", raising=False)
    monkeypatch.chdir(tmp_path)
    fresh = Settings()
    assert fresh.model_mode == "live"  # the deployment default
    assert settings_module.default_to_stub_models(fresh) is True
    assert fresh.model_mode == "stub"
    live = Settings(model_mode="live")
    assert settings_module.default_to_stub_models(live) is False
    assert live.model_mode == "live"


# --- `harness eval run`: several agents, one table, exit statuses ----------------------------

def _outcome(status="complete", gate="passed") -> EvalOutcome:
    return EvalOutcome("verdict", "sonnet", "exp-1", status,
                       metrics={"gate_evaluation": {"status": gate, "checks": []}})


def test_exit_status_fails_incomplete_runs_and_gates_only_when_required():
    assert exit_status([_outcome(), _outcome(gate="failed")]) == 0
    assert exit_status([_outcome(), _outcome(status="truncated")]) == 1
    assert exit_status([_outcome(status="error")]) == 1
    assert exit_status([_outcome()], require_gates=True) == 0
    assert exit_status([_outcome(gate="failed")], require_gates=True) == 1
    assert exit_status([_outcome(gate="not_checked")], require_gates=True) == 1
    # A run with no stored verdict is not a pass.
    assert EvalOutcome("verdict", "", "-", "truncated").gate_status == "not_checked"


def test_failing_checks_name_the_metric_the_value_and_the_bound():
    outcome = EvalOutcome("build-repair", "sonnet", "exp-1", "complete", metrics={
        "gate_evaluation": {"status": "failed", "missing_provenance": ["commit"], "checks": [
            {"metric": "task_success_rate", "bound": "min", "limit": 0.75, "value": 0.5,
             "status": "failed"},
            {"metric": "execution_not_checked_count", "bound": "eq", "limit": 0.0,
             "value": 1.0, "status": "failed"},
            {"metric": "p95_model_requests", "bound": "max", "limit": 8.0, "value": None,
             "status": "not_checked"},
            {"metric": "schema_validity_rate", "bound": "eq", "limit": 1.0, "value": 1.0,
             "status": "passed"}]}})
    assert outcome.failing_checks == [
        "task_success_rate=0.5<0.75", "execution_not_checked_count=1!=0",
        "p95_model_requests=n/a", "provenance:commit"]


def test_eval_run_all_runs_every_packaged_agent_and_prints_one_table(tmp_path):
    result = CliRunner().invoke(app, ["eval", "run", "--all", "--report-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    agents = reporting.packaged_eval_agents()
    table = result.stdout.rsplit("\nagent ", 1)[1]
    for header in ("status", "n", "success", "gates", "failing checks", "report"):
        assert header in table.splitlines()[0]
    rows = table.splitlines()[2:]
    assert [row.split()[0] for row in rows] == agents
    assert all(row.split()[2] == "complete" for row in rows)
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(
        row.split()[-1].rsplit("/", 1)[1] for row in rows)


def test_a_truncated_run_fails_the_batch_but_not_the_other_runs(monkeypatch, tmp_path):
    from infosec_harness.evals.run import TruncatedExperiment

    real = reporting.run_experiment

    async def flaky(agent, **kwargs):
        if agent == "verdict":
            raise TruncatedExperiment("exp-cut", {
                "completed_runs": 1, "planned_runs": 9, "completed_cases": 1,
                "planned_cases": 9, "error_type": "ConnectError", "error": "endpoint down",
                "failed_case": "c2", "failed_repetition": 0})
        return await real(agent, **kwargs)

    monkeypatch.setattr(reporting, "run_experiment", flaky)
    result = CliRunner().invoke(app, ["eval", "run", "recon", "verdict",
                                      "--report-dir", str(tmp_path)])
    assert result.exit_code == 1
    rows = {line.split()[0]: line.split() for line in result.stdout.splitlines()[-2:]}
    assert rows["recon"][2] == "complete" and rows["verdict"][2] == "truncated"
    assert rows["verdict"][5] == "not_checked"


@pytest.mark.parametrize("args", [[], ["verdict", "--all"],
                                  ["recon", "verdict", "--dataset", "x.yaml"],
                                  ["verdict", "-m", "sonnet", "-m", "haiku", "--report", "r.json"]])
def test_eval_run_refuses_ambiguous_selections(args):
    result = CliRunner().invoke(app, ["eval", "run", *args])
    assert result.exit_code == 2


# --- `harness eval release`: refusals before any model call ----------------------------------

def _code(commit="a" * 40, dirty=False) -> CodeVersion:
    return CodeVersion(git_commit=commit, git_dirty=dirty, harness_version="0", python="3")


@pytest.fixture
def no_runs(monkeypatch):
    async def refuse(*args, **kwargs):
        pytest.fail("a refused release must not run any agent")

    monkeypatch.setattr(reporting, "run_experiment", refuse)


@pytest.mark.parametrize(("mode", "code", "reason"), [
    ("stub", _code(), "HARNESS_MODEL_MODE=stub measures no agent"),
    ("live", _code(dirty=True), "the working tree differs from aaaaaaaaaaaa"),
    ("live", _code(commit=""), "there is no git commit to qualify"),
])
def test_release_refuses_stub_models_and_trees_that_are_not_a_commit(
        monkeypatch, no_runs, mode, code, reason):
    monkeypatch.setattr(get_settings(), "model_mode", mode)
    monkeypatch.setattr(release, "code_version", lambda: code)
    result = CliRunner().invoke(app, ["eval", "release"])
    assert result.exit_code == 2
    assert reason in result.stderr


def test_release_refuses_an_agent_with_no_packaged_dataset(monkeypatch, no_runs):
    monkeypatch.setattr(get_settings(), "model_mode", "live")
    monkeypatch.setattr(release, "code_version", lambda: _code())
    result = CliRunner().invoke(app, ["eval", "release", "--agent", "no-such-agent"])
    assert result.exit_code == 2
    assert "no packaged eval dataset for ['no-such-agent']" in result.stderr


async def test_release_writes_reports_per_commit_and_keeps_the_baseline_refusals(monkeypatch):
    """With the preconditions bypassed, a stub release still cannot record a baseline."""
    monkeypatch.setattr(release, "release_refusal", lambda: None)
    monkeypatch.setattr(release, "code_version", lambda: _code())
    outcomes, status = await release.qualify_release(
        ["probe-diagnosis", "verdict"], save_baselines=True)
    assert status == 1
    directory = get_settings().reports_dir / "release" / ("a" * 40)
    summary = json.loads((directory / "summary.json").read_text())
    assert summary["commit"] == "a" * 40 and summary["status"] == "failed"
    assert [run["agent"] for run in summary["runs"]] == ["probe-diagnosis", "verdict"]
    for outcome, run in zip(outcomes, summary["runs"], strict=True):
        assert outcome.report.parent == directory and outcome.report.is_file()
        if run["gate_status"] == "passed":
            assert "against the stub model" in run["baseline"]
        else:
            assert run["baseline"] is None


# --- `harness eval baseline save --latest` ---------------------------------------------------

async def _store(experiment_id, agent, *, tier="sonnet", pricing="priced", status="complete",
                 split="full", year=2100):
    await db.create_all()
    async with db.session() as session:
        session.add(db.EvalExperiment(
            id=experiment_id, agent=agent, dataset="d", model_tier=tier,
            model_name=("stub:x" if pricing == "stub" else "bedrock:model"), pricing=pricing,
            created_at=datetime(year, 1, 1, tzinfo=UTC),
            metrics={"status": status, "comparison_identity": {"split": split}}))
        await session.commit()


async def test_latest_picks_the_newest_complete_live_full_run_of_that_tier():
    agent = "latest-fixture"
    await _store("exp-latest-old", agent, year=2099)
    await _store("exp-latest-wanted", agent, year=2100)
    await _store("exp-latest-stub", agent, pricing="stub", year=2101)
    await _store("exp-latest-heldout", agent, split="external", year=2102)
    await _store("exp-latest-truncated", agent, status="truncated", year=2103)
    await _store("exp-latest-opus", agent, tier="opus", year=2104)
    assert (await reporting.latest_live_experiment(agent, "sonnet")).id == "exp-latest-wanted"
    assert (await reporting.latest_live_experiment(agent, "opus")).id == "exp-latest-opus"
    with pytest.raises(SystemExit, match="no complete live run of latest-fixture on haiku"):
        await reporting.latest_live_experiment(agent, "haiku")


async def test_latest_defaults_to_the_agents_own_tier():
    from infosec_harness.agents import registry

    tier = registry.load_spec("verdict").model or "sonnet"
    await _store("exp-latest-verdict", "verdict", tier=tier, year=2200)
    assert (await reporting.latest_live_experiment("verdict")).id == "exp-latest-verdict"


def test_baseline_save_latest_records_that_run(monkeypatch):
    import asyncio

    asyncio.run(_store("exp-latest-cli", "latest-cli-fixture", year=2300))
    saved = []

    async def record(experiment_id):
        saved.append(experiment_id)

    monkeypatch.setattr(reporting, "save_baseline", record)
    result = CliRunner().invoke(app, ["eval", "baseline", "save", "--latest",
                                      "latest-cli-fixture", "-m", "sonnet"])
    assert result.exit_code == 0, result.output
    assert saved == ["exp-latest-cli"]
    assert "exp-latest-cli" in result.stdout


@pytest.mark.parametrize("args", [[], ["exp-1", "--latest", "verdict"], ["exp-1", "-m", "opus"]])
def test_baseline_save_takes_an_id_or_latest(args):
    assert CliRunner().invoke(app, ["eval", "baseline", "save", *args]).exit_code == 2
