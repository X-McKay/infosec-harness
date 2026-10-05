"""Execution-backed eval cases cannot be satisfied by mentioning the expected string."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from infosec_harness.domain.models import EnvironmentSpec, ProbeSource
from infosec_harness.evals import execution_checks
from infosec_harness.evals.execution_checks import (
    ExecutionCheckResult,
    builder_infrastructure_failure,
    run_execution_check,
)
from infosec_harness.sandbox import docker


def _case() -> dict:
    return {
        "name": "perl-dbi-driver-not-installed",
        "repo": "eval-corpus/perl/sqli/vulnerable",
        "execution_check": "perl_dbd_sqlite_v1",
        "expect_mentions": "DBD::SQLite",
        "expected": "addressed",
    }


def _spec(*commands: str) -> EnvironmentSpec:
    return EnvironmentSpec(
        base_image="perl:5.40",
        install_commands=list(commands),
        test_command="prove -v {test_file}",
    )


async def test_a_literal_string_cannot_pass_without_successful_execution():
    seen = []

    async def failed_engine(case, spec, check):
        seen.append((case, spec, check))
        return ExecutionCheckResult(
            status="failed", check=check,
            reason="controller-authored dependency check failed",
            build_status="passed", check_exit_code=1,
        )

    result = await run_execution_check(
        _case(), _spec("printf 'DBD::SQLite\\n'"), stub=False, engine=failed_engine
    )

    assert result is not None
    assert result.predicted == "unaddressed"
    assert result.status == "failed"
    assert seen[0][1].install_commands == ["printf 'DBD::SQLite\\n'"]


async def test_success_requires_the_execution_engine_to_observe_the_checker():
    async def passing_engine(case, spec, check):
        return ExecutionCheckResult(
            status="passed", check=check,
            reason="controller-authored dependency check passed",
            source_hash="a" * 64, image_tag="harness-target:fixture-spec",
            build_status="passed", build_exit_code=0, check_exit_code=0,
            output_excerpt="HARNESS_EVAL_CHECK::perl-dbd-sqlite-v1",
        )

    result = await run_execution_check(
        _case(), _spec("cpanm --local-lib=/opt/home/perl5 --installdeps ."),
        stub=False, engine=passing_engine,
    )

    assert result is not None
    assert result.predicted == "addressed"
    assert result.as_score()["source_hash"] == "a" * 64
    assert result.as_score()["execution_mode"] == "secure-sandbox-v1"


async def test_missing_secure_runtime_is_not_checked_and_never_a_pass():
    async def unavailable_engine(case, spec, check):
        return ExecutionCheckResult(
            status="not_checked", check=check,
            reason="sandbox runtime 'runsc' is unavailable",
        )

    result = await run_execution_check(
        _case(), _spec("cpanm DBD::SQLite"), stub=False, engine=unavailable_engine
    )

    assert result is not None
    assert result.status == "not_checked"
    assert result.predicted == "execution_not_checked"
    assert result.as_score()["reason"] == "sandbox runtime 'runsc' is unavailable"


async def test_stub_mode_skips_the_engine_and_labels_the_evidence_unknown():
    called = False

    async def engine(case, spec, check):
        nonlocal called
        called = True
        raise AssertionError("stub mode must not start a build")

    result = await run_execution_check(
        _case(), _spec("cpanm DBD::SQLite"), stub=True, engine=engine
    )

    assert result is not None
    assert result.status == "not_checked"
    assert result.predicted == "execution_not_checked"
    assert result.execution_mode == "stub-not-checked-v1"
    assert "quality" in result.reason
    assert called is False


async def test_cases_without_an_execution_contract_keep_structural_scoring():
    assert await run_execution_check(
        {"name": "structural"}, _spec("cpanm DBD::SQLite"), stub=False
    ) is None


@pytest.mark.parametrize(("agent", "name"), [
    ("probe-author", "sqli-marker-oracle"),
    ("probe-repair", "asserts-before-reaching-the-sink"),
    ("probe-repair", "instruments-an-object-the-target-never-uses"),
])
async def test_probe_scoring_never_dispatches_undeclared_sandbox_checks(monkeypatch, agent, name):
    from infosec_harness.evals.adapters import ADAPTERS
    from infosec_harness.evals.dataset import load_dataset
    from infosec_harness.evals.run import _score_output

    async def unexpected_execution(*args, **kwargs):
        raise AssertionError("structural scoring must not dispatch sandbox execution")

    monkeypatch.setattr(docker, "ensure_runtime_available", unexpected_execution)
    monkeypatch.setattr(docker, "run_probe", unexpected_execution)
    case = next(case for case in load_dataset(agent).cases if case["name"] == name)
    probe = ProbeSource(test_file_path="tests/test_probe.py", content=(
        f"{case['target_callable']}\nHARNESS_PRECONDITION::n\nHARNESS_ORACLE::n\n"))
    predicted, outcome, diagnostic = await _score_output(
        SimpleNamespace(agent=agent, stub=False), case, ADAPTERS[agent](case), probe)
    assert (predicted, outcome) == (case["expected"], "answered")
    assert diagnostic == {"typed_output": {
        "type": "ProbeSource", "value": probe.model_dump(mode="json"), "truncated": False,
    }}


def test_a_lima_host_tempfile_failure_is_infrastructure_not_model_quality():
    assert builder_infrastructure_failure(
        "ERROR: failed to build: resolve : lstat /var/folders: no such file or directory"
    )
    assert not builder_infrastructure_failure(
        "RUN cpanm DBD::SQLite returned a non-zero code: 1"
    )


async def _secure_check(repo: str | None = None) -> ExecutionCheckResult:
    case = {**_case(), **({"repo": repo} if repo is not None else {})}
    return await execution_checks._secure_engine(case, _spec("cpanm DBD::SQLite"),
                                                 "perl_dbd_sqlite_v1")


@pytest.fixture
def no_build(monkeypatch):
    """Every precondition below must refuse before a snapshot or build is attempted."""
    async def refuse(*_args, **_kwargs):
        raise AssertionError("a refused precondition must not reach checkout")

    monkeypatch.setattr(execution_checks, "checkout", refuse)


@pytest.mark.parametrize(("repo", "reason"), [
    ("../outside-the-checkout", "execution fixture escapes the repository root"),
    ("eval-corpus/no-such-fixture", "execution fixture is missing"),
])
async def test_execution_check_refuses_an_unsafe_fixture(no_build, repo, reason):
    result = await _secure_check(repo)
    assert (result.status, result.reason) == ("not_checked", reason)


@pytest.mark.parametrize("settings", [
    SimpleNamespace(allow_insecure_runtime=True, sandbox_runtime="runsc"),
    SimpleNamespace(allow_insecure_runtime=True, sandbox_runtime="runc"),
    SimpleNamespace(allow_insecure_runtime=False, sandbox_runtime="runc"),
])
async def test_execution_check_requires_enforced_runsc(
    monkeypatch, no_build, settings,
):
    monkeypatch.setattr(execution_checks, "get_settings", lambda: settings)
    reason = "execution checks require enforced runsc; the insecure fallback is disabled"
    result = await _secure_check()
    assert (result.status, result.reason) == ("not_checked", reason)


async def test_execution_check_requires_runsc_to_be_registered_and_the_daemon_default(
    monkeypatch, no_build,
):
    """The configured name is not evidence: the daemon must advertise and select runsc."""
    async def unavailable(_runtime=None):
        return False

    monkeypatch.setattr(docker, "runtime_available", unavailable)
    result = await _secure_check()
    assert result.status == "not_checked"
    assert "is not available on this host" in result.reason
