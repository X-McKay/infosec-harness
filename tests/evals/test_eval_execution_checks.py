"""Execution-backed eval cases cannot be satisfied by mentioning the expected string."""

from __future__ import annotations

from infosec_harness.domain.models import EnvironmentSpec
from infosec_harness.evals.execution_checks import (
    ExecutionCheckResult,
    _builder_infrastructure_failure,
    run_execution_check,
)


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


def test_a_lima_host_tempfile_failure_is_infrastructure_not_model_quality():
    assert _builder_infrastructure_failure(
        "ERROR: failed to build: resolve : lstat /var/folders: no such file or directory"
    )
    assert not _builder_infrastructure_failure(
        "RUN cpanm DBD::SQLite returned a non-zero code: 1"
    )
