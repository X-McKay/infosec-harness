"""Execution-backed eval cases cannot be satisfied by mentioning the expected string."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from infosec_harness.domain.models import EnvironmentSpec, ProbeSource
from infosec_harness.evals import execution_checks, probe_execution
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


def test_a_lima_host_tempfile_failure_is_infrastructure_not_model_quality():
    assert builder_infrastructure_failure(
        "ERROR: failed to build: resolve : lstat /var/folders: no such file or directory"
    )
    assert not builder_infrastructure_failure(
        "RUN cpanm DBD::SQLite returned a non-zero code: 1"
    )


# --- Both execution engines share one set of sandbox preconditions -------------------------

_PROBE = ProbeSource(test_file_path="tests/test_probe.py", content="def test_probe():\n    pass\n")
_DECLARED = probe_execution.DECLARED_CHECKS[("probe-author", "sqli-marker-oracle")]


async def _both_engines(repo: str | None = None) -> tuple[str, str, str, str]:
    """Run the dependency-check engine and the probe engine on the same fixture conditions."""
    case = {**_case(), **({"repo": repo} if repo is not None else {})}
    declaration = _DECLARED if repo is None else replace(_DECLARED, repo=repo)
    dependency = await execution_checks._secure_engine(case, _spec("cpanm DBD::SQLite"),
                                                        "perl_dbd_sqlite_v1")
    probe = await probe_execution._secure_engine(declaration, _PROBE, "controller-nonce")
    return dependency.status, dependency.reason, probe.status, probe.reason


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
async def test_both_engines_refuse_an_unsafe_fixture_identically(no_build, repo, reason):
    assert await _both_engines(repo) == ("not_checked", reason, "not_checked", reason)


@pytest.mark.parametrize("settings", [
    SimpleNamespace(allow_insecure_runtime=True, sandbox_runtime="runsc"),
    SimpleNamespace(allow_insecure_runtime=True, sandbox_runtime="runc"),
    SimpleNamespace(allow_insecure_runtime=False, sandbox_runtime="runc"),
])
async def test_both_engines_refuse_anything_but_enforced_runsc_identically(
    monkeypatch, no_build, settings,
):
    monkeypatch.setattr(execution_checks, "get_settings", lambda: settings)
    reason = "execution checks require enforced runsc; the insecure fallback is disabled"
    dependency_status, dependency, probe_status, probe = await _both_engines()
    assert (dependency_status, probe_status) == ("not_checked", "not_checked")
    assert dependency == probe == reason


async def test_both_engines_require_runsc_to_be_registered_and_the_daemon_default(
    monkeypatch, no_build,
):
    """The configured name is not evidence: the daemon must advertise and select runsc."""
    async def unavailable(_runtime=None):
        return False

    monkeypatch.setattr(docker, "runtime_available", unavailable)
    dependency_status, dependency, probe_status, probe = await _both_engines()
    assert (dependency_status, probe_status) == ("not_checked", "not_checked")
    assert "is not available on this host" in dependency
    assert "is not available on this host" in probe
