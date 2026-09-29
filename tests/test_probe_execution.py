from __future__ import annotations

import atexit
import hashlib
import io
import re
import sys
from dataclasses import replace

from infosec_harness.domain.models import ProbeSource
from infosec_harness.evals.probe_execution import (
    ProbeExecutionResult,
    _trace_suffix,
    evaluate_probe_execution,
)


def _case(name: str, nonce: str = "n-123") -> dict:
    return {"name": name, "payload": {"oracle_nonce": nonce}}


def _probe() -> ProbeSource:
    return ProbeSource(
        test_file_path="tests/test_probe.py",
        content="def test_probe():\n    pass\n",
    )


async def test_declared_check_passes_only_engine_observed_target_and_oracle() -> None:
    seen = {}

    async def engine(declaration, probe, nonce):
        seen.update(declaration=declaration, probe=probe, nonce=nonce)
        return ProbeExecutionResult(
            status="observed",
            check="target-call:app.py:get_user",
            reason="in-process target and oracle signals observed",
            target_invoked=True,
            oracle_observed=True,
            exit_code=0,
        )

    result = await evaluate_probe_execution(
        "probe-author",
        _case("sqli-marker-oracle"),
        _probe(),
        stub=False,
        engine=engine,
    )
    assert result is not None and result.status == "observed"
    assert result.evidence_strength == "in_process_unattested"
    assert seen["declaration"].target_callable == "get_user"
    assert seen["nonce"] != "n-123"
    assert len(seen["nonce"]) == 32


async def test_marker_substrings_alone_are_not_execution_evidence() -> None:
    async def engine(declaration, probe, nonce):
        assert "get_user" in probe.content
        assert "HARNESS_ORACLE" in probe.content
        return ProbeExecutionResult(
            status="failed",
            check="target-call:app.py:get_user",
            reason="controller trace did not observe the declared target",
            target_invoked=False,
            oracle_observed=True,
            exit_code=0,
        )

    probe = ProbeSource(
        test_file_path="tests/test_probe.py",
        content="get_user = 'mentioned only'; print('HARNESS_ORACLE::n-123')",
    )
    result = await evaluate_probe_execution(
        "probe-repair",
        _case("instruments-an-object-the-target-never-uses"),
        probe,
        stub=False,
        engine=engine,
    )
    assert result is not None and result.status == "failed"
    assert not result.target_invoked


async def test_stub_fails_closed_and_controller_nonce_is_not_case_nonce() -> None:
    stubbed = await evaluate_probe_execution(
        "probe-author",
        _case("sqli-marker-oracle"),
        _probe(),
        stub=True,
    )
    assert stubbed is not None and stubbed.status == "not_checked"
    assert stubbed.execution_mode == "stub-not-checked-v1"


async def test_unsupported_case_has_no_inflated_execution_claim() -> None:
    assert (
        await evaluate_probe_execution(
            "probe-author",
            _case("javascript-xss-jest-marker"),
            _probe(),
            stub=False,
        )
        is None
    )


async def test_drifted_controller_target_is_not_checked(monkeypatch, tmp_path) -> None:
    from infosec_harness.evals import probe_execution

    declaration = replace(
        probe_execution.DECLARED_CHECKS[("probe-author", "sqli-marker-oracle")],
        repo="fixture",
        target_sha256="0" * 64,
    )
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "app.py").write_text("def get_user(): pass\n")
    monkeypatch.setattr(probe_execution, "REPO_ROOT", tmp_path)
    result = await probe_execution._secure_engine(declaration, _probe(), "controller-nonce")
    assert result.status == "not_checked"
    assert "identity drifted" in result.reason


def test_controller_trace_is_specific_to_file_and_callable() -> None:
    from infosec_harness.evals.probe_execution import DECLARED_CHECKS

    declaration = DECLARED_CHECKS[("probe-author", "sqli-marker-oracle")]
    suffix = _trace_suffix(declaration, "nonce")
    assert "co_name == 'get_user'" in suffix
    assert "'/work/repo/app.py'" in suffix
    assert declaration.target_sha256 in suffix
    assert "frame.f_locals.get('name')" in suffix
    assert "alice' OR '1'='1" in suffix
    assert "HARNESS_TARGET_INVOKED::nonce" in suffix
    assert "HARNESS_CONTROLLER_ORACLE::nonce" in suffix


def test_controller_trace_observes_real_declared_call_and_return_value(monkeypatch) -> None:
    from infosec_harness.evals.probe_execution import DECLARED_CHECKS

    content = b"trusted target identity"
    declaration = replace(
        DECLARED_CHECKS[("probe-author", "sqli-marker-oracle")],
        target_sha256=hashlib.sha256(content).hexdigest(),
    )
    monkeypatch.setattr("os.path.realpath", lambda _path: "/work/repo/app.py")
    monkeypatch.setattr("builtins.open", lambda *_args, **_kwargs: io.BytesIO(content))
    namespace = {}
    exec(
        compile(
            "def get_user(conn, name):\n    return ['public', 'secret']\n",
            "/work/repo/app.py",
            "exec",
        ),
        namespace,
    )
    exec(_trace_suffix(declaration, "nonce"), namespace)

    # Candidate-authored strings alone do not affect controller state.
    assert namespace["_harness_target_hit"] is False
    assert namespace["_harness_oracle_hit"] is False
    try:
        namespace["get_user"](None, declaration.argument_value)
        assert namespace["_harness_target_hit"] is True
        assert namespace["_harness_oracle_hit"] is True
    finally:
        sys.settrace(None)
        atexit.unregister(namespace["_harness_report_target"])


def test_candidate_can_read_appended_source_and_forge_both_observations() -> None:
    from infosec_harness.evals.probe_execution import DECLARED_CHECKS

    declaration = DECLARED_CHECKS[("probe-author", "sqli-marker-oracle")]
    combined_source = "# candidate source\n" + _trace_suffix(declaration, "a" * 32)
    recovered = re.search(r"HARNESS_TARGET_INVOKED::([0-9a-f]{32})", combined_source)
    assert recovered is not None
    nonce = recovered.group(1)
    forged_output = f"HARNESS_TARGET_INVOKED::{nonce}\nHARNESS_CONTROLLER_ORACLE::{nonce}\n"
    assert f"HARNESS_TARGET_INVOKED::{nonce}" in forged_output
    assert f"HARNESS_CONTROLLER_ORACLE::{nonce}" in forged_output
