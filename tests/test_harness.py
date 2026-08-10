from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from infosec_harness.abox_worker import (
    AboxWorkerError,
    plan_no_network_worker,
    run_no_network_worker,
)
from infosec_harness.benchmarks import (
    BenchmarkAdmissionError,
    BenchmarkLane,
    admit,
    dry_run,
    load_registry,
)
from infosec_harness.domain import AuthorizationManifest, Budget, TerminalState, Usage
from infosec_harness.evaluation import run_replay_evaluation
from infosec_harness.gym import HiddenGrade, ReplaySecurityEnv, SubmitDisposition, load_task
from infosec_harness.host_observer import (
    HostObserverEvidence,
    ObservedFlow,
    sign_observer_evidence,
)
from infosec_harness.lab_evidence import (
    LabEvidenceError,
    SyntheticExperimentEvidence,
    _kubectl,
    sign_evidence,
    verify_evidence,
)
from infosec_harness.minikube_lab import MinikubeLabStatus, admission_report, load_lab_status
from infosec_harness.offline import (
    bounded_diff,
    compare_runs,
    load_context,
    reconcile_cost,
    retention_audit,
    validate_context,
)
from infosec_harness.policy import (
    PolicyError,
    canonical_path,
    load_authorization,
    redact,
    signed_deny_egress_policy,
    verify_egress_policy,
)
from infosec_harness.providers import (
    FakeBackend,
    ProviderCapabilities,
    ProviderError,
    ReplayBackend,
)
from infosec_harness.reports import cost_json, report_markdown
from infosec_harness.runtime import triage, validate_summary
from infosec_harness.sandbox import NoExecSandbox, network_self_test
from infosec_harness.sarif import import_sarif
from infosec_harness.stores import ArtifactStore, RunStore
from infosec_harness.tools import ReadOnlyTools

ROOT = Path(__file__).parents[1]
SARIF = ROOT / "fixtures/sample.sarif"
REPO = ROOT / "fixtures/sample-repo"


def run(tmp_path: Path, backend, **kwargs):
    return asyncio.run(
        triage(
            sarif=SARIF,
            repo=REPO,
            revision="fixture-revision-001",
            backend=backend,
            data_root=tmp_path,
            authorization=load_authorization(ROOT / "fixtures/authorization.json"),
            authorization_path=ROOT / "fixtures/authorization.json",
            **kwargs,
        )
    )


def test_sarif_preserves_scanner_flow_fingerprint_and_suppression(tmp_path: Path) -> None:
    findings = import_sarif(SARIF, ArtifactStore(tmp_path))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.scanner["name"] == "fixture-scanner"
    assert finding.code_flow[1].path == "src/app.py"
    assert finding.fingerprints["primaryLocationLineHash"] == "fixture-line-hash"
    assert finding.revision == "fixture-revision-001"


def test_sarif_dedup_keeps_all_scanner_occurrences(tmp_path: Path) -> None:
    payload = json.loads(SARIF.read_text())
    duplicate = payload["runs"][0]["results"][0].copy()
    duplicate["suppressions"] = [{"kind": "inSource", "status": "accepted"}]
    payload["runs"][0]["results"].append(duplicate)
    duplicate_sarif = tmp_path / "duplicate.sarif"
    duplicate_sarif.write_text(json.dumps(payload))
    finding = import_sarif(duplicate_sarif, ArtifactStore(tmp_path / "artifacts"))[0]
    assert finding.occurrence_count == 2
    assert len(finding.occurrence_artifacts) == 2
    assert finding.suppressions[0]["kind"] == "inSource"


def test_replay_triage_persists_consistent_report_audit_and_cost(tmp_path: Path) -> None:
    summary = run(tmp_path, ReplayBackend(ROOT / "fixtures/replay/sample.json"))
    assert summary.terminal_state == TerminalState.COMPLETE
    validate_summary(summary)
    assert summary.dispositions[0].human_review_required
    assert summary.dispositions[0].supporting[0].path == "src/app.py"
    assert "text" not in summary.evidence[0].excerpts[0]
    assert "template =" not in report_markdown(summary)
    loaded = RunStore(tmp_path).get(summary.run_id)
    assert loaded.model_dump(mode="json") == summary.model_dump(mode="json")
    assert "Typed disposition: `needs_review`" in report_markdown(summary)
    assert json.loads(cost_json(summary))["usage"] == {"input_tokens": 220, "output_tokens": 90, "cache_read_tokens": 0}
    events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert any(event.get("terminal_state") == "complete" for event in events)
    assert (tmp_path / "reports" / f"{summary.run_id}.md").exists()
    assert (tmp_path / "reports" / f"{summary.run_id}.json").exists()
    assert (tmp_path / "costs" / f"{summary.run_id}.json").exists()
    assert list((tmp_path / "artifacts" / "protected").iterdir())
    with sqlite3.connect(tmp_path / "runs.sqlite3") as conn:
        assert conn.execute("SELECT terminal_state FROM runs").fetchone()[0] == "complete"


@pytest.mark.parametrize(
    ("fixture", "terminal"),
    [
        ("malformed.json", TerminalState.MALFORMED_MODEL_OUTPUT),
        ("refusal.json", TerminalState.PROVIDER_REFUSAL),
        ("timeout.json", TerminalState.BUDGET_EXHAUSTED),
    ],
)
def test_replay_failure_outcomes_are_distinct(tmp_path: Path, fixture: str, terminal: TerminalState) -> None:
    summary = run(tmp_path, ReplayBackend(ROOT / "fixtures/replay" / fixture))
    assert summary.terminal_state == terminal
    assert RunStore(tmp_path).get(summary.run_id).terminal_state == terminal


def test_replay_mismatch_never_falls_back_to_a_provider(tmp_path: Path) -> None:
    summary = run(tmp_path, ReplayBackend(ROOT / "fixtures/replay/mismatch.json"))
    assert summary.terminal_state == TerminalState.INFRA_ERROR
    assert summary.error_class == "replay_miss"


def test_tool_policy_denial_is_terminal_and_recorded(tmp_path: Path) -> None:
    summary = run(
        tmp_path,
        ReplayBackend(ROOT / "fixtures/replay/sample.json"),
        requested_tool_path="../outside",
    )
    assert summary.terminal_state == TerminalState.POLICY_BLOCKED
    assert any(not decision.allowed for decision in summary.policy_decisions)


def test_budget_exhaustion_prevents_success(tmp_path: Path) -> None:
    output = json.loads((ROOT / "fixtures/replay/sample.json").read_text())["result"]
    summary = run(tmp_path, FakeBackend(output, Usage(input_tokens=9999)), budget=Budget(max_input_tokens=5))
    assert summary.terminal_state == TerminalState.BUDGET_EXHAUSTED
    assert not summary.dispositions
    validate_summary(summary)


def test_cost_budget_exhaustion_prevents_success(tmp_path: Path) -> None:
    output = json.loads((ROOT / "fixtures/replay/sample.json").read_text())["result"]
    summary = run(tmp_path, FakeBackend(output, Usage(input_tokens=220, output_tokens=90)), budget=Budget(max_cost_usd=0.0001))
    assert summary.terminal_state == TerminalState.BUDGET_EXHAUSTED
    assert summary.error_class == "cost budget exhausted"


def test_provider_error_is_not_a_success(tmp_path: Path) -> None:
    summary = run(tmp_path, FakeBackend(ProviderError("provider_error", "safe message")))
    assert summary.terminal_state == TerminalState.INFRA_ERROR
    assert summary.error_class == "provider_error"


def test_provider_capability_mismatch_stops_before_provider_dispatch(tmp_path: Path) -> None:
    output = json.loads((ROOT / "fixtures/replay/sample.json").read_text())["result"]
    backend = FakeBackend(output)
    backend.capabilities = ProviderCapabilities(structured_output=False)
    summary = run(tmp_path, backend)
    assert summary.terminal_state == TerminalState.INFRA_ERROR
    assert summary.error_class == "unsupported"


def test_invalid_authorization_is_a_distinct_terminal_outcome(tmp_path: Path) -> None:
    authorization = load_authorization(ROOT / "fixtures/authorization.json")
    invalid = authorization.model_copy(update={"signature": "0" * 64})
    summary = asyncio.run(
        triage(
            sarif=SARIF,
            repo=REPO,
            revision="fixture-revision-001",
            backend=ReplayBackend(ROOT / "fixtures/replay/sample.json"),
            data_root=tmp_path,
            authorization=AuthorizationManifest.model_validate(invalid),
            authorization_path=ROOT / "fixtures/authorization.json",
        )
    )
    assert summary.terminal_state == TerminalState.AUTHORIZATION_FAILED
    assert summary.error_class == "authorization signature invalid"


@pytest.mark.parametrize("flag", ["sandbox_healthy", "network_observer_healthy"])
def test_unhealthy_sandbox_or_observer_is_recorded_terminal_outcome(tmp_path: Path, flag: str) -> None:
    summary = run(
        tmp_path,
        ReplayBackend(ROOT / "fixtures/replay/sample.json"),
        **{flag: False},
    )
    assert summary.terminal_state == TerminalState.INFRA_ERROR
    assert summary.error_class == "RuntimeError"


def test_path_and_secret_policy_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(PolicyError):
        canonical_path(REPO, "../outside")
    redacted, fingerprints = redact("api_key=fixture-secret-value")
    assert "fixture-secret-value" not in redacted
    assert fingerprints
    secret_file = tmp_path / "secret.py"
    secret_file.write_text("token=fixture-secret-value")
    _, decision = ReadOnlyTools(tmp_path).read("secret.py", 1, 1)
    assert not decision.allowed


def test_malformed_sarif_and_secret_bearing_sarif_fail_closed(tmp_path: Path) -> None:
    malformed = tmp_path / "malformed.sarif"
    malformed.write_text("not json")
    with pytest.raises(ValueError):
        import_sarif(malformed, ArtifactStore(tmp_path / "malformed-artifacts"))
    payload = json.loads(SARIF.read_text())
    payload["runs"][0]["results"][0]["message"]["text"] = "api_key=fixture-secret-value"
    secret_sarif = tmp_path / "secret.sarif"
    secret_sarif.write_text(json.dumps(payload))
    summary = asyncio.run(
        triage(
            sarif=secret_sarif,
            repo=REPO,
            revision="fixture-revision-001",
            backend=ReplayBackend(ROOT / "fixtures/replay/sample.json"),
            data_root=tmp_path / "restricted",
            authorization=load_authorization(ROOT / "fixtures/authorization.json"),
            authorization_path=ROOT / "fixtures/authorization.json",
        )
    )
    assert summary.terminal_state == TerminalState.RESTRICTED_EVIDENCE


def test_sandbox_and_network_capability_boundaries() -> None:
    sandbox = NoExecSandbox()
    assert sandbox.self_test().admitted
    with pytest.raises(PermissionError):
        sandbox.execute("target-code")
    network = network_self_test()
    assert not network.admitted
    assert network.network_observer == "observer_unavailable"


def test_egress_signature_is_expiring_and_verifiable() -> None:
    assert verify_egress_policy(signed_deny_egress_policy("test-run"))


def test_benchmark_registry_is_fail_closed() -> None:
    manifest = load_registry(ROOT / "evals/benchmark-registry.json")[0]
    admit(manifest, BenchmarkLane.REGRESSION)
    with pytest.raises(BenchmarkAdmissionError):
        admit(manifest, BenchmarkLane.RELEASE)
    with pytest.raises(BenchmarkAdmissionError):
        admit(manifest.model_copy(update={"rights_state": "unknown"}), BenchmarkLane.REGRESSION)
    assert dry_run(manifest, BenchmarkLane.REGRESSION)["execution_started"] is False


def test_search_and_tree_are_typed_bounded_tools() -> None:
    tools = ReadOnlyTools(REPO)
    tree, tree_decision = tools.list_tree(".", 2)
    matches, search_decision = tools.search("render", "src")
    assert tree_decision.allowed and "src/app.py" in tree
    assert search_decision.allowed and matches[0]["path"] == "src/app.py"


def test_replay_security_env_seals_grade_and_deterministically_scores_disposition() -> None:
    task = load_task(str(ROOT / "evals/replay-task.json"))
    env = ReplaySecurityEnv(
        task,
        HiddenGrade(
            finding_id="finding-fixture",
            expected_disposition="needs_review",
            required_citation_path="src/app.py",
        ),
    )
    observation, info = env.reset(seed=7, task_id=task.task_id)
    assert info.status == "ready"
    assert "expected_disposition" not in observation.model_dump_json()
    disposition = json.loads((ROOT / "fixtures/replay/sample.json").read_text())["result"]
    _, reward, terminated, truncated, result = env.step(
        SubmitDisposition(finding_id="finding-fixture", disposition=disposition)
    )
    assert terminated and not truncated and result.status == "success"
    assert reward.correctness == reward.evidence == reward.safety == 1


def test_replay_evaluation_persists_deterministic_result(tmp_path: Path) -> None:
    task = load_task(str(ROOT / "evals/replay-task.json"))
    visible = json.loads((ROOT / "fixtures/replay/sample.json").read_text())["result"]
    result = run_replay_evaluation(task=task, visible_disposition=visible, data_root=tmp_path)
    assert result.status == "success" and not result.execution_started
    assert (tmp_path / "evaluations" / f"{result.evaluation_id}.json").exists()


def test_bounded_diff_context_and_operational_views(tmp_path: Path) -> None:
    diff = bounded_diff(REPO, "src/app_before.py", "src/app.py")
    assert diff["diff"] and diff["coverage"] == ["bounded unified diff"]
    bundle = load_context(ROOT / "fixtures/context.json")
    validate_context(bundle)
    left = run(tmp_path, ReplayBackend(ROOT / "fixtures/replay/sample.json"))
    right = run(tmp_path, ReplayBackend(ROOT / "fixtures/replay/sample.json"))
    comparison = compare_runs(RunStore(tmp_path), left.run_id, right.run_id)
    assert comparison["same_dependency_closure"]
    assert reconcile_cost(RunStore(tmp_path), left.run_id, left.usage.model_dump())["matches"]
    assert retention_audit(tmp_path)["action"] == "audit_only_no_deletion"


def test_minikube_worker_admission_fails_closed_until_observer_is_verified() -> None:
    status = load_lab_status(ROOT / "fixtures/minikube-lab-status.json")
    assert admission_report(status)["admitted"] is False
    ready = MinikubeLabStatus.model_validate(
        {
            **status.model_dump(mode="json"),
            "cluster_running": True,
            "namespace_ready": True,
            "default_deny_enforced": True,
            "observer_healthy": True,
            "observer_mode": "host-side",
            "synthetic_oracle_healthy": True,
        }
    )
    assert admission_report(ready)["admitted"] is False
    experiment = sign_evidence(
        SyntheticExperimentEvidence(
            experiment_id="fixture-admission-experiment",
            profile="infosec-harness",
            namespace="infosec-harness-lab",
            minikube_version="v1.38.1",
            cni_identity="kindnet=test-image",
            oracle_cluster_ip="10.96.0.10",
            approved_job_uid="approved-job-uid",
            denied_job_uid="denied-job-uid",
            approved_log_artifact="sha256:" + "a" * 64,
            denied_log_artifact="sha256:" + "b" * 64,
            manifest_hashes={"oracle.yaml": "sha256:" + "c" * 64},
            recorded_at=datetime.now(UTC),
            signature="0" * 64,
        ),
        b"test-key",
    )
    observer_key = b"observer-test-key-material-at-least-32"
    observer = sign_observer_evidence(
        HostObserverEvidence(
            observer_id="fixture-observer",
            observer_mode="host-side",
            collector_version="fixture-v1",
            healthy=True,
            collected_at=datetime.now(UTC),
            flows=[
                ObservedFlow(
                    workload_id="minikube:synthetic-probe",
                    experiment_id=experiment.experiment_id,
                    verdict="allowed",
                    protocol="tcp",
                    destination_ip=experiment.oracle_cluster_ip,
                    destination_port=8080,
                    policy_decision_id="allowed-policy-decision",
                    observed_at=datetime.now(UTC),
                ),
                ObservedFlow(
                    workload_id="minikube:synthetic-probe",
                    experiment_id=experiment.experiment_id,
                    verdict="denied",
                    protocol="tcp",
                    destination_ip=experiment.oracle_cluster_ip,
                    destination_port=8080,
                    policy_decision_id="denied-policy-decision",
                    observed_at=datetime.now(UTC),
                ),
            ],
            signature="0" * 64,
        ),
        observer_key,
    )
    assert admission_report(ready, experiment, observer, observer_key)["admitted"] is True
    tampered = observer.model_copy(update={"collector_version": "tampered"})
    assert admission_report(ready, experiment, tampered, observer_key)["admitted"] is False


def test_synthetic_experiment_evidence_is_signed_and_fresh() -> None:
    evidence = SyntheticExperimentEvidence(
        experiment_id="fixture-experiment-001",
        profile="infosec-harness",
        namespace="infosec-harness-lab",
        minikube_version="v1.38.1",
        cni_identity="kindnet=test-image",
        oracle_cluster_ip="10.96.0.10",
        approved_job_uid="approved-job-uid",
        denied_job_uid="denied-job-uid",
        approved_log_artifact="sha256:" + "a" * 64,
        denied_log_artifact="sha256:" + "b" * 64,
        manifest_hashes={"oracle.yaml": "sha256:" + "c" * 64},
        recorded_at=datetime.now(UTC),
        signature="0" * 64,
    )
    signed = sign_evidence(evidence, b"test-key")
    verify_evidence(signed, b"test-key")
    with pytest.raises(LabEvidenceError, match="signature"):
        verify_evidence(signed.model_copy(update={"oracle_cluster_ip": "10.96.0.11"}), b"test-key")
    stale = sign_evidence(signed.model_copy(update={"recorded_at": datetime.now(UTC) - timedelta(hours=1)}), b"test-key")
    with pytest.raises(LabEvidenceError, match="stale"):
        verify_evidence(stale, b"test-key")


def test_live_experiment_collection_requires_an_explicit_single_kubeconfig(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("KUBECONFIG", raising=False)
    with pytest.raises(LabEvidenceError, match="explicit absolute KUBECONFIG"):
        _kubectl("isolated-profile", "get", "namespace", "example", "-o", "json")

    kubeconfig = tmp_path / "kubeconfig"
    kubeconfig.touch()
    calls: list[list[str]] = []

    class Completed:
        returncode = 0
        stdout = '{"items": []}'

    def fake_run(command, **_kwargs):
        calls.append(command)
        return Completed()

    monkeypatch.setenv("KUBECONFIG", str(kubeconfig))
    monkeypatch.setattr("infosec_harness.lab_evidence.subprocess.run", fake_run)
    assert _kubectl("isolated-profile", "get", "namespace", "example", "-o", "json") == {"items": []}
    assert calls == [
        [
            "kubectl",
            "--kubeconfig",
            str(kubeconfig),
            "--context",
            "isolated-profile",
            "get",
            "namespace",
            "example",
            "-o",
            "json",
        ]
    ]


def test_abox_worker_plan_is_sealed_safe_and_no_network(tmp_path: Path) -> None:
    workspace = tmp_path / "controller-workspace"
    (workspace / ".abox").mkdir(parents=True)
    (workspace / ".abox" / "project.toml").write_bytes((ROOT / ".abox" / "project.toml").read_bytes())
    sealed = tmp_path / "sealed.json"
    sealed.write_text('{"evidence_ref":"artifact:sha256:test"}')
    plan = plan_no_network_worker(workspace, sealed, "sealed-evidence-self-test")
    argv = plan.argv()
    assert "--network" in argv and argv[argv.index("--network") + 1] == "safe"
    assert "--ephemeral" in argv and "--no-warm" in argv
    assert "--input-file" in argv
    assert argv[-4:] == ["python3", "-I", "-c", argv[-1]]
    assert "ABOX_INPUT_FILE" in argv[-1]
    original_digest = plan.artifact.sha256
    sealed.write_text("changed after planning")
    assert plan.artifact.sha256 == original_digest
    assert plan.artifact.content != sealed.read_bytes()
    result = run_no_network_worker(plan)
    assert not result.admitted
    assert result.reason == "abox requires a controller-owned Git workspace"


def test_abox_worker_refuses_symlink_and_invalid_task(tmp_path: Path) -> None:
    workspace = tmp_path / "controller-workspace"
    (workspace / ".abox").mkdir(parents=True)
    (workspace / ".abox" / "project.toml").write_bytes((ROOT / ".abox" / "project.toml").read_bytes())
    sealed = tmp_path / "sealed.json"
    sealed.write_text("sealed")
    link = tmp_path / "sealed-link.json"
    link.symlink_to(sealed)
    with pytest.raises(AboxWorkerError, match="non-symlink"):
        plan_no_network_worker(workspace, link, "valid-task")
    with pytest.raises(AboxWorkerError, match="task"):
        plan_no_network_worker(workspace, sealed, "../invalid")
    (workspace / ".abox" / "project.toml").write_text("[network]\nmode = 'safe'\n")
    with pytest.raises(AboxWorkerError, match="approved safe profile"):
        plan_no_network_worker(workspace, sealed, "valid-task")
