"""CLI entry point; all normal commands are local and credential-free."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .abox_worker import plan_no_network_worker, run_live_self_test, run_no_network_worker
from .policy import (
    canonical_path,
    digest,
    load_authorization,
    signed_deny_egress_policy,
    verify_egress_policy,
)
from .providers import ReplayBackend
from .reports import cost_json, report_json, report_markdown
from .runtime import triage
from .sandbox import NoExecSandbox, network_self_test
from .stores import RunStore


def _data_root(value: str | None) -> Path:
    return Path(value or ".harness").resolve()


def command_policy_self_test() -> int:
    root = Path.cwd().resolve()
    policy = signed_deny_egress_policy("self-test")
    ok = verify_egress_policy(policy)
    try:
        canonical_path(root, "../escape")
    except Exception:
        path_denied = True
    else:
        path_denied = False
    print(json.dumps({"ok": ok and path_denied, "path_traversal_denied": path_denied, "egress_signature_valid": ok}))
    return 0 if ok and path_denied else 1


def command_sandbox_self_test() -> int:
    sandbox = NoExecSandbox()
    report = sandbox.self_test()
    refused = False
    try:
        sandbox.execute("untrusted")
    except PermissionError:
        refused = True
    print(json.dumps({**report.__dict__, "execution_refused": refused}, sort_keys=True))
    return 0 if report.admitted and refused else 1


def command_network_self_test() -> int:
    report = network_self_test()
    print(json.dumps({**report.__dict__, "fail_closed": not report.admitted}, sort_keys=True))
    # A capability gap is an expected healthy result: no networked worker can start.
    return 0 if not report.admitted and report.network_observer == "observer_unavailable" else 1


def command_observer_self_test() -> int:
    from .host_observer import observer_self_test

    report = observer_self_test()
    print(json.dumps(report.model_dump(), sort_keys=True))
    return 0 if not report.admitted else 1


def command_sbom() -> int:
    policy = Path("policies/runtime-dependencies.json")
    print(
        json.dumps(
            {
                "format": "minimal-runtime-sbom",
                "dependency_admission": json.loads(policy.read_text()),
                "uv_lock_hash": digest(Path("uv.lock").read_bytes()),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def command_benchmark_self_test() -> int:
    from .benchmarks import BenchmarkLane, admit, load_registry

    manifests = load_registry(Path("evals/benchmark-registry.json"))
    for manifest in manifests:
        admit(manifest, BenchmarkLane.REGRESSION)
    print(json.dumps({"ok": True, "admitted_regression_tasks": [item.task_id for item in manifests]}))
    return 0


def command_benchmark_dry_run(task_id: str, lane: str) -> int:
    from .benchmarks import BenchmarkLane, dry_run, load_registry

    requested_lane = BenchmarkLane(lane)
    manifests = load_registry(Path("evals/benchmark-registry.json"))
    manifest = next((item for item in manifests if item.task_id == task_id), None)
    if manifest is None:
        raise KeyError(f"unknown benchmark task: {task_id}")
    print(json.dumps(dry_run(manifest, requested_lane), sort_keys=True))
    return 0


def command_evaluate_replay(task_path: Path, replay_fixture: Path, data_root: Path) -> int:
    from .evaluation import run_replay_evaluation
    from .gym import load_task

    visible = json.loads(replay_fixture.read_text(encoding="utf-8"))["result"]
    result = run_replay_evaluation(task=load_task(str(task_path)), visible_disposition=visible, data_root=data_root)
    print(json.dumps(result.model_dump(mode="json"), sort_keys=True))
    return 0 if result.status == "success" else 2


def command_diff_review(repo: Path, before: str, after: str) -> int:
    from .offline import bounded_diff

    print(json.dumps(bounded_diff(repo, before, after), indent=2, sort_keys=True))
    return 0


def command_context_self_test(path: Path) -> int:
    from .offline import load_context, validate_context

    bundle = load_context(path)
    validate_context(bundle)
    print(json.dumps({"ok": True, "bundle_id": bundle.bundle_id, "gaps": bundle.gaps}, sort_keys=True))
    return 0


def command_compare_runs(left: str, right: str, data_root: Path) -> int:
    from .offline import compare_runs

    print(json.dumps(compare_runs(RunStore(data_root), left, right), indent=2, sort_keys=True))
    return 0


def command_retention_audit(data_root: Path) -> int:
    from .offline import retention_audit

    print(json.dumps(retention_audit(data_root), indent=2, sort_keys=True))
    return 0


def command_cost_reconcile(run_id: str, usage_json: Path, data_root: Path) -> int:
    from .offline import reconcile_cost

    usage = json.loads(usage_json.read_text(encoding="utf-8"))
    print(json.dumps(reconcile_cost(RunStore(data_root), run_id, usage), indent=2, sort_keys=True))
    return 0


def command_minikube_admission(
    status_path: Path,
    data_root: Path,
    experiment_path: Path,
    observer_path: Path,
    observer_key_path: Path,
) -> int:
    from .host_observer import HostObserverEvidence, load_observer_key
    from .lab_evidence import load_and_verify_evidence
    from .minikube_lab import admission_report, load_lab_status

    experiment = load_and_verify_evidence(data_root, experiment_path) if experiment_path.exists() else None
    observer = HostObserverEvidence.model_validate_json(observer_path.read_text()) if observer_path.exists() else None
    observer_key = load_observer_key(observer_key_path) if observer is not None else None
    report = admission_report(load_lab_status(status_path), experiment, observer, observer_key)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["admitted"] else 2


def command_record_minikube_experiment(data_root: Path, profile: str, namespace: str) -> int:
    from .lab_evidence import record_live_experiment

    evidence, artifact_hash = record_live_experiment(data_root, profile, namespace)
    print(
        json.dumps(
            {
                "artifact_hash": artifact_hash,
                "cni_identity": evidence.cni_identity,
                "evidence_id": evidence.experiment_id,
                "oracle_cluster_ip": evidence.oracle_cluster_ip,
                "recorded_at": evidence.recorded_at.isoformat(),
                "signed": True,
            },
            sort_keys=True,
        )
    )
    return 0


def command_abox_worker_plan(workspace: Path, sealed_input: Path, task_id: str) -> int:
    plan = plan_no_network_worker(workspace, sealed_input, task_id)
    print(
        json.dumps(
            {
                "admitted": True,
                "artifact_sha256": plan.artifact.sha256,
                "argv": plan.argv(),
                "network_mode": "safe",
                "target_execution": False,
                "task_id": plan.task_id,
            },
            sort_keys=True,
        )
    )
    return 0


def command_abox_worker_self_test(workspace: Path, sealed_input: Path, task_id: str) -> int:
    result = run_no_network_worker(plan_no_network_worker(workspace, sealed_input, task_id))
    print(json.dumps(result.__dict__, sort_keys=True))
    return 0 if result.verified else 2


def command_abox_worker_live_self_test(project_config: Path, sealed_input: Path) -> int:
    result = run_live_self_test(project_config, sealed_input)
    print(json.dumps(result.__dict__, sort_keys=True))
    return 0 if result.verified else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="infosec-harness")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in (
        "policy-self-test",
        "sandbox-self-test",
        "network-self-test",
        "observer-self-test",
        "sbom",
        "benchmark-self-test",
    ):
        sub.add_parser(name)
    benchmark_dry_run = sub.add_parser("benchmark-dry-run")
    benchmark_dry_run.add_argument("task_id")
    benchmark_dry_run.add_argument("--lane", choices=["regression", "release", "defensive_research", "high_risk_capability"], required=True)
    evaluate_replay = sub.add_parser("evaluate-replay")
    evaluate_replay.add_argument("--task", type=Path, default=Path("evals/replay-task.json"))
    evaluate_replay.add_argument("--replay-fixture", type=Path, default=Path("fixtures/replay/sample.json"))
    evaluate_replay.add_argument("--data-root")
    diff_review = sub.add_parser("diff-review")
    diff_review.add_argument("repo", type=Path)
    diff_review.add_argument("before")
    diff_review.add_argument("after")
    context_self_test = sub.add_parser("context-self-test")
    context_self_test.add_argument("--context", type=Path, default=Path("fixtures/context.json"))
    compare = sub.add_parser("compare-runs")
    compare.add_argument("left")
    compare.add_argument("right")
    compare.add_argument("--data-root")
    retention = sub.add_parser("retention-audit")
    retention.add_argument("--data-root")
    reconcile = sub.add_parser("cost-reconcile")
    reconcile.add_argument("run_id")
    reconcile.add_argument("usage_json", type=Path)
    reconcile.add_argument("--data-root")
    lab_admission = sub.add_parser("minikube-lab-admission")
    lab_admission.add_argument("--status", type=Path, default=Path("fixtures/minikube-lab-status.json"))
    lab_admission.add_argument("--experiment-evidence", type=Path, default=Path(".harness/minikube-lab/latest.json"))
    lab_admission.add_argument("--observer-evidence", type=Path, default=Path(".harness/host-observer/latest.json"))
    lab_admission.add_argument("--observer-key", type=Path, default=Path(".harness/host-observer/key"))
    lab_admission.add_argument("--data-root")
    lab_record = sub.add_parser("minikube-lab-record-experiment")
    lab_record.add_argument("--profile", default="infosec-harness")
    lab_record.add_argument("--namespace", default="infosec-harness-lab")
    lab_record.add_argument("--data-root")
    for name in ("abox-worker-plan", "abox-worker-self-test"):
        worker = sub.add_parser(name)
        worker.add_argument("sealed_input", type=Path)
        worker.add_argument("--workspace", type=Path, default=Path("."))
        worker.add_argument("--task-id", default="sealed-evidence-self-test")
    live_worker = sub.add_parser("abox-worker-live-self-test")
    live_worker.add_argument("sealed_input", type=Path)
    live_worker.add_argument("--project-config", type=Path, default=Path(".abox/project.toml"))
    triage_parser = sub.add_parser("triage")
    triage_parser.add_argument("sarif", type=Path)
    triage_parser.add_argument("repo", type=Path)
    triage_parser.add_argument("revision")
    triage_parser.add_argument("--backend", choices=["replay"], default="replay")
    triage_parser.add_argument("--replay-fixture", type=Path, default=Path("fixtures/replay/sample.json"))
    triage_parser.add_argument("--data-root")
    triage_parser.add_argument("--authorization", type=Path, default=Path("fixtures/authorization.json"))
    triage_parser.add_argument("--deny-tool-path")
    triage_parser.add_argument("--sandbox-unhealthy", action="store_true")
    triage_parser.add_argument("--network-observer-unhealthy", action="store_true")
    for name in ("report", "cost-report"):
        item = sub.add_parser(name)
        item.add_argument("run_id")
        item.add_argument("--data-root")
    args = parser.parse_args(argv)
    if args.command == "policy-self-test":
        return command_policy_self_test()
    if args.command == "sandbox-self-test":
        return command_sandbox_self_test()
    if args.command == "network-self-test":
        return command_network_self_test()
    if args.command == "observer-self-test":
        return command_observer_self_test()
    if args.command == "sbom":
        return command_sbom()
    if args.command == "benchmark-self-test":
        return command_benchmark_self_test()
    if args.command == "benchmark-dry-run":
        return command_benchmark_dry_run(args.task_id, args.lane)
    if args.command == "evaluate-replay":
        return command_evaluate_replay(args.task, args.replay_fixture, _data_root(args.data_root))
    if args.command == "diff-review":
        return command_diff_review(args.repo, args.before, args.after)
    if args.command == "context-self-test":
        return command_context_self_test(args.context)
    if args.command == "compare-runs":
        return command_compare_runs(args.left, args.right, _data_root(args.data_root))
    if args.command == "retention-audit":
        return command_retention_audit(_data_root(args.data_root))
    if args.command == "cost-reconcile":
        return command_cost_reconcile(args.run_id, args.usage_json, _data_root(args.data_root))
    if args.command == "minikube-lab-admission":
        return command_minikube_admission(
            args.status,
            _data_root(args.data_root),
            args.experiment_evidence,
            args.observer_evidence,
            args.observer_key,
        )
    if args.command == "minikube-lab-record-experiment":
        return command_record_minikube_experiment(_data_root(args.data_root), args.profile, args.namespace)
    if args.command == "abox-worker-plan":
        return command_abox_worker_plan(args.workspace, args.sealed_input, args.task_id)
    if args.command == "abox-worker-self-test":
        return command_abox_worker_self_test(args.workspace, args.sealed_input, args.task_id)
    if args.command == "abox-worker-live-self-test":
        return command_abox_worker_live_self_test(args.project_config, args.sealed_input)
    if args.command == "triage":
        summary = asyncio.run(
            triage(
                sarif=args.sarif,
                repo=args.repo,
                revision=args.revision,
                backend=ReplayBackend(args.replay_fixture),
                data_root=_data_root(args.data_root),
                authorization=load_authorization(args.authorization),
                authorization_path=args.authorization,
                requested_tool_path=args.deny_tool_path,
                sandbox_healthy=not args.sandbox_unhealthy,
                network_observer_healthy=not args.network_observer_unhealthy,
            )
        )
        print(f"RUN_ID={summary.run_id}")
        print(f"TERMINAL_STATE={summary.terminal_state.value}")
        return 0 if summary.terminal_state.value == "complete" else 2
    summary = RunStore(_data_root(args.data_root)).get(args.run_id)
    if args.command == "report":
        print(report_markdown(summary))
        print(report_json(summary))
    else:
        print(cost_json(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
