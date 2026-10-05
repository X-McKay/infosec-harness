"""The release report: one complete experiment's metrics, judged against the agent's policy.

The report speaks the policy's language -- ``hard_gates`` and ``metrics`` carry exactly the
values the policy names -- and records the policy's verdict (``gate_evaluation``) and which of
its checks could not have failed for this run (``inert_checks``) beside the numbers, so a pass
is never read without the evidence-quality facts that qualify it. Provenance is what makes a
pass reproducible rather than a claim.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from infosec_harness.evals._json import write_json
from infosec_harness.evals.gates import ReleasePolicy, load_policy
from infosec_harness.evals.inert_gates import find_inert_checks, format_inert_notice

# Every check here is deterministic; there is no LLM judge anywhere in this suite.
EVALUATORS = ("deterministic_output_match", "schema_validity", "budget_gate", "scenario_coverage")


def build_release_report(
    *, agent: str, metrics: Mapping[str, Any], policy: ReleasePolicy, cfg_hash: str,
    model_name: str, pricing: str, dataset_path: str, agent_version: str, experiment_id: str,
    spec: object | None = None,
) -> dict[str, Any]:
    identity = metrics.get("comparison_identity") or {}
    present = {name: metrics[name] for name in policy.metrics_named if name in metrics}
    report: dict[str, Any] = {
        "schema_version": 1,
        "subject": {"kind": "agent", "name": agent},
        "agent": agent,
        # What the numbers are over. Only `status == "complete"` with n == n_planned describes
        # the whole selected case set, and only `split == "full"` is the whole dataset.
        "run": {
            "status": metrics.get("status"),
            "split": identity.get("split"),
            "n": metrics.get("n"),
            "n_planned": metrics.get("n_planned"),
            "cases_planned": metrics.get("cases_planned"),
            "repetitions": identity.get("repetitions"),
            "case_set_digest": identity.get("case_set_digest"),
        },
        "hard_gates": {name: present[name] for name in policy.hard_gates if name in present},
        "metrics": {name: present[name] for name in policy.thresholds if name in present},
        "gate_evaluation": policy.evaluate(metrics).as_report(),
        # The playbook makes uncovered material risk a release blocker, so the report carries
        # covered *and uncovered* scenario IDs for the cases this run actually used.
        "coverage": metrics.get("scenario_coverage") or {},
        # Distributions, not just means: a single average cannot show the tail a budget
        # exists to brake.
        "distributions": metrics.get("distributions", {}),
        "provenance": {
            # Captured before the first case; recomputing it now could attach a different
            # dirty-tree digest if the worktree changed during a long run.
            **(metrics.get("code_identity") or {}),
            "agent_version": agent_version,
            "config_hash": cfg_hash,
            "model": model_name,
            "model_pricing": pricing,
            "dataset": dataset_path,
            "dataset_version": identity.get("dataset_version"),
            "case_set_digest": identity.get("case_set_digest"),
            "split": identity.get("split"),
            "execution_mode": identity.get("execution_mode"),
            "evaluator_version": identity.get("evaluator_version"),
            "recorded_at": datetime.now(UTC).isoformat(),
            "run_count": identity.get("repetitions"),
            "experiment_id": experiment_id,
            "evaluators": list(EVALUATORS),
            # Recorded explicitly so the absence of a judge is a stated fact, not an omission:
            # the playbook forbids one as the sole evaluator for schema validity and safety.
            "judge_rubric": None,
            "model_settings": dict(getattr(spec, "model_settings", None) or {}),
            "skills": list((getattr(spec, "metadata", None) or {}).get("enabled_skills") or []),
            "toolsets": list(
                (getattr(spec, "metadata", None) or {}).get("enabled_toolsets") or []),
            # Case-level results are persisted under this id rather than inlined.
            "case_results": f"experiment {experiment_id}" if experiment_id else None,
        },
    }
    report["inert_checks"] = [check.as_report() for check in find_inert_checks(report, policy.raw)]
    return report


def write_release_report(
    path: Path, *, agent: str, metrics: Mapping[str, Any], cfg_hash: str, model_name: str,
    pricing: str, dataset_path: str, agent_version: str, experiment_id: str = "",
    spec: object | None = None, policy: ReleasePolicy | None = None,
    echo: Callable[[str], None] = print,
) -> dict[str, Any]:
    """Publish the report atomically and print the inert-gate audit beside it."""
    policy = policy or load_policy(agent)
    report = build_release_report(
        agent=agent, metrics=metrics, policy=policy, cfg_hash=cfg_hash, model_name=model_name,
        pricing=pricing, dataset_path=dataset_path, agent_version=agent_version,
        experiment_id=experiment_id, spec=spec,
    )
    inert = find_inert_checks(report, policy.raw)
    write_json(path, report)
    # A threshold on a metric this run could not move looks like coverage and is none: say
    # so next to the evidence, loudly, without changing the run's verdict.
    echo(format_inert_notice(inert, subject=agent, policy=dict(policy.raw)))
    echo(f"release report written to {path} (gates {report['gate_evaluation']['status']})")
    return report
