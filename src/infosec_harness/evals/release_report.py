"""The release report: one complete experiment's metrics, judged against the agent's policy.

The report speaks the policy's language -- ``hard_gates`` and ``metrics`` carry exactly the
values the policy names -- and records the policy's verdict (``gate_evaluation``) and which of
its checks could not have failed for this run (``inert_checks``) beside the numbers, so a pass
is never read without the evidence-quality facts that qualify it. Provenance is what makes a
pass reproducible rather than a claim, and the policy's ``required_provenance`` makes a report
without it ``not_checked``.

``run`` says what the numbers are over (split, repetitions, case-set digest); ``provenance``
says what produced them. Each fact is recorded in exactly one of the two. Every evaluator in
this suite is deterministic -- there is no LLM judge -- and case-level results stay in the
experiment store under ``provenance.experiment_id``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from infosec_harness._io import write_json
from infosec_harness.evals.gates import ReleasePolicy
from infosec_harness.evals.inert_gates import find_inert_checks, format_inert_notice


def report_provenance(
    *, code_identity: Mapping[str, Any], comparison_identity: Mapping[str, Any],
    agent_version: str, cfg_hash: str, model_name: str, pricing: str, experiment_id: str,
    spec: Any,
) -> dict[str, Any]:
    """What produced a run, captured before its first case.

    Built once by the runner and used both for the stored experiment's gate verdict and for
    the report, so the two cannot disagree about which provenance a run carried. Recomputing
    the code identity later could attach a different dirty-tree digest if the worktree changed
    during a long run.
    """
    metadata = spec.metadata or {}
    return {
        **code_identity,
        "agent_version": agent_version,
        "config_hash": cfg_hash,
        "model": model_name,
        "model_pricing": pricing,
        "dataset": comparison_identity.get("dataset"),
        "dataset_version": comparison_identity.get("dataset_version"),
        "execution_mode": comparison_identity.get("execution_mode"),
        "evaluator_version": comparison_identity.get("evaluator_version"),
        "experiment_id": experiment_id,
        "model_settings": dict(spec.model_settings or {}),
        "skills": list(metadata.get("enabled_skills") or []),
        "toolsets": list(metadata.get("enabled_toolsets") or []),
    }


def write_release_report(
    path: Path, *, agent: str, metrics: Mapping[str, Any], provenance: Mapping[str, Any],
    policy: ReleasePolicy, echo: Callable[[str], None] = print,
) -> dict[str, Any]:
    """Publish the report atomically and print the inert-gate audit beside it."""
    identity = metrics.get("comparison_identity") or {}
    present = {name: metrics[name] for name in policy.metrics_named if name in metrics}
    recorded = {**provenance, "recorded_at": datetime.now(UTC).isoformat()}
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
        "gate_evaluation": policy.evaluate(metrics, provenance=recorded).as_report(),
        # The playbook makes uncovered material risk a release blocker, so the report carries
        # covered *and uncovered* scenario IDs for the cases this run actually used.
        "coverage": metrics.get("scenario_coverage") or {},
        # Distributions, not just means: a single average cannot show the tail a budget
        # exists to brake.
        "distributions": metrics.get("distributions", {}),
        "provenance": recorded,
    }
    inert = find_inert_checks(report, policy)
    report["inert_checks"] = [check.as_report() for check in inert]
    write_json(path, report)
    # A threshold on a metric this run could not move looks like coverage and is none: say
    # so next to the evidence, loudly, without changing the run's verdict.
    echo(format_inert_notice(inert, subject=agent, policy=policy))
    echo(f"release report written to {path} (gates {report['gate_evaluation']['status']})")
    return report
