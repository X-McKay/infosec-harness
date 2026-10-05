"""The qualification run for a release: every agent's full dataset, live, at one clean commit.

A release is qualified when every agent's release policy is ``passed`` on a live model for the
exact commit being released. The preconditions are refusals rather than warnings: a stub run
measures no agent, and a run from a dirty tree names a commit that did not contain the code it
measured. Reports land under ``HARNESS_REPORTS_DIR/release/<commit>/`` with a ``summary.json``
beside them; with ``save_baselines`` every passing run is also recorded as the committed
baseline through the ordinary baseline rules, so their refusals still apply.

Execution-backed gates (``build-repair``'s execution checks, for example) need a host whose
sandbox runtime actually executes (``runsc``). Without one those checks are ``not_checked``,
and ``execution_not_checked_count`` fails its gate by design: an unexecuted check is not a pass.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from infosec_harness._io import write_json
from infosec_harness.evals.provenance import CodeVersion, code_version
from infosec_harness.evals.reporting import (
    EvalOutcome,
    packaged_eval_agents,
    run_evals,
    save_baseline,
)
from infosec_harness.settings import Settings, get_settings


class ReleaseRefused(SystemExit):
    """A precondition of a release qualification run does not hold; nothing was run."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"release qualification refused: {reason}")


def release_refusal(settings: Settings | None = None, code: CodeVersion | None = None) -> str | None:
    """Why a release qualification cannot run here, or ``None`` when it can."""
    settings = settings or get_settings()
    if settings.model_mode == "stub":
        return ("HARNESS_MODEL_MODE=stub measures no agent. Configure a live model "
                "(docs/development/LOCAL_SETUP.md, Live models) and set HARNESS_MODEL_MODE=live.")
    code = code or code_version()
    if not code.git_commit:
        return "there is no git commit to qualify. Run it from a source checkout."
    if code.git_dirty:
        return (f"the working tree differs from {code.git_commit[:12]}, so the results would "
                "not describe that commit. Commit or remove the changes first.")
    return None


def release_dir(commit: str) -> Path:
    return get_settings().reports_dir / "release" / commit


def _agents(selected: list[str] | None) -> list[str]:
    available = packaged_eval_agents()
    unknown = sorted(set(selected or []) - set(available))
    if unknown:
        raise ReleaseRefused(f"no packaged eval dataset for {unknown}; available: {available}")
    return [agent for agent in available if not selected or agent in selected]


async def qualify_release(agents: list[str] | None = None, *, model: str | None = None,
                          save_baselines: bool = False) -> tuple[list[EvalOutcome], int]:
    """Run the qualification and return its outcomes and exit status (0 only if all passed)."""
    if reason := release_refusal():
        raise ReleaseRefused(reason)
    selected = _agents(agents)
    code = code_version()
    directory = release_dir(code.git_commit)
    outcomes = await run_evals(selected, [model] if model else None, report_dir=directory)
    passed = [o for o in outcomes if o.status == "complete" and o.gate_status == "passed"]
    baselines: dict[str, str] = {}
    if save_baselines:
        # After every run, so writing baseline files cannot change what a later run measured.
        for outcome in passed:
            try:
                baselines[outcome.experiment_id] = str(await save_baseline(outcome.experiment_id))
            except SystemExit as refusal:
                print(f"  {outcome.agent}: {refusal}")
                baselines[outcome.experiment_id] = f"refused: {refusal}"
    status = 0 if len(passed) == len(outcomes) and not any(
        value.startswith("refused") for value in baselines.values()) else 1
    summary = directory / "summary.json"
    write_json(summary, {
        "schema_version": 1,
        "commit": code.git_commit,
        "harness_version": code.harness_version,
        "recorded_at": datetime.now(UTC).isoformat(),
        "model_tier": model,
        "status": "passed" if status == 0 else "failed",
        "runs": [{
            "agent": o.agent, "model": o.model, "experiment_id": o.experiment_id,
            "status": o.status, "n": o.metrics.get("n"), "n_planned": o.metrics.get("n_planned"),
            "task_success_rate": o.metrics.get("task_success_rate"),
            "gate_status": o.gate_status, "failing_checks": o.failing_checks,
            "report": str(o.report) if o.report else None,
            "baseline": baselines.get(o.experiment_id),
        } for o in outcomes],
    })
    print(f"\nrelease {code.git_commit[:12]}: "
          f"{'PASSED' if status == 0 else 'NOT QUALIFIED'} "
          f"({len(passed)}/{len(outcomes)} runs passed their release policy); summary {summary}")
    return outcomes, status

