"""Deterministic replay evaluation runner; it does not execute benchmark targets."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from .domain import Disposition, DispositionKind
from .gym import HiddenGrade, ReplaySecurityEnv, SubmitDisposition, TaskSpec
from .policy import digest


class EvaluationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    evaluation_id: str
    task_id: str
    status: str
    reward: dict[str, float]
    task_manifest_hash: str
    created_at: datetime
    execution_started: bool = False


def run_replay_evaluation(
    *, task: TaskSpec, visible_disposition: dict[str, object], data_root: Path
) -> EvaluationResult:
    """Grade a visible replay disposition against a sealed deterministic rule."""
    grade = HiddenGrade(
        finding_id="finding-fixture",
        expected_disposition=DispositionKind.NEEDS_REVIEW,
        required_citation_path="src/app.py",
    )
    env = ReplaySecurityEnv(task, grade)
    env.reset(seed=0, task_id=task.task_id)
    _, reward, terminated, truncated, info = env.step(
        SubmitDisposition(finding_id="finding-fixture", disposition=Disposition.model_validate(visible_disposition))
    )
    if not terminated or truncated:
        raise RuntimeError("replay environment did not reach a valid terminal state")
    task_hash = digest(task.model_dump_json())
    evaluation_id = f"eval-{digest(f'{task_hash}|{info.status}')[7:23]}"
    result = EvaluationResult(
        evaluation_id=evaluation_id,
        task_id=task.task_id,
        status=info.status,
        reward=reward.model_dump(),
        task_manifest_hash=task_hash,
        created_at=datetime.now(UTC),
    )
    directory = data_root / "evaluations"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{evaluation_id}.json").write_text(
        json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result
