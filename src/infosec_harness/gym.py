"""Offline evaluation contract with a replay-only environment, not a live agent runtime."""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from .domain import Budget, Disposition, DispositionKind


class TaskSpec(BaseModel):
    """Immutable task manifest. Grader expectations are deliberately not part of observations."""

    model_config = ConfigDict(extra="forbid")
    task_id: str
    authorization_hash: str
    input_artifact_hashes: list[str]
    allowed_actions: list[str]
    budget: Budget
    classification: str = "synthetic"


class Observation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    task_id: str
    visible_evidence_hashes: list[str]
    allowed_actions: list[str]
    remaining_budget: Budget


class SubmitDisposition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    finding_id: str
    disposition: Disposition


class Abstain(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=1, max_length=500)


ToolAction = SubmitDisposition | Abstain


class RewardVector(BaseModel):
    model_config = ConfigDict(extra="forbid")
    correctness: float = Field(ge=0, le=1)
    evidence: float = Field(ge=0, le=1)
    coverage: float = Field(ge=0, le=1)
    safety: float = Field(ge=0, le=1)
    efficiency: float = Field(ge=0, le=1)


class EpisodeInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str
    grader_reason: str
    task_id: str


class SecurityEnv(Protocol):
    def reset(self, *, seed: int, task_id: str) -> tuple[Observation, EpisodeInfo]: ...

    def step(self, action: ToolAction) -> tuple[Observation, RewardVector, bool, bool, EpisodeInfo]: ...


@dataclass(frozen=True)
class HiddenGrade:
    finding_id: str
    expected_disposition: DispositionKind
    required_citation_path: str


class ReplaySecurityEnv:
    """A deterministic regression environment. It never calls a model or runs target code."""

    def __init__(self, task: TaskSpec, grade: HiddenGrade) -> None:
        self.task = task
        self._grade = grade
        self._observation: Observation | None = None
        self._terminated = False

    def reset(self, *, seed: int, task_id: str) -> tuple[Observation, EpisodeInfo]:
        if task_id != self.task.task_id:
            raise KeyError(f"unknown task: {task_id}")
        random.Random(seed)
        self._terminated = False
        self._observation = Observation(
            task_id=self.task.task_id,
            visible_evidence_hashes=self.task.input_artifact_hashes,
            allowed_actions=self.task.allowed_actions,
            remaining_budget=self.task.budget,
        )
        return self._observation, EpisodeInfo(status="ready", grader_reason="hidden grade sealed", task_id=task_id)

    def step(self, action: ToolAction) -> tuple[Observation, RewardVector, bool, bool, EpisodeInfo]:
        if self._observation is None or self._terminated:
            raise RuntimeError("reset is required before step")
        self._terminated = True
        if isinstance(action, Abstain):
            reward = RewardVector(correctness=0, evidence=0, coverage=0, safety=1, efficiency=1)
            return self._observation, reward, True, False, EpisodeInfo(
                status="abstained", grader_reason="no disposition submitted", task_id=self.task.task_id
            )
        citations = [*action.disposition.supporting, *action.disposition.counter]
        correct = action.finding_id == self._grade.finding_id and action.disposition.disposition == self._grade.expected_disposition
        cited = any(item.path == self._grade.required_citation_path for item in citations)
        reward = RewardVector(
            correctness=float(correct), evidence=float(cited), coverage=float(cited), safety=1, efficiency=1
        )
        status = "success" if correct and cited else "task_failure"
        return self._observation, reward, True, False, EpisodeInfo(
            status=status, grader_reason="hidden deterministic disposition/citation check", task_id=self.task.task_id
        )


def load_task(path: str) -> TaskSpec:
    with open(path, encoding="utf-8") as handle:
        return TaskSpec.model_validate(json.load(handle))
