"""The application's contracts; provider and workflow SDKs own their own protocols."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Literal, NamedTuple

from pydantic import BaseModel, ConfigDict, Field, model_validator

# The workflow generation: a breaking workflow change bumps it, which also renames the default
# task queue and the run-id prefix, so old workers and histories drain separately.
GENERATION = "v11"
# Report bounds shared by the verdict contract and the workflow that writes the report.
MAX_EVIDENCE_IDS = 10
MAX_SUMMARY_CHARS = 12_000


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Finding(Contract):
    title: str = Field(min_length=1, max_length=1000)
    description: str = Field(default="", max_length=100_000)
    repo_url: str = Field(min_length=1, max_length=4000)
    revision: str = Field(default="HEAD", min_length=1, max_length=200)
    source_mode: Literal["git_revision", "working_snapshot"] = "git_revision"
    file_path: str | None = Field(default=None, max_length=4000)
    cwe: str | None = Field(default=None, pattern=r"^CWE-[0-9]+$")


class Limits(Contract):
    max_requests: int = Field(default=30, ge=1, le=100)
    max_tool_calls: int = Field(default=100, ge=1, le=300)
    total_tokens: int = Field(default=300_000, ge=1, le=2_000_000)
    timeout_seconds: int = Field(default=1800, ge=1, le=7200)
    command_timeout_seconds: int = Field(default=120, ge=1, le=600)


class InvestigationRequest(Contract):
    finding: Finding
    limits: Limits = Field(default_factory=Limits)
    expected_worker_identity: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class WorkerIdentity(Contract):
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    code_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    dependencies: dict[str, str]


class Citation(Contract):
    path: str = Field(min_length=1, max_length=4000)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)

    @model_validator(mode="after")
    def ordered(self) -> Citation:
        if self.end_line < self.start_line:
            raise ValueError("citation line range is reversed")
        return self


class Verdict(Contract):
    label: Literal["potentially_exploitable", "likely_not_exploitable", "inconclusive"]
    summary: str = Field(min_length=1, max_length=MAX_SUMMARY_CHARS)
    evidence_ids: list[str] = Field(default_factory=list, max_length=MAX_EVIDENCE_IDS)
    citations: list[Citation] = Field(default_factory=list, max_length=30)
    # Earlier complete probes the investigator disowns as flawed; each must predate the
    # cited probe and the summary must explain the flaw. They stay in the report.
    superseded_evidence_ids: list[str] = Field(default_factory=list, max_length=MAX_EVIDENCE_IDS)


# The HARNESS_PROBE claims: four prerequisites and the observation they qualify.
PROBE_PREREQUISITES = ("target_reached", "oracle_valid", "positive_control", "negative_control")
PROBE_FIELDS = (*PROBE_PREREQUISITES, "vulnerability_observed")


class Evidence(Contract):
    """Process fields are observed; text and observations remain untrusted claims."""

    id: str
    kind: Literal["command", "probe"]
    command: str
    exit_code: int | None
    stdout: str = ""
    stderr: str = ""
    # Reserved and currently always False: an in-sandbox kill at the command budget surfaces
    # as exit 137 with observations["timeout_feedback"]. Kept so v11 histories still decode;
    # removing it is a v12 change.
    timed_out: bool = False
    output_truncated: bool = False
    sandbox_id: str
    source_digest: str
    observations: dict[str, bool | str | int | None] = Field(default_factory=dict)

    @property
    def complete_verified_probe(self) -> bool:
        """Qualified observation claims; callers must establish receipt/source provenance."""
        return (
            self.kind == "probe"
            and self.exit_code == 0
            and not self.timed_out
            and not self.output_truncated
            and isinstance(self.observations.get("workspace_digest"), str)
            and self.observations.get("source_verified") is True
            and all(self.observations.get(key) is True for key in PROBE_PREREQUISITES)
            and type(self.observations.get("vulnerability_observed")) is bool
        )

    def excerpt(self, limit: int = 4096) -> Evidence:
        """Bound command/output text; ``report_excerpted`` is computed from the full values."""
        fields = {key: getattr(self, key) for key in ("command", "stdout", "stderr")}
        excerpted = any(len(value.encode()) > limit for value in fields.values())
        return self.model_copy(
            update={
                **{key: value.encode()[:limit].decode(errors="ignore") for key, value in fields.items()},
                "observations": {**self.observations, "report_excerpted": excerpted},
            }
        )


class Support(NamedTuple):
    """The admission rule's decision for one definitive verdict."""

    # Source citations plus a cited complete probe whose observation matches the label.
    corroborated: bool
    # Qualified probes that contradict the label and were not superseded; any one blocks it.
    contrary: list[Evidence]
    # Qualified contradicting probes the verdict superseded and the ordering rule excused.
    superseded: list[Evidence]


def definitive_support(verdict: Verdict, evidence: Iterable[Evidence]) -> Support:
    """Decide whether the evidence admits a definitive verdict.

    Pure admission rule: source citations plus a cited complete source-verified probe whose
    ``vulnerability_observed`` matches the label; any contrary qualified probe blocks it.
    Callers own evidence provenance and must build ``evidence`` independently.
    """
    expected = verdict.label == "potentially_exploitable"
    qualified = [item for item in evidence if item.complete_verified_probe]
    cited = [
        item
        for item in qualified
        if item.id in verdict.evidence_ids
        and item.observations["vulnerability_observed"] is expected
    ]
    corroborated = bool(verdict.citations) and bool(cited)
    # A flawed earlier probe may be superseded only by a newer cited one: a contrary probe
    # that ran after the citation can never be disowned.
    latest_cited = max((probe_step(item.id) for item in cited), default=-1)
    excused = {
        identity
        for identity in verdict.superseded_evidence_ids
        if -1 < probe_step(identity) < latest_cited
    }
    contrary: list[Evidence] = []
    superseded: list[Evidence] = []
    for item in qualified:
        if item.observations["vulnerability_observed"] is not expected:
            (superseded if item.id in excused else contrary).append(item)
    return Support(corroborated, contrary, superseded)


# Evidence ids are ``<kind>:<agent run step>:<tool call id>`` (built in tools/execute.py).
EVIDENCE_ID = re.compile(r"[a-z]+:([0-9]{1,9}):.+", re.DOTALL)


def probe_step(identity: str) -> int:
    """The agent run step from a ``kind:<step>:<tool-call>`` evidence id; -1 when unknown."""
    match = EVIDENCE_ID.fullmatch(identity)
    return int(match[1]) if match else -1


class InvestigationResult(Contract):
    finding: Finding
    verdict: Verdict
    evidence: list[Evidence]
    source_digest: str
    model: str
    worker_identity: WorkerIdentity | None = None
    usage: dict[str, int | float | None] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)


class RunState(Contract):
    id: str
    status: Literal["pending", "running", "completed", "failed", "cancelled"]
    phase: str
    finding: Finding
    result: InvestigationResult | None = None
    error: str | None = None


class RunSummary(Contract):
    id: str
    title: str
    status: str
    started_at: str
    closed_at: str | None = None
    # Null when the run is not completed or its result could not be read in time.
    verdict: (
        Literal["potentially_exploitable", "likely_not_exploitable", "inconclusive"] | None
    ) = None
    cwe: str | None = None
    repo_url: str | None = None


class RunPage(Contract):
    items: list[RunSummary]
    next_page_token: str | None = None


class Health(Contract):
    """Temporal connectivity only; never sandbox, worker or model qualification."""

    status: Literal["control_plane_ready", "temporal_unavailable"]
    temporal: bool
    runtime: Literal["not_checked"] = "not_checked"
    generation: str
    task_queue: str


class RunEvent(Contract):
    at: str
    kind: Literal[
        "workflow_started",
        "activity_scheduled",
        "activity_completed",
        "activity_failed",
        "activity_timed_out",
        "timer",
        "workflow_completed",
        "workflow_failed",
        "workflow_cancelled",
        "other",
    ]
    name: str | None = Field(default=None, max_length=200)
    # Bounded labels such as an exit code or failure type; never a payload.
    detail: str = Field(default="", max_length=200)


class RunEvents(Contract):
    run_id: str
    events: list[RunEvent] = Field(max_length=500)
    truncated: bool = False


class ReportSummary(Contract):
    """Operator report files are untrusted and vary in shape: every parsed field is optional."""

    name: str
    kind: Literal["model", "diagnostic", "openshell", "replay", "unknown"]
    bytes: int
    modified_at: str
    status: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    commit: str | None = None
    model: str | None = None
    planned: int | None = None
    completed: int | None = None
    task_success_rate: float | None = None
    unsafe_negatives: int | None = None
    gates: dict[str, str] = Field(default_factory=dict)


class ReportList(Contract):
    items: list[ReportSummary] = Field(max_length=200)
    truncated: bool = False
