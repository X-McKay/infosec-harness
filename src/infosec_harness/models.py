"""The application's contracts; provider and workflow SDKs own their own protocols."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


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
    summary: str = Field(min_length=1, max_length=12_000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=10)
    citations: list[Citation] = Field(default_factory=list, max_length=30)


class Evidence(Contract):
    """Process fields are observed; text and observations remain untrusted claims."""

    id: str
    kind: Literal["command", "probe"]
    command: str
    exit_code: int | None
    stdout: str = ""
    stderr: str = ""
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
            and all(
                self.observations.get(key) is True
                for key in (
                    "target_reached",
                    "oracle_valid",
                    "positive_control",
                    "negative_control",
                )
            )
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


def definitive_support(
    verdict: Verdict, evidence: Iterable[Evidence]
) -> tuple[bool, list[Evidence]]:
    """Return ``(corroborated, contrary)`` for a definitive verdict.

    Pure admission rule: source citations plus a cited complete source-verified probe whose
    ``vulnerability_observed`` matches the label; any contrary qualified probe blocks it.
    Callers own evidence provenance and must build ``evidence`` independently.
    """
    expected = verdict.label == "potentially_exploitable"
    qualified = [item for item in evidence if item.complete_verified_probe]
    corroborated = bool(verdict.citations) and any(
        item.id in verdict.evidence_ids
        and item.observations["vulnerability_observed"] is expected
        for item in qualified
    )
    contrary = [
        item for item in qualified if item.observations["vulnerability_observed"] is not expected
    ]
    return corroborated, contrary


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


class RunPage(Contract):
    items: list[RunSummary]
    next_page_token: str | None = None
