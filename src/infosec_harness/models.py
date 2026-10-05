"""The application's contracts; provider and workflow SDKs own their own protocols."""

from __future__ import annotations

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


class InvestigationResult(Contract):
    finding: Finding
    verdict: Verdict
    evidence: list[Evidence]
    source_digest: str
    model: str
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
