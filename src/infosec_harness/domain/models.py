"""Typed contracts shared by agents, activities, persistence, and the API.

Agent output types are the models the graph routes on; their field descriptions are
part of the output schema the model sees, so keep them precise.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Any, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, model_validator


def _nested_model_fields(cls: type[BaseModel]) -> set[str]:
    """Names of fields whose annotation is a nested model (optionally ``| None``)."""
    names: set[str] = set()
    for name, info in cls.model_fields.items():
        candidates = get_args(info.annotation) or (info.annotation,)
        if any(isinstance(c, type) and issubclass(c, BaseModel) for c in candidates):
            names.add(name)
    return names


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="before")
    @classmethod
    def _decode_double_encoded_objects(cls, data: Any) -> Any:
        """Accept a nested object that arrived as a JSON *string*.

        Models routinely double-encode a single nested object in a tool call — emitting
        ``"sink": "{\"file_path\": ...}"`` while getting the sibling ``list[CodeRef]``
        right — which fails validation and burns the agent's output retries. Only a string
        in a slot that wants an object is touched, and only when it parses to one, so this
        widens acceptance of input that would otherwise always fail and changes nothing
        else.
        """
        if not isinstance(data, dict):
            return data
        decoded = None
        for name in _nested_model_fields(cls):
            value = data.get(name)
            if not isinstance(value, str):
                continue
            try:
                parsed = json.loads(value)
            except (ValueError, TypeError):
                continue
            if isinstance(parsed, dict):
                decoded = decoded if decoded is not None else dict(data)
                decoded[name] = parsed
        return decoded if decoded is not None else data


def canonical_json(model: BaseModel | dict | list) -> str:
    """Byte-stable JSON (sorted keys, no whitespace variance) for hashing and prompts."""
    data = model.model_dump(mode="json") if isinstance(model, BaseModel) else model
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Findings (intake)
# ---------------------------------------------------------------------------


class FindingSourceKind(StrEnum):
    generic_json = "generic_json"
    ado = "ado"
    free_text = "free_text"


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"
    unknown = "unknown"


class FindingInput(_Model):
    """The published generic JSON schema an external process submits (D1).

    Only ``repo_url`` and ``title`` are required; anything missing is extracted from
    ``description`` by the intake agent or the finding is parked as ``needs_info``.
    """

    external_id: str | None = Field(None, description="ID in the originating system")
    title: str
    description: str = ""
    repo_url: str = Field(description="Git URL or a local path visible to the worker")
    revision: str = Field("HEAD", description="Commit SHA, tag, or branch")
    file_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    symbol: str | None = None
    cwe: str | None = Field(None, description="e.g. CWE-89")
    severity: Severity = Severity.unknown
    source_tool: str | None = None
    source_kind: FindingSourceKind = FindingSourceKind.generic_json
    ado_work_item_id: int | None = None


class CodeLocation(_Model):
    file_path: str
    start_line: int | None = None
    end_line: int | None = None
    symbol: str | None = None


class FieldEvidence(_Model):
    field: str
    quote: str = Field(description="Verbatim span of the source text supporting the field")
    confidence: float = Field(ge=0, le=1)


class ExtractedFinding(_Model):
    """IntakeAgent output: fields recovered from prose, each with a citation."""

    file_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    symbol: str | None = None
    cwe: str | None = Field(None, description="Most specific CWE id, formatted CWE-<n>")
    vulnerability_class: str | None = Field(None, description="Short name, e.g. 'SQL injection'")
    attack_preconditions: list[str] = Field(default_factory=list)
    claimed_impact: str | None = None
    evidence: list[FieldEvidence] = Field(
        default_factory=list, description="One entry per extracted field, quoting the source text"
    )


class Finding(_Model):
    """Canonical finding every downstream step consumes."""

    fingerprint: str
    external_id: str | None = None
    title: str
    description: str = ""
    repo_url: str
    revision: str
    location: CodeLocation | None = None
    cwe: str | None = None
    vulnerability_class: str | None = None
    severity: Severity = Severity.unknown
    attack_preconditions: list[str] = Field(default_factory=list)
    claimed_impact: str | None = None
    source_kind: FindingSourceKind
    source_tool: str | None = None
    ado_work_item_id: int | None = None

    @staticmethod
    def compute_fingerprint(inp: FindingInput) -> str:
        key = canonical_json(
            {
                "repo": inp.repo_url,
                "rev": inp.revision,
                "file": inp.file_path,
                "line": inp.start_line,
                "cwe": inp.cwe,
                "title": inp.title,
                "ext": inp.external_id,
            }
        )
        return sha256_text(key)[:24]


# ---------------------------------------------------------------------------
# Repository preparation
# ---------------------------------------------------------------------------


class RepoRef(_Model):
    repo_url: str
    revision: str = "HEAD"


class RepoSnapshot(_Model):
    repo_url: str
    revision: str
    resolved_commit: str | None = None
    path: str = Field(description="Absolute path of the snapshot on the worker's shared volume")
    content_hash: str


class StackFingerprint(_Model):
    languages: dict[str, int] = Field(default_factory=dict, description="language -> file count")
    manifests: list[str] = Field(default_factory=list)
    build_systems: list[str] = Field(default_factory=list)
    test_frameworks: list[str] = Field(default_factory=list)
    registries: list[str] = Field(
        default_factory=list, description="Package registry hosts declared by the repo (D14)"
    )
    test_dirs: list[str] = Field(default_factory=list)


class RepoProfile(_Model):
    """ReconAgent output."""

    summary: str = Field(description="Two or three sentences on what the application does")
    primary_language: str
    frameworks: list[str] = Field(default_factory=list)
    components: list[str] = Field(default_factory=list, description="Top-level modules/services")
    entry_points: list[str] = Field(
        default_factory=list, description="Files/functions where untrusted input enters"
    )
    test_framework: str = Field(description="e.g. pytest, junit5, jest, Test::More")
    test_layout: str = Field(description="Where tests live and how they are named")


class EnvironmentSpec(_Model):
    """EnvPlanner/BuildRepair/PartialBuild output; rendered into a Dockerfile."""

    base_image: str = Field(description="Public or registry-qualified image, e.g. python:3.12-slim")
    system_packages: list[str] = Field(default_factory=list, description="apt/apk packages")
    install_commands: list[str] = Field(
        default_factory=list,
        description="Shell commands run from the repo root to install dependencies and build",
    )
    test_command: str = Field(
        description="Command to run ONE test file; use {test_file} as the placeholder, "
        "e.g. 'python -m pytest -q {test_file}'"
    )
    env: dict[str, str] = Field(default_factory=dict)
    scope: Literal["full", "partial"] = "full"
    module_path: str | None = Field(None, description="Sub-directory built when scope is partial")
    rationale: str = ""


class BuildResult(_Model):
    ok: bool
    image_tag: str | None = None
    spec: EnvironmentSpec
    log_artifact: str | None = None
    error_excerpt: str = ""
    duration_s: float = 0.0


class SmokeResult(_Model):
    ok: bool
    output_excerpt: str = ""


class PreparedEnvironment(_Model):
    snapshot: RepoSnapshot
    stack: StackFingerprint
    profile: RepoProfile | None = None
    build: BuildResult | None = None
    smoke: SmokeResult | None = None
    status: Literal["ready", "unbuildable", "failed"]
    attempts: int = 0
    reason: str = ""


# ---------------------------------------------------------------------------
# Finding triage
# ---------------------------------------------------------------------------


class CodeRef(_Model):
    file_path: str
    start_line: int
    end_line: int
    note: str = ""


class Reachability(StrEnum):
    reachable = "reachable"
    unreachable = "unreachable"
    unknown = "unknown"


class FindingContext(_Model):
    """ContextAgent output: the code slice relevant to the finding."""

    summary: str
    source: CodeRef | None = Field(None, description="Where untrusted input enters")
    sink: CodeRef | None = Field(None, description="The dangerous operation")
    path: list[CodeRef] = Field(default_factory=list, description="Ordered source -> sink steps")
    sanitizers: list[CodeRef] = Field(default_factory=list)
    reachability: Reachability
    reachability_rationale: str
    target_callable: str | None = Field(
        None, description="Function/method a unit test should call to reach the sink"
    )


class OracleKind(StrEnum):
    marker_output = "marker_output"
    canary_file = "canary_file"


class ProbePlan(_Model):
    """ProbePlannerAgent output: what the probe must demonstrate and how we detect it."""

    hypothesis: str = Field(description="One sentence: the exploit condition the test attempts")
    payload: str = Field(description="The malicious input(s) the test will use")
    oracle: OracleKind
    oracle_condition: str = Field(
        description="The observable condition that proves exploitation, which the test "
        "converts into printing the oracle marker (or creating the canary file)"
    )
    precondition_checkpoint: str = Field(
        description="The point the test reaches before triggering the sink; the test prints "
        "the precondition marker there"
    )
    test_file_path: str = Field(description="Repo-relative path for the new test file")
    notes: str = ""


class ProbeSource(_Model):
    """ProbeAuthor/ProbeRepair output."""

    test_file_path: str
    content: str = Field(description="Complete test file contents")
    explanation: str = ""


class ProbeExecution(_Model):
    attempt: int
    exit_code: int | None
    timed_out: bool = False
    oracle_fired: bool
    precondition_reached: bool
    # The sink call returned. `precondition_reached` is printed before the call, so without
    # this a probe that threw mid-call looks exactly like one the code resisted.
    sink_returned: bool = False
    # Set when the test runner's own output says it executed zero tests (see
    # sandbox.docker.no_tests_executed). A zero-test run is a probe defect, never a negative
    # result: nothing exercised the sink. Naming it deterministically keeps the diagnosis agent
    # from having to infer "did not run" from a bare exit code, which it gets wrong.
    runner_reported_no_tests: str | None = None
    stdout_tail: str = ""
    stderr_tail: str = ""
    duration_s: float = 0.0
    log_artifact: str | None = None
    source_artifact: str | None = None


class DiagnosisKind(StrEnum):
    probe_defect = "probe_defect"
    valid_positive = "valid_positive"
    valid_negative = "valid_negative"
    environment_issue = "environment_issue"


class ProbeDiagnosis(_Model):
    kind: DiagnosisKind
    explanation: str
    fix_hint: str = Field("", description="For probe_defect: what the repair should change")


class VerdictLabel(StrEnum):
    potentially_exploitable = "potentially_exploitable"
    likely_not_exploitable = "likely_not_exploitable"
    inconclusive = "inconclusive"


class InconclusiveReason(StrEnum):
    environment_unbuildable = "environment_unbuildable"
    probe_unrepairable = "probe_unrepairable"
    budget_exhausted = "budget_exhausted"
    conflicting_evidence = "conflicting_evidence"
    needs_info = "needs_info"
    error = "error"


class Verdict(_Model):
    label: VerdictLabel
    confidence: float = Field(ge=0, le=1)
    rationale: str
    inconclusive_reason: InconclusiveReason | None = None
    evidence: list[CodeRef] = Field(default_factory=list)


class VerdictFacts(_Model):
    """Deterministic facts the verdict validator checks the agent's verdict against (§5.3)."""

    environment_ready: bool
    oracle_fired: bool = False
    precondition_reached: bool = False
    last_diagnosis: DiagnosisKind | None = None
    reachability: Reachability = Reachability.unknown
    probe_repairs_exhausted: bool = False


class PriorityBand(StrEnum):
    p1 = "P1"
    p2 = "P2"
    p3 = "P3"
    p4 = "P4"


class TriageResult(_Model):
    fingerprint: str
    verdict: Verdict
    priority_score: float
    priority: PriorityBand
    environment_scope: Literal["full", "partial", "none"] = "none"
    early_exit: str | None = None


class AgentOutcome(_Model):
    """One agent call plus the accounting the harness records (§9, §10)."""

    output: Any
    agent: str
    model_name: str = ""
    config_hash: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    cost_usd: float | None = None
    cost_estimated: bool = True
    latency_s: float = 0.0
    retries: int = 0
    tools_called: list[str] = Field(default_factory=list)
    skills_loaded: list[str] = Field(default_factory=list)
    # Model requests this run actually made. Without it, a run that exhausted its request
    # budget is indistinguishable in the record from one that finished comfortably, so a
    # `request_limit` breach cannot be told from a loop without re-running live.
    requests: int = 0
    # Tool calls repeated with identical arguments, `tool(args)` -> count, only where count > 1.
    # Empty on a healthy run; non-empty is the signature of a loop rather than of hard work.
    repeated_tool_calls: dict[str, int] = Field(default_factory=dict)


class TriageRunOutput(_Model):
    """Everything one FindingTriageWorkflow produces, for persistence and reporting."""

    finding: Finding
    result: TriageResult
    prepared_status: str
    invocations: list[AgentOutcome] = Field(default_factory=list)
    needs_info: bool = False
