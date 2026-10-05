"""Typed arguments of every workflow and every deterministic activity the workflows schedule.

The PydanticAI data converter serializes these models at the Temporal boundary and validates
them on the other side, so a payload is checked once, by its type, rather than unpacked from a
``dict`` with string keys at each end. Every field is required unless absence has a meaning.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from infosec_harness.domain.models import (
    BatchStatus,
    EnvironmentSpec,
    Finding,
    FindingInput,
    PreparedEnvironment,
    ProbeSource,
    RepoSnapshot,
    StackFingerprint,
    TriageRunOutput,
)


class _Payload(BaseModel):
    model_config = ConfigDict(extra="forbid")


class BatchArgs(_Payload):
    """``TriageBatchWorkflow`` input, persisted at acceptance and retried by reconciliation."""

    batch_id: str = Field(min_length=1)
    findings: list[FindingInput]
    per_repo_concurrency: int = Field(ge=1)


class ComponentPreparationArgs(_Payload):
    batch_id: str = Field(min_length=1)
    # The finding the shared preparation is accounted to: the first of its component.
    fingerprint: str = Field(min_length=1)
    snapshot: RepoSnapshot
    stack: StackFingerprint
    component_root: str


class FindingTriageArgs(_Payload):
    batch_id: str = Field(min_length=1)
    finding_input: FindingInput
    prepared: PreparedEnvironment


class ResolveLocationArgs(_Payload):
    finding: Finding
    repo_path: str


class BuildArgs(_Payload):
    snapshot: RepoSnapshot
    spec: EnvironmentSpec


class SmokeArgs(_Payload):
    image_tag: str
    test_command: str
    language: str
    module_path: str


class ProbeArgs(_Payload):
    image_tag: str
    probe: ProbeSource
    spec: EnvironmentSpec
    nonce: str
    attempt: int


class RecordRecipeArgs(_Payload):
    stack: StackFingerprint
    spec: EnvironmentSpec
    worked: bool


class ProgressArgs(_Payload):
    batch_id: str
    fingerprint: str
    phase: str
    event_key: str
    detail: str = ""


class SaveOutputArgs(_Payload):
    batch_id: str
    output: TriageRunOutput


class WritebackArgs(_Payload):
    run_id: str
    output: TriageRunOutput


class FinishBatchArgs(_Payload):
    batch_id: str
    status: BatchStatus
    detail: str


class ReserveArgs(_Payload):
    root_id: str
    operation_id: str
    requested: dict[str, float]
    agent: str
    operation_kind: Literal["agent", "execution"]
    fingerprint: str
    configuration_digest: str | None = None
    run_id: str | None = None
    invocation_id: str | None = None


class SettleArgs(_Payload):
    root_id: str
    operation_id: str
    observed: dict[str, float] | None
    record: dict[str, Any]


class CloseBrokerRunArgs(_Payload):
    """Close one workflow run's broker leases; issuance takes ``InvocationRequest`` itself."""

    run_id: str = Field(min_length=1)
    root_id: str = Field(min_length=1)
