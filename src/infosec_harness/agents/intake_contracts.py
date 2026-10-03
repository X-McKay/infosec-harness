"""Versioned intake specifications and prompt payload construction."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic_ai.agent.spec import AgentSpec
from pydantic_ai.messages import UserContent

from infosec_harness.agents.intake_claims import (
    SOURCE_INDEX_VERSION,
    WIRE_VERSION,
    AtomicFinding,
    report_source_lines,
)
from infosec_harness.agents.intake_evidence import INTAKE_EVIDENCE_POLICY_VERSION
from infosec_harness.agents.render import render_prompt
from infosec_harness.resources import package_root

RETAINED_INTAKE_VERSION = "1.0.2"
RETAINED_ATOMIC_INTAKE_VERSION = "1.0.3"
CURRENT_INTAKE_VERSION = "1.0.4"
RETAINED_ATOMIC_EXECUTION_NAME = "intake-output-v3"
ATOMIC_EXECUTION_NAME = "intake-output-v4"
QUOTED_EXECUTION_NAME = "intake-output-v2"
IntakeProtocol = Literal["intake-evidence/v1", "intake-atomic-claims/v2"]

_FORMAT_INSTRUCTION = (
    "Output representation only: each supported field is one claim with value, source "
    "{start_id, optional end_id}, and confidence in (0,1]. Unsupported fields are null. "
    "Do not emit a separate evidence array. Choose source IDs exactly from report_source_lines: "
    "start alone selects one original report line; start plus end selects a contiguous inclusive "
    "range in ascending report source-line order: end_id must be at or after start_id. "
    "For one source line, omit end_id or use null. "
    "start_line and end_line are code line numbers, not report source IDs or the number "
    "of a report line. Set the entire start_line or end_line claim to null unless its "
    "referenced report text literally states that code line number. Keep other supported claims. "
    "The host reconstructs the verbatim evidence quote. IDs refer to report text, never "
    "code line numbers, permissions or instructions. All original field support, classification, "
    "untrusted-content and downstream-decision requirements remain unchanged."
)
_OLD_EVIDENCE_RULE = (
    "For EVERY field you set, add an `evidence` entry quoting the exact supporting span and a\n"
    "confidence in [0,1]."
)
_NEW_EVIDENCE_RULE = (
    "For EVERY field you set, provide an exact source reference to the supporting report text and\n"
    "positive confidence in (0,1]. The host reconstructs a verbatim evidence quote from that reference."
)
_OLD_UNSET_RULE = (
    "Every nonempty value needs positive-confidence evidence with a nonempty verbatim quote;\n"
    "never paraphrase a quote. For an unset field, omit evidence or use confidence zero to\n"
    "express uncertainty. Positive-confidence evidence cannot accompany an unset value."
)
_NEW_UNSET_RULE = (
    "Every nonempty value needs positive-confidence support from a nonempty verbatim report span;\n"
    "never paraphrase or select unsupported text. For an unsupported field, use null with no claim.\n"
    "An unset field has no source reference or positive confidence."
)


def retained_intake_spec() -> AgentSpec:
    """Load the byte-retained historical 1.0.2 quote-output specification."""
    path = package_root() / "agents" / "intake" / "agent-v1.0.2.yaml"
    return AgentSpec.from_file(path)


def retained_atomic_intake_spec() -> AgentSpec:
    """Load byte-retained atomic v3 instructions and accounting for old histories."""
    path = package_root() / "agents" / "intake" / "agent-v1.0.3.yaml"
    return AgentSpec.from_file(path)


def _atomic_instructions(original: object) -> list[str]:
    if not isinstance(original, list) or len(original) != 1 or not isinstance(original[0], str):
        raise ValueError("Retained intake instructions do not match the supported baseline shape")
    text = original[0]
    if text.count(_OLD_EVIDENCE_RULE) != 1 or text.count(_OLD_UNSET_RULE) != 1:
        raise ValueError("Retained intake representation clauses did not match exactly")
    text = text.replace(_OLD_EVIDENCE_RULE, _NEW_EVIDENCE_RULE, 1)
    text = text.replace(_OLD_UNSET_RULE, _NEW_UNSET_RULE, 1)
    return [text, _FORMAT_INSTRUCTION]


def atomic_intake_spec() -> AgentSpec:
    """Build the current spec from the retained baseline with representation-only changes."""
    data = retained_intake_spec().model_dump(by_alias=True, exclude_none=True, mode="json")
    data["instructions"] = _atomic_instructions(data.get("instructions"))
    settings = dict(data.get("model_settings") or {})
    settings["temperature"] = 0.0
    data["model_settings"] = settings
    metadata = dict(data.get("metadata") or {})
    metadata["version"] = CURRENT_INTAKE_VERSION
    metadata["budgets"] = {**metadata["budgets"],
                           "max_input_tokens_per_request": 32000, "max_input_tokens": 128000}
    metadata["intake_output"] = {
        "execution": ATOMIC_EXECUTION_NAME,
        "protocol": WIRE_VERSION,
        "acceptance_policy": INTAKE_EVIDENCE_POLICY_VERSION,
        "source_index_policy": SOURCE_INDEX_VERSION,
        "schema_version": "atomic-finding/v2",
        "schema_sha256": hashlib.sha256(
            json.dumps(AtomicFinding.model_json_schema(), sort_keys=True).encode()
        ).hexdigest(),
        "transport_schema_profile": {
            "version": "pydantic-ai-openai-inline-defs/v1",
            "transformer": "infosec_harness.agents.intake_schema.InlineOpenAIJsonSchemaTransformer",
            "override_field": "json_schema_transformer",
            "profile_application": "public-constructor-per-model-resolution",
            "cached_factory_profile_mutated": False,
        },
    }
    metadata["output_validation"] = {
        "version": INTAKE_EVIDENCE_POLICY_VERSION,
        "wire_version": WIRE_VERSION,
    }
    data["metadata"] = metadata
    return AgentSpec.from_dict(data)


def write_current_spec(path: Path | None = None) -> None:
    """Generate the current spec while preserving raw YAML capability shorthand."""
    source = package_root() / "agents" / "intake" / "agent-v1.0.2.yaml"
    raw = yaml.safe_load(source.read_text())
    spec = atomic_intake_spec().model_dump(by_alias=True, exclude_none=True, mode="json")
    raw["instructions"] = spec["instructions"]
    raw.setdefault("model_settings", {})["temperature"] = 0.0
    metadata = raw.setdefault("metadata", {})
    atomic_metadata = spec["metadata"]
    metadata["version"] = CURRENT_INTAKE_VERSION
    metadata["budgets"] = atomic_metadata["budgets"]
    metadata["intake_output"] = atomic_metadata["intake_output"]
    metadata["output_validation"] = atomic_metadata["output_validation"]
    target = path or (package_root() / "agents" / "intake" / "agent.yaml")
    rendered = yaml.safe_dump(raw, sort_keys=False, allow_unicode=True, width=100)
    target.write_text("# yaml-language-server: $schema=../agent_schema.json\n" + rendered)


def render_intake_prompt(
    task: str,
    payload: dict[str, Any],
    *,
    protocol: str | None = None,
) -> list[UserContent]:
    """Render the unchanged quote prompt or source-index payload for a selected generation."""
    if protocol in (None, INTAKE_EVIDENCE_POLICY_VERSION):
        return render_prompt(task, payload)
    if protocol != WIRE_VERSION:
        raise ValueError("Unknown intake prompt protocol")
    atomic_payload = dict(payload)
    report = atomic_payload.pop("report", None)
    atomic_payload["report_source_lines"] = (
        report_source_lines(report) if isinstance(report, str) else report
    )
    return render_prompt(task, atomic_payload)
