"""Deterministic stand-in models for ``HARNESS_MODEL_MODE=stub`` (tests, CI, offline demos).

They exercise every graph edge, activity, and persistence path without credentials.
Their *judgments* are deliberately uninformative (the verdict stub always answers
``inconclusive``), so stub runs measure plumbing, never accuracy. The env-planner stub is
a small heuristic baseline so builds and probe execution run for real.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from pydantic_ai.messages import ModelMessage, ModelResponse, ToolCallPart, UserPromptPart
from pydantic_ai.models import Model
from pydantic_ai.models.function import AgentInfo, FunctionModel


def _prompt_text(messages: list[ModelMessage]) -> str:
    parts: list[str] = []
    for m in messages:
        for p in getattr(m, "parts", []):
            if isinstance(p, UserPromptPart):
                content = p.content if isinstance(p.content, list) else [p.content]
                parts.extend(c for c in content if isinstance(c, str))
    return "\n".join(parts)


def _tag(text: str, name: str) -> Any:
    m = re.search(rf"<{name}>\n(.*?)\n</{name}>", text, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except json.JSONDecodeError:
        return m.group(1)


def _primary_language(stack: dict | None) -> str:
    langs = (stack or {}).get("languages") or {}
    return max(langs, key=langs.get) if langs else "unknown"


def _env_plan(stack: dict | None) -> dict:
    stack = stack or {}
    manifests = set(stack.get("manifests") or [])
    lang = _primary_language(stack)
    if lang == "python":
        install = ["python -m pip install --no-cache-dir --user pytest"]
        if "requirements.txt" in manifests:
            install.insert(0, "python -m pip install --no-cache-dir --user -r requirements.txt")
        if "pyproject.toml" in manifests or "setup.py" in manifests:
            install.insert(0, "python -m pip install --no-cache-dir --user -e .")
        return {"base_image": "python:3.12-slim", "install_commands": install,
                "test_command": "python -m pytest -q -s {test_file}",
                "env": {"PYTHONDONTWRITEBYTECODE": "1", "PATH": "/work/home/.local/bin:/usr/local/bin:/usr/bin:/bin"},
                "rationale": "stub heuristic: python"}
    if lang in {"javascript", "typescript"}:
        return {"base_image": "node:22-slim",
                "install_commands": ["npm install --no-audit --no-fund"],
                "test_command": "npx jest --runTestsByPath {test_file}", "rationale": "stub heuristic: node"}
    if lang == "java":
        return {"base_image": "maven:3.9-eclipse-temurin-21",
                "install_commands": ["mvn -q -B -DskipTests test-compile"],
                "test_command": "mvn -q -B test -Dtest=HarnessProbeTest", "rationale": "stub heuristic: maven"}
    if lang == "perl":
        return {"base_image": "perl:5.40", "install_commands": ["cpanm --notest --installdeps . || true"],
                "test_command": "prove -v {test_file}", "rationale": "stub heuristic: perl"}
    return {"base_image": "debian:bookworm-slim", "install_commands": [],
            "test_command": "sh {test_file}", "rationale": "stub heuristic: unknown stack"}


# The stub carries all three markers with the oracle branch present but never taken: a probe
# that reaches the sink, returns, and observes nothing. It must satisfy the same contract as a real probe — an offline stand-in the
# validator rejects would make every offline test a lie.
_PROBE_TEMPLATES = {
    "python": ("tests/test_harness_probe.py",
               "def test_harness_probe():\n"
               "    print('HARNESS_PRECONDITION::{nonce}')\n"
               "    print('HARNESS_SINK_RETURNED::{nonce}')\n"
               "    observed = False  # the stub never observes the exploit condition\n"
               "    if observed:\n"
               "        print('HARNESS_ORACLE::{nonce}')\n"),
    "javascript": ("__tests__/harness_probe.test.js",
                   "test('harness probe', () => {\n"
                   "  console.log('HARNESS_PRECONDITION::{nonce}');\n"
                   "  console.log('HARNESS_SINK_RETURNED::{nonce}');\n"
                   "  const observed = false;  // the stub never observes the condition\n"
                   "  if (observed) { console.log('HARNESS_ORACLE::{nonce}'); }\n"
                   "});\n"),
    "perl": ("t/harness_probe.t",
             "use Test::More tests => 1;\n"
             "print \"HARNESS_PRECONDITION::{nonce}\\n\";\n"
             "print \"HARNESS_SINK_RETURNED::{nonce}\\n\";\n"
             "my $observed = 0;  # the stub never observes the condition\n"
             "print \"HARNESS_ORACLE::{nonce}\\n\" if $observed;\n"
             "ok(1);\n"),
}


def _probe(text: str) -> dict:
    lang = _primary_language(_tag(text, "stack_fingerprint"))
    nonce = _tag(text, "oracle_nonce") or "none"
    plan = _tag(text, "probe_plan") or {}
    fallback = ("harness_probe.sh",
                "echo HARNESS_PRECONDITION::{nonce}\n"
                "echo HARNESS_SINK_RETURNED::{nonce}\n"
                "if false; then echo HARNESS_ORACLE::{nonce}; fi\n")
    path, body = _PROBE_TEMPLATES.get(lang, fallback)
    path = plan.get("test_file_path") or path
    return {"test_file_path": path, "content": body.replace("{nonce}", str(nonce)),
            "explanation": "stub probe: reaches the sink and returns; observes nothing"}


def _diagnosis(text: str) -> dict:
    execution = _tag(text, "probe_execution") or {}
    if execution.get("oracle_fired"):
        kind = "valid_positive"
    elif execution.get("exit_code") is None:
        # No exit status at all: the probe never ran, so nothing here is about the code
        # under test. This is the shape execute_probe_activity returns when the isolation
        # runtime is unavailable.
        kind = "environment_issue"
    elif execution.get("exit_code") == 0:
        kind = "valid_negative"
    else:
        kind = "probe_defect"
    return {"kind": kind, "explanation": "stub diagnosis from exit code and oracle signals"}


_STUBS: dict[str, Callable[[str], dict]] = {
    "intake": lambda t: {"evidence": []},
    "recon": lambda t: {
        "summary": "stub profile", "primary_language": _primary_language(_tag(t, "stack_fingerprint")),
        "frameworks": [], "components": [], "entry_points": [],
        "test_framework": ((_tag(t, "stack_fingerprint") or {}).get("test_frameworks") or ["unknown"])[0],
        "test_layout": "unknown"},
    "env-planner": lambda t: _env_plan(_tag(t, "stack_fingerprint")),
    "build-repair": lambda t: (_tag(t, "failed_spec") or _env_plan(_tag(t, "stack_fingerprint"))),
    "partial-build": lambda t: {**(_tag(t, "failed_spec") or _env_plan(_tag(t, "stack_fingerprint"))),
                                "scope": "partial", "module_path": None},
    "context": lambda t: {"summary": "stub context", "reachability": "unknown",
                          "reachability_rationale": "stub model does not analyse code"},
    "probe-planner": lambda t: {
        "hypothesis": "stub hypothesis", "payload": "' OR '1'='1", "oracle": "marker_output",
        "oracle_condition": "stub", "precondition_checkpoint": "test start",
        "test_file_path": _probe(t)["test_file_path"]},
    "probe-author": _probe,
    "probe-repair": lambda t: _tag(t, "probe_source") or _probe(t),
    "probe-diagnosis": _diagnosis,
    "verdict": lambda t: {"label": "inconclusive", "confidence": 0.0,
                          "rationale": "stub model: no exploitability judgment",
                          "inconclusive_reason": "conflicting_evidence"},
}


def stub_model(agent_name: str, tier: str) -> Model:
    produce = _STUBS.get(agent_name)

    def respond(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        if produce is None or not info.output_tools:
            raise RuntimeError(f"No stub for agent {agent_name!r}")
        args = produce(_prompt_text(messages))
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, args)])

    return FunctionModel(respond, model_name=f"stub-{agent_name}-{tier}")
