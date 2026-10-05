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

# The commands, paths, warm-ups and image table the validators enforce: a stub plan the
# validators would reject would make every offline test a lie.
from infosec_harness.agents.ecosystem_contract import (
    CPANM_INSTALL_COMMAND,
    JS_TEST_COMMANDS,
    MAVEN_INSTALL_COMMAND,
    MAVEN_TEST_COMMAND,
    MAVEN_WARMUP_COMMANDS,
    PERL5LIB_PATH,
    PROVE_TEST_COMMAND,
    PYTEST_TEST_COMMAND,
    RUNTIME_HOME,
    maven_image_for_release,
)
from infosec_harness.domain.models import StackFingerprint


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


def _stack(stack: dict | None) -> StackFingerprint:
    return StackFingerprint.model_validate(stack or {})


def _primary_language(stack: StackFingerprint) -> str:
    return stack.top_language or "unknown"


# ts-jest type-checks the probe, so a TS project also needs the type declarations for the test
# globals: without @types/jest the run fails with "TS2582: Cannot find name 'test'".
_TS_JEST_PACKAGES = ("ts-jest", "typescript", "@types/jest", "@types/node")


def _node_plan(stack: StackFingerprint, typescript: bool) -> dict:
    frameworks = [f for f in stack.test_frameworks if f in JS_TEST_COMMANDS]
    runner = frameworks[0] if frameworks else "jest"
    install = ["npm ci --no-audit --no-fund" if "package-lock.json" in stack.manifests
               else "npm install --no-audit --no-fund"]
    command = JS_TEST_COMMANDS[runner]
    note = f"stub heuristic: node, runner {runner}"
    if typescript:
        # A bare `npx jest` cannot parse TypeScript; vitest and tsx compile it unconfigured, and
        # jest needs ts-jest on the command line because the spec may not edit jest.config.
        if runner == "jest":
            install.append("npm install --no-audit --no-fund --no-save " + " ".join(_TS_JEST_PACKAGES))
            command = command.replace("npx jest", "npx jest --preset ts-jest")
            note += " + ts-jest (TypeScript sources)"
        elif runner == "node:test":
            install.append("npm install --no-audit --no-fund --no-save tsx")
            command = "npx tsx --test {test_file}"
            note += " via tsx (TypeScript sources)"
    return {"base_image": "node:22-slim", "install_commands": install,
            "test_command": command, "rationale": note}


def _jvm_framework(stack: StackFingerprint) -> str:
    """The JVM test framework the fingerprint reports; JUnit 4 when none is declared, as for 50
    of the 51 harvested Vul4J Maven entries."""
    for name in ("junit5", "junit4", "testng"):
        if name in stack.test_frameworks:
            return name
    return "junit4"


def _maven_image(stack: StackFingerprint) -> str:
    """A base image whose javac still accepts the level the project declares."""
    if stack.java_release is None:
        return "maven:3.9-eclipse-temurin-17"
    return maven_image_for_release(stack.java_release)


def _env_plan(raw_stack: dict | None) -> dict:
    stack = _stack(raw_stack)
    manifests = set(stack.manifests)
    lang = _primary_language(stack)
    if lang == "python":
        install = ["python -m pip install --no-cache-dir --user pytest"]
        if "requirements.txt" in manifests:
            install.insert(0, "python -m pip install --no-cache-dir --user -r requirements.txt")
        if "pyproject.toml" in manifests or "setup.py" in manifests:
            install.insert(0, "python -m pip install --no-cache-dir --user -e .")
        return {"base_image": "python:3.12-slim", "install_commands": install,
                "test_command": PYTEST_TEST_COMMAND,
                # `pip --user` installs under HOME at build time; the probe runs from its copy.
                "env": {"PYTHONDONTWRITEBYTECODE": "1",
                        "PATH": f"{RUNTIME_HOME}/.local/bin:/usr/local/bin:/usr/bin:/bin"},
                "rationale": "stub heuristic: python"}
    if lang in {"javascript", "typescript"}:
        return _node_plan(stack, typescript=lang == "typescript")
    if lang == "java":
        # The recipe the validators enforce: test-compile plus a pinned Surefire goal, and a
        # warm-up that runs a throwaway test in the project's own framework so the offline probe
        # finds its provider. Framework and base image are read from the fingerprint.
        framework = _jvm_framework(stack)
        return {"base_image": _maven_image(stack),
                "install_commands": [MAVEN_INSTALL_COMMAND, MAVEN_WARMUP_COMMANDS[framework]],
                "test_command": MAVEN_TEST_COMMAND,
                "rationale": f"stub heuristic: maven, {framework}"}
    if lang == "perl":
        # The skills/build-cpanm recipe: a local lib the sandbox user can write, PERL5LIB on the
        # executable /opt copy, and `prove` (perl core, so nothing installs it).
        return {"base_image": "perl:5.38-slim",
                "system_packages": ["gcc", "make", "libc6-dev"],
                "install_commands": [CPANM_INSTALL_COMMAND],
                "env": {"PERL5LIB": PERL5LIB_PATH},
                "test_command": PROVE_TEST_COMMAND, "rationale": "stub heuristic: perl"}
    return {"base_image": "debian:bookworm-slim", "install_commands": [],
            "test_command": "sh {test_file}", "rationale": "stub heuristic: unknown stack"}


# A bare `test(...)` is a global under jest only (vitest defaults to `globals: false`; mocha's
# BDD interface names it `it`), so the probe body follows the runner the env plan chose.
_JS_PROBE_BODY = (
    "{head}test('harness probe', () => {{\n"
    "  console.log('HARNESS_PRECONDITION::{{nonce}}');\n"
    "  console.log('HARNESS_SINK_RETURNED::{{nonce}}');\n"
    "  const observed = false;  // the stub never observes the condition\n"
    "  if (observed) {{ console.log('HARNESS_ORACLE::{{nonce}}'); }}\n"
    "}});\n")
_JS_PROBE_TEMPLATES = {
    "jest": _JS_PROBE_BODY.format(head=""),
    "vitest": _JS_PROBE_BODY.format(head="import { test } from 'vitest';\n"),
    "node:test": _JS_PROBE_BODY.format(head="const test = require('node:test');\n"),
    "mocha": _JS_PROBE_BODY.format(head="").replace("test('harness probe'", "it('harness probe'"),
}


# All three markers with the oracle branch present but never taken: a probe that reaches the
# sink, returns, and observes nothing, under the same contract as a real probe.
_PROBE_TEMPLATES = {
    "python": ("tests/test_harness_probe.py",
               "def test_harness_probe():\n"
               "    print('HARNESS_PRECONDITION::{nonce}')\n"
               "    print('HARNESS_SINK_RETURNED::{nonce}')\n"
               "    observed = False  # the stub never observes the exploit condition\n"
               "    if observed:\n"
               "        print('HARNESS_ORACLE::{nonce}')\n"),
    "javascript": ("__tests__/harness_probe.test.js", _JS_PROBE_BODY.format(head="")),
    "perl": ("t/harness_probe.t",
             "use Test::More tests => 1;\n"
             "print \"HARNESS_PRECONDITION::{nonce}\\n\";\n"
             "print \"HARNESS_SINK_RETURNED::{nonce}\\n\";\n"
             "my $observed = 0;  # the stub never observes the condition\n"
             "print \"HARNESS_ORACLE::{nonce}\\n\" if $observed;\n"
             "ok(1);\n"),
}


def _java_probe(annotation_import: str, annotation: str, modifier: str, method: str) -> str:
    """A stub Java probe in one framework's shape: public class and method (JUnit 4 and TestNG
    require both), named HarnessProbeTest to match the `-Dtest=` selector."""
    return (f"{annotation_import}\n\n"
            f"public class HarnessProbeTest {{\n"
            f"    {annotation}\n"
            f"    {modifier} void {method}() throws Exception {{\n"
            f"        System.out.println(\"HARNESS_PRECONDITION::{{nonce}}\");\n"
            f"        System.out.println(\"HARNESS_SINK_RETURNED::{{nonce}}\");\n"
            f"        boolean observed = false;  // the stub never observes the condition\n"
            f"        if (observed) {{\n"
            f"            System.out.println(\"HARNESS_ORACLE::{{nonce}}\");\n"
            f"        }}\n"
            f"    }}\n"
            f"}}\n")


# Which annotation compiles depends on the framework on the project's test classpath.
_JAVA_PROBES = {
    "junit4": _java_probe("import org.junit.Test;", "@Test", "public", "probe"),
    "junit5": _java_probe("import org.junit.jupiter.api.Test;", "@Test", "public", "probe"),
    "testng": _java_probe("import org.testng.annotations.Test;", "@Test", "public", "probe"),
}
_JAVA_PROBE_PATH = "src/test/java/HarnessProbeTest.java"


def _probe(text: str) -> dict:
    stack = _stack(_tag(text, "stack_fingerprint"))
    lang = _primary_language(stack)
    nonce = _tag(text, "oracle_nonce") or "none"
    plan = _tag(text, "probe_plan") or {}
    fallback = ("harness_probe.sh",
                "echo HARNESS_PRECONDITION::{nonce}\n"
                "echo HARNESS_SINK_RETURNED::{nonce}\n"
                "if false; then echo HARNESS_ORACLE::{nonce}; fi\n")
    # The probe body is per *runner*, not per language.
    if lang == "java":
        path, body = _JAVA_PROBE_PATH, _JAVA_PROBES[_jvm_framework(stack)]
    else:
        path, body = _PROBE_TEMPLATES.get(lang, fallback)
    if lang in {"javascript", "typescript"}:
        runner = next((f for f in stack.test_frameworks if f in _JS_PROBE_TEMPLATES), "jest")
        body = _JS_PROBE_TEMPLATES[runner]
        path = _PROBE_TEMPLATES["javascript"][0]
    path = plan.get("test_file_path") or path
    return {"test_file_path": path, "content": body.replace("{nonce}", str(nonce)),
            "explanation": "stub probe: reaches the sink and returns; observes nothing"}


# Stderr shapes that mean the environment lacked something the test needed, rather than the
# probe being wrong (each was observed as an exit-1 run with no test output).
_ENVIRONMENT_SIGNATURES = ("no suitable driver", "can't locate", "cannot find module",
                           "modulenotfounderror", "classnotfoundexception",
                           "npx canceled due to missing packages",
                           "cannot be found. make sure the testenvironment")


def _diagnosis(text: str) -> dict:
    """Mirror the deterministic facts the real graph applies, not a bare exit-code heuristic.

    A stub that read only `oracle_fired` and `exit_code` would make the eval dataset agree with
    the reading `graph.triage` exists to override.
    """
    execution = _tag(text, "probe_execution") or {}
    stderr = str(execution.get("stderr_tail") or "").lower()
    if execution.get("oracle_fired"):
        # Ahead of the zero-test check, as in graph.triage._ground_zero_test_diagnosis: an
        # observed exploit condition stands whatever the runner counted.
        kind = "valid_positive"
    elif execution.get("runner_reported_no_tests"):
        # Nothing exercised the sink, so the run says nothing about exploitability.
        kind = "probe_defect"
    elif any(sig in stderr for sig in _ENVIRONMENT_SIGNATURES):
        kind = "environment_issue"
    elif execution.get("exit_code") is None:
        # The probe never ran (e.g. the isolation runtime was unavailable).
        kind = "environment_issue"
    elif execution.get("exit_code") == 0 and not execution.get("sink_returned"):
        # A clean exit proves nothing if the sink call never returned.
        kind = "probe_defect"
    elif execution.get("exit_code") == 0:
        kind = "valid_negative"
    else:
        kind = "probe_defect"
    return {"kind": kind, "explanation": "stub diagnosis from the recorded execution facts"}


def _partial_build_plan(text: str) -> dict:
    """Keep the partial-build stub inside the narrowed-output contract."""
    plan = _tag(text, "failed_spec") or _env_plan(_tag(text, "stack_fingerprint"))
    return {**plan, "scope": "partial", "module_path": plan.get("module_path") or "."}


_STUBS: dict[str, Callable[[str], dict]] = {
    # The atomic-claims wire with no claim: every field null.
    "intake": lambda t: {},
    "recon": lambda t: {
        "summary": "stub profile",
        "primary_language": _primary_language(_stack(_tag(t, "stack_fingerprint"))),
        "frameworks": [], "components": [], "entry_points": [],
        "test_framework": ((_tag(t, "stack_fingerprint") or {}).get("test_frameworks") or ["unknown"])[0],
        "test_layout": "unknown"},
    "env-planner": lambda t: _env_plan(_tag(t, "stack_fingerprint")),
    "build-repair": lambda t: (_tag(t, "failed_spec") or _env_plan(_tag(t, "stack_fingerprint"))),
    "partial-build": _partial_build_plan,
    "context": lambda t: {"summary": "stub context", "reachability": "unknown",
                          "source": None, "sink": None, "path": [], "sanitizers": [],
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
        if agent_name == "verdict" and "Use inconclusive_reason=environment_unbuildable." in (
            info.instructions or ""
        ):
            args["inconclusive_reason"] = "environment_unbuildable"
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, args)])

    return FunctionModel(respond, model_name=f"stub-{agent_name}-{tier}")

