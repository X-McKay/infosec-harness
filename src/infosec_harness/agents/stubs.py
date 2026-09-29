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


# One command per Node runner, because the runner is not interchangeable with its selector.
# Measured on real fixtures under node 18/20/22:
#   * `--runTestsByPath` is a jest-only flag; `vitest run --runTestsByPath <path>` dies in vitest's
#     argument parser before a single test runs.
#   * every one of these carries a defeat for the project's own console silencing where one
#     exists: a repository `jest.config.js` or `vitest.config.js` with `silent: true` erases all
#     three HARNESS_ markers while still exiting 0, and `--silent=false` restores them. mocha and
#     node:test never capture a test's stdout, so they need no flag.
_JS_TEST_COMMANDS = {
    "jest": "npx jest --silent=false --runTestsByPath {test_file}",
    "vitest": "npx vitest run --silent=false {test_file}",
    "mocha": "npx mocha {test_file}",
    "node:test": "node --test {test_file}",
    "jasmine": "npx jasmine {test_file}",
}
# ts-jest type-checks the probe, so a TS project also needs the *type* declarations for whichever
# runner's globals the probe uses: without @types/jest the run fails with
# "TS2582: Cannot find name 'test'" and reports `Tests: 0 total`, never executing the probe.
_TS_JEST_PACKAGES = ("ts-jest", "typescript", "@types/jest", "@types/node")


def _node_plan(stack: dict, manifests: set[str], typescript: bool) -> dict:
    frameworks = [f for f in (stack.get("test_frameworks") or []) if f in _JS_TEST_COMMANDS]
    runner = frameworks[0] if frameworks else "jest"
    install = ["npm ci --no-audit --no-fund" if "package-lock.json" in manifests
               else "npm install --no-audit --no-fund"]
    command = _JS_TEST_COMMANDS[runner]
    note = f"stub heuristic: node, runner {runner}"
    if typescript:
        # A .ts probe reaches nothing under a bare `npx jest`: the default babel transform has no
        # TypeScript plugin and the suite fails to parse. vitest compiles TS with no configuration
        # at all, tsx does the same for node:test, and jest needs ts-jest named on the command
        # line because the spec may not edit the repository's jest.config.
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
                "test_command": "python -m pytest -q -s -o addopts= {test_file}",
                "env": {"PYTHONDONTWRITEBYTECODE": "1", "PATH": "/work/home/.local/bin:/usr/local/bin:/usr/bin:/bin"},
                "rationale": "stub heuristic: python"}
    if lang in {"javascript", "typescript"}:
        return _node_plan(stack, manifests, typescript=lang == "typescript")
    if lang == "java":
        # Compile with test-compile and then invoke a *pinned* surefire goal: the version Maven
        # 3.x binds to the `test` phase is 2.12.4, which has no JUnit Platform provider, and a
        # phase-bound plugin version cannot be overridden from the command line. The build warms
        # the pinned plugin and its provider into the local repo so the probe run can be offline.
        # The second install command writes a throwaway JUnit 5 test and *runs* it, then removes
        # it. Merely invoking the plugin with nothing to run (`-DfailIfNoTests=false`) is not
        # enough: surefire resolves its provider lazily at test-execution time, from the JUnit
        # version on the test classpath, so the warm-up downloaded the plugin and all of its own
        # dependencies and the offline probe still died on `surefire-junit-platform:jar:3.2.5
        # (absent)`. Verified against eval-corpus/java: with the real run, the offline probe
        # passes in a --network=none container; without it, all four cases fail.
        return {"base_image": "maven:3.9-eclipse-temurin-21",
                # -Dmaven.repo.local is not optional: Maven reads user.home, which is /root for
                # the sandbox user's unmapped uid. Build writes under /opt/home; the probe reads
                # the /work/home copy of it.
                "install_commands": [
                    "mvn -B -Dmaven.repo.local=/opt/home/.m2/repository -DskipTests test-compile",
                    "mkdir -p src/test/java && echo 'import org.junit.jupiter.api.Test; class "
                    "HarnessWarmupTest { @Test void warm() {} }' > "
                    "src/test/java/HarnessWarmupTest.java && "
                    "mvn -B -Dmaven.repo.local=/opt/home/.m2/repository test-compile "
                    "org.apache.maven.plugins:maven-surefire-plugin:3.2.5:test "
                    "-Dtest=HarnessWarmupTest && "
                    "rm -f src/test/java/HarnessWarmupTest.java "
                    "target/test-classes/HarnessWarmupTest.class"],
                "test_command": ("mvn -B -o -Dmaven.repo.local=/work/home/.m2/repository "
                                 "test-compile "
                                 "org.apache.maven.plugins:maven-surefire-plugin:3.2.5:test "
                                 "-Dtest=HarnessProbeTest "
                                 "-Dmaven.test.redirectTestOutputToFile=false"),
                "rationale": "stub heuristic: maven"}
    if lang == "perl":
        # The shape verified against the corpus (see skills/build-cpanm): --local-lib because the
        # sandbox user cannot write perl's site dir and cpanm would otherwise report success and
        # install nothing importable; the install path is the build-time /opt/home while PERL5LIB
        # is the probe-time /work/home it gets copied to; gcc/make because DBI is an XS module.
        # `prove` is perl core, so nothing installs it -- `App::prove` is not a distribution.
        return {"base_image": "perl:5.38-slim",
                "system_packages": ["gcc", "make", "libc6-dev"],
                "install_commands": ["cpanm --notest --local-lib=/opt/home/perl5 --installdeps ."],
                "env": {"PERL5LIB": "/work/home/perl5/lib/perl5"},
                # -Ilib, not just -v: measured on a fixture whose modules live in blib/lib and
                # one whose live in src/perl, a probe with no `use lib` and a prove with no -I
                # dies on `Can't locate Runner.pm`. The recipe in skills/build-cpanm says both
                # flags are load-bearing and this stub used to carry only one of them.
                "test_command": "prove -v -Ilib {test_file}", "rationale": "stub heuristic: perl"}
    return {"base_image": "debian:bookworm-slim", "install_commands": [],
            "test_command": "sh {test_file}", "rationale": "stub heuristic: unknown stack"}


# A bare `test(...)` is a global under jest only. vitest ships `globals: false` by default and
# mocha's default BDD interface names it `it`, so the same body that passes under jest dies with
# `ReferenceError: test is not defined` under either -- measured on real fixtures. The stub's
# probe has to match the runner its own env plan chose, or every offline run of a vitest or mocha
# repository fails for a reason that has nothing to do with the code under test.
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
    "javascript": ("__tests__/harness_probe.test.js", _JS_PROBE_BODY.format(head="")),
    "perl": ("t/harness_probe.t",
             "use Test::More tests => 1;\n"
             "print \"HARNESS_PRECONDITION::{nonce}\\n\";\n"
             "print \"HARNESS_SINK_RETURNED::{nonce}\\n\";\n"
             "my $observed = 0;  # the stub never observes the condition\n"
             "print \"HARNESS_ORACLE::{nonce}\\n\" if $observed;\n"
             "ok(1);\n"),
}


def _probe(text: str) -> dict:
    stack = _tag(text, "stack_fingerprint") or {}
    lang = _primary_language(stack)
    nonce = _tag(text, "oracle_nonce") or "none"
    plan = _tag(text, "probe_plan") or {}
    fallback = ("harness_probe.sh",
                "echo HARNESS_PRECONDITION::{nonce}\n"
                "echo HARNESS_SINK_RETURNED::{nonce}\n"
                "if false; then echo HARNESS_ORACLE::{nonce}; fi\n")
    path, body = _PROBE_TEMPLATES.get(lang, fallback)
    if lang in {"javascript", "typescript"}:
        runner = next((f for f in (stack.get("test_frameworks") or []) if f in _JS_PROBE_TEMPLATES),
                      "jest")
        body = _JS_PROBE_TEMPLATES[runner]
        path = _PROBE_TEMPLATES["javascript"][0]
    path = plan.get("test_file_path") or path
    return {"test_file_path": path, "content": body.replace("{nonce}", str(nonce)),
            "explanation": "stub probe: reaches the sink and returns; observes nothing"}


# Stderr shapes that mean the environment lacked something the test needed, rather than the
# probe being wrong. Measured on java-sqli: a missing JDBC driver at probe time.
_ENVIRONMENT_SIGNATURES = ("no suitable driver", "can't locate", "cannot find module",
                           "modulenotfounderror", "classnotfoundexception",
                           # Node. Both were measured as exit-1 runs with no test output at all,
                           # so without them the stub read each as a probe defect and sent the
                           # graph to probe repair, which can install nothing: `npx` refusing to
                           # fetch a runner the project never declared, and a jest config naming
                           # a test environment package (jest-environment-jsdom, removed from
                           # jest core in 28) that the install did not provide.
                           "npx canceled due to missing packages",
                           "cannot be found. make sure the testenvironment")


def _diagnosis(text: str) -> dict:
    """Mirror the deterministic facts the real graph applies, not a bare exit-code heuristic.

    This stub used to decide from `oracle_fired` and `exit_code` alone -- which is exactly the
    reading `graph.triage._correct_unsupported_negative` and `_ground_zero_test_diagnosis`
    exist to override, and exactly what the live agent regressed to on perl-cmdi-vulnerable.
    A stub that models the bug makes the eval dataset agree with the wrong answer, so the
    dataset stops being able to catch it: the new zero-test and unreturned-sink cases failed
    here until this was fixed, which is the dataset doing its job.
    """
    execution = _tag(text, "probe_execution") or {}
    stderr = str(execution.get("stderr_tail") or "").lower()
    if execution.get("oracle_fired"):
        # Ahead of the zero-test check, and mirroring graph.triage._ground_zero_test_diagnosis:
        # the exploit condition was observed, so what the runner counted while it was observed
        # cannot unmake that. A run with markers and `Tests: 0` is a real shape, not a hypothesis.
        kind = "valid_positive"
    elif execution.get("runner_reported_no_tests"):
        # Nothing exercised the sink, so the run says nothing about exploitability.
        kind = "probe_defect"
    elif any(sig in stderr for sig in _ENVIRONMENT_SIGNATURES):
        kind = "environment_issue"
    elif execution.get("exit_code") is None:
        # No exit status at all: the probe never ran, so nothing here is about the code
        # under test. This is the shape execute_probe_activity returns when the isolation
        # runtime is unavailable.
        kind = "environment_issue"
    elif execution.get("exit_code") == 0 and not execution.get("sink_returned"):
        # A clean exit proves nothing if the sink call never returned: the precondition marker
        # is printed *before* the call, so a probe that threw mid-call is indistinguishable
        # from code that resisted the payload. That was a measured false negative.
        kind = "probe_defect"
    elif execution.get("exit_code") == 0:
        kind = "valid_negative"
    else:
        kind = "probe_defect"
    return {"kind": kind, "explanation": "stub diagnosis from the recorded execution facts"}


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
