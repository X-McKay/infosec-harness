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

# The commands, paths, warm-ups and image table the validators enforce. Sharing them is the
# point: a stub plan the validators would reject makes every offline test a lie, and a stub that
# carried its own copy of the Maven recipe is exactly how the JUnit-5-only warm-up survived here
# after being found wrong for the corpus.
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
# The table itself is ecosystem_contract.JS_TEST_COMMANDS, the one the validators check against.
# ts-jest type-checks the probe, so a TS project also needs the *type* declarations for whichever
# runner's globals the probe uses: without @types/jest the run fails with
# "TS2582: Cannot find name 'test'" and reports `Tests: 0 total`, never executing the probe.
_TS_JEST_PACKAGES = ("ts-jest", "typescript", "@types/jest", "@types/node")


def _node_plan(stack: dict, manifests: set[str], typescript: bool) -> dict:
    frameworks = [f for f in (stack.get("test_frameworks") or []) if f in JS_TEST_COMMANDS]
    runner = frameworks[0] if frameworks else "jest"
    install = ["npm ci --no-audit --no-fund" if "package-lock.json" in manifests
               else "npm install --no-audit --no-fund"]
    command = JS_TEST_COMMANDS[runner]
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


def _jvm_framework(stack: dict | None) -> str:
    """The JVM test framework the fingerprint reports, defaulting the way the corpus does.

    JUnit 4 rather than JUnit 5 when nothing is declared: of the 51 Maven entries harvested from
    Vul4J, 50 are JUnit 4 (or JUnit 3 on the JUnit 4 artifact) and one is JUnit 5.
    """
    declared = set((stack or {}).get("test_frameworks") or ())
    for name in ("junit5", "junit4", "testng"):
        if name in declared:
            return name
    return "junit4"


def _maven_image(stack: dict | None) -> str:
    """A base image whose javac still accepts the level the project declares.

    temurin-21 unconditionally was wrong: JDK 21 refuses -source 7, which 14 of the 58 harvested
    Vul4J entries declare, and JDK 17 refuses -source 6, which some of the rest declare. Measured
    with Zulu 8/11/17/21 under Maven 3.9.16 -- see skills/build-maven for the table.
    """
    release = (stack or {}).get("java_release")
    if release is None:
        return "maven:3.9-eclipse-temurin-17"
    return maven_image_for_release(release)


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
                "test_command": PYTEST_TEST_COMMAND,
                # `pip --user` installs under HOME at build time; the probe runs from its copy.
                "env": {"PYTHONDONTWRITEBYTECODE": "1",
                        "PATH": f"{RUNTIME_HOME}/.local/bin:/usr/local/bin:/usr/bin:/bin"},
                "rationale": "stub heuristic: python"}
    if lang in {"javascript", "typescript"}:
        return _node_plan(stack, manifests, typescript=lang == "typescript")
    if lang == "java":
        # Compile with test-compile and then invoke a *pinned* surefire goal: the version Maven
        # 3.x binds to the `test` phase is 2.12.4, which has no JUnit Platform provider, and a
        # phase-bound plugin version cannot be overridden from the command line. The build warms
        # the pinned plugin and its provider into the local repo so the probe run can be offline.
        # The second install command writes a throwaway test and *runs* it, then removes it.
        # Merely invoking the plugin with nothing to run (`-DfailIfNoTests=false`) is not enough:
        # surefire resolves its provider lazily at test-execution time, from the framework on the
        # test classpath, so the warm-up downloaded the plugin and all of its own dependencies and
        # the offline probe still died on `surefire-junit-platform:jar:3.2.5 (absent)`. Verified
        # against eval-corpus/java: with the real run, the offline probe passes in a
        # --network=none container; without it, all four cases fail.
        #
        # The warm-up's framework and the base image are *read*, not assumed. The stub used to
        # emit a JUnit 5 warm-up and temurin-21 unconditionally, and both are wrong for most real
        # Java: a jupiter warm-up in a JUnit 4 project fails test-compile ("cannot find symbol:
        # class Test") so no image is ever built, and JDK 21's javac rejects -source 7, which 14
        # of the harvested Vul4J entries declare. Both were executed; see skills/build-maven.
        framework = _jvm_framework(stack)
        return {"base_image": _maven_image(stack),
                # -Dmaven.repo.local is not optional: Maven reads user.home, which is /root for
                # the sandbox user's unmapped uid. Build writes under /opt/home; the probe reads
                # the /work/home copy of it.
                "install_commands": [MAVEN_INSTALL_COMMAND, MAVEN_WARMUP_COMMANDS[framework]],
                "test_command": MAVEN_TEST_COMMAND,
                "rationale": f"stub heuristic: maven, {framework}"}
    if lang == "perl":
        # The shape verified against the corpus (see skills/build-cpanm): --local-lib because the
        # sandbox user cannot write perl's site dir and cpanm would otherwise report success and
        # install nothing importable. Keep PERL5LIB on the immutable /opt/home install: /work is
        # a noexec tmpfs, so copying an XS module there makes its shared object unmappable.
        # `prove` is perl core, so nothing installs it -- `App::prove` is not a distribution.
        return {"base_image": "perl:5.38-slim",
                "system_packages": ["gcc", "make", "libc6-dev"],
                "install_commands": [CPANM_INSTALL_COMMAND],
                "env": {"PERL5LIB": PERL5LIB_PATH},
                # -Ilib, not just -v: measured on a fixture whose modules live in blib/lib and
                # one whose live in src/perl, a probe with no `use lib` and a prove with no -I
                # dies on `Can't locate Runner.pm`. The recipe in skills/build-cpanm says both
                # flags are load-bearing and this stub used to carry only one of them.
                "test_command": PROVE_TEST_COMMAND, "rationale": "stub heuristic: perl"}
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


def _java_probe(annotation_import: str, annotation: str, modifier: str, method: str) -> str:
    """A stub Java probe in one framework's shape.

    JUnit 4 and TestNG need `public` on both the class and the method: with either left
    package-private Surefire's JUnit4Provider reports `initializationError` and prints no markers,
    so a stub written in the JUnit 5 shape would fail on exactly the repositories this stub is
    meant to exercise. The `-Dtest=HarnessProbeTest` selector names the class, so the file's name,
    its class and the selector all have to be HarnessProbeTest.
    """
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


# Java has no single shape: which annotation compiles, and whether package-private is allowed,
# depends on the framework on the project's test classpath. The stub used to fall through to the
# shell fallback for Java entirely, so a stub Java run wrote `harness_probe.sh` and handed it to
# `mvn -Dtest=HarnessProbeTest`, which runs nothing.
_JAVA_PROBES = {
    "junit4": _java_probe("import org.junit.Test;", "@Test", "public", "probe"),
    "junit5": _java_probe("import org.junit.jupiter.api.Test;", "@Test", "public", "probe"),
    "testng": _java_probe("import org.testng.annotations.Test;", "@Test", "public", "probe"),
}
_JAVA_PROBE_PATH = "src/test/java/HarnessProbeTest.java"


def _probe(text: str) -> dict:
    # `or {}` because both branches below call `.get()` on it.
    stack = _tag(text, "stack_fingerprint") or {}
    lang = _primary_language(stack)
    nonce = _tag(text, "oracle_nonce") or "none"
    plan = _tag(text, "probe_plan") or {}
    fallback = ("harness_probe.sh",
                "echo HARNESS_PRECONDITION::{nonce}\n"
                "echo HARNESS_SINK_RETURNED::{nonce}\n"
                "if false; then echo HARNESS_ORACLE::{nonce}; fi\n")
    # The probe body is per *runner*, not per language: a jest-shaped body throws
    # `ReferenceError: test is not defined` under vitest, and a jupiter-shaped body does not
    # compile against the JUnit 4 artifact. Both were measured.
    if lang == "java":
        path, body = _JAVA_PROBE_PATH, _JAVA_PROBES[_jvm_framework(stack)]
    else:
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


def _partial_build_plan(text: str) -> dict:
    """Keep the partial-build stub inside the narrowed-output contract."""
    plan = _tag(text, "failed_spec") or _env_plan(_tag(text, "stack_fingerprint"))
    return {**plan, "scope": "partial", "module_path": plan.get("module_path") or "."}


_STUBS: dict[str, Callable[[str], dict]] = {
    "intake": lambda t: {"evidence": []},
    "recon": lambda t: {
        "summary": "stub profile", "primary_language": _primary_language(_tag(t, "stack_fingerprint")),
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


def atomic_intake_stub_model(agent_name: str, tier: str) -> Model:
    """Deterministic no-claim output for the new typed intake wire in offline mode."""
    from pydantic_ai.messages import ModelResponse, ToolCallPart

    def respond(_messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        if agent_name != "intake" or not info.output_tools:
            raise RuntimeError(f"No atomic intake stub for agent {agent_name!r}")
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, {})])

    return FunctionModel(respond, model_name=f"stub-{agent_name}-{tier}-atomic")
