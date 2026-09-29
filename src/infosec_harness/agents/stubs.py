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

# The warm-up commands and the image table the validators enforce. Sharing them is the point: a
# stub plan the validators would reject makes every offline test a lie, and a stub that carried
# its own copy of the Maven recipe is exactly how the JUnit-5-only warm-up survived here after
# being found wrong for the corpus.
from infosec_harness.agents.validators import MAVEN_WARMUP_COMMANDS, maven_image_for_release


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
                "test_command": "python -m pytest -q -s {test_file}",
                "env": {"PYTHONDONTWRITEBYTECODE": "1", "PATH": "/work/home/.local/bin:/usr/local/bin:/usr/bin:/bin"},
                "rationale": "stub heuristic: python"}
    if lang in {"javascript", "typescript"}:
        return {"base_image": "node:22-slim",
                "install_commands": ["npm install --no-audit --no-fund"],
                "test_command": "npx jest --runTestsByPath {test_file}", "rationale": "stub heuristic: node"}
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
                "install_commands": [
                    "mvn -B -Dmaven.repo.local=/opt/home/.m2/repository -DskipTests test-compile",
                    MAVEN_WARMUP_COMMANDS[framework]],
                "test_command": ("mvn -B -o -Dmaven.repo.local=/work/home/.m2/repository "
                                 "test-compile "
                                 "org.apache.maven.plugins:maven-surefire-plugin:3.2.5:test "
                                 "-Dtest=HarnessProbeTest "
                                 "-Dmaven.test.redirectTestOutputToFile=false"),
                "rationale": f"stub heuristic: maven, {framework}"}
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
    stack = _tag(text, "stack_fingerprint")
    lang = _primary_language(stack)
    nonce = _tag(text, "oracle_nonce") or "none"
    plan = _tag(text, "probe_plan") or {}
    fallback = ("harness_probe.sh",
                "echo HARNESS_PRECONDITION::{nonce}\n"
                "echo HARNESS_SINK_RETURNED::{nonce}\n"
                "if false; then echo HARNESS_ORACLE::{nonce}; fi\n")
    if lang == "java":
        path, body = _JAVA_PROBE_PATH, _JAVA_PROBES[_jvm_framework(stack)]
    else:
        path, body = _PROBE_TEMPLATES.get(lang, fallback)
    path = plan.get("test_file_path") or path
    return {"test_file_path": path, "content": body.replace("{nonce}", str(nonce)),
            "explanation": "stub probe: reaches the sink and returns; observes nothing"}


# Stderr shapes that mean the environment lacked something the test needed, rather than the
# probe being wrong. Measured on java-sqli: a missing JDBC driver at probe time.
_ENVIRONMENT_SIGNATURES = ("no suitable driver", "can't locate", "cannot find module",
                           "modulenotfounderror", "classnotfoundexception")


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
    if execution.get("runner_reported_no_tests"):
        # Nothing exercised the sink, so the run says nothing about exploitability.
        kind = "probe_defect"
    elif any(sig in stderr for sig in _ENVIRONMENT_SIGNATURES):
        kind = "environment_issue"
    elif execution.get("oracle_fired"):
        kind = "valid_positive"
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
