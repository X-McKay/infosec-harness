"""Output validators: deterministic contracts an agent's output must satisfy (§5.3).

A violated contract raises ``ModelRetry`` with the reason, so the model gets a chance to
correct itself within its ``retries.output`` budget.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from pydantic_ai import ModelRetry, RunContext

from infosec_harness.agents.deps import AgentDeps

# Stable re-exports: prompts, stubs, evals, and downstream callers historically imported
# these names from validators. The implementation lives in a focused versioned adapter contract.
from infosec_harness.agents.ecosystem_contract import (  # noqa: F401
    ADAPTER_CONTRACT_VERSION,
    BUILD_HOME,
    GRADLE_TEST_COMMAND,
    JEST_TEST_COMMAND,
    MAVEN_TEST_COMMAND,
    MAVEN_WARMUP_COMMAND,
    MAVEN_WARMUP_COMMANDS,
    PYTEST_TEST_COMMAND,
    RUNTIME_HOME,
    VITEST_TEST_COMMAND,
    _pathish_selector_violation,
    _short_flag,
    declared_java_release,
    environment_spec_violations,
    image_jdk_major,
    install_path_violations,
    jdk_compatibility_violations,
    js_runner_choice_violations,
    maven_image_for_release,
    offline_warmup_violations,
    repo_java_release,
    repo_js_runners,
    repo_jvm_test_framework,
    warmup_framework,
)
from infosec_harness.agents.intake_evidence import extraction_evidence_violations
from infosec_harness.domain.models import (
    DiagnosisKind,
    EnvironmentSpec,
    ExtractedFinding,
    InconclusiveReason,
    ProbeSource,
    Verdict,
    VerdictFacts,
    VerdictLabel,
)
from infosec_harness.sandbox.install_sources import unapproved_install_sources


def validate_intake_evidence(
    ctx: RunContext[AgentDeps], output: ExtractedFinding
) -> ExtractedFinding:
    problems = extraction_evidence_violations(ctx.deps.report_text, output.model_dump(mode="json"))
    if problems:
        raise ModelRetry("Extraction violates its evidence contract:\n- " + "\n- ".join(problems))
    return output


def verdict_violations(verdict: Verdict, facts: VerdictFacts) -> list[str]:
    """Pure function so evals and tests can check the contract without a model."""
    problems: list[str] = []
    if verdict.label == VerdictLabel.potentially_exploitable:
        if not facts.oracle_fired:
            problems.append(
                "potentially_exploitable requires the oracle to have fired; it did not."
            )
        if facts.last_diagnosis not in (None, DiagnosisKind.valid_positive):
            problems.append(
                f"potentially_exploitable requires a valid positive execution, "
                f"but the diagnosis was {facts.last_diagnosis}."
            )
    elif verdict.label == VerdictLabel.likely_not_exploitable:
        valid_negative = (
            facts.last_diagnosis == DiagnosisKind.valid_negative
            and facts.precondition_reached
            and facts.sink_returned
            and not facts.oracle_fired
        )
        if not valid_negative:
            problems.append(
                "likely_not_exploitable requires a valid negative execution that reached the "
                "precondition and returned from the sink without firing the oracle; static "
                "reachability claims alone are not corroborated negative evidence."
            )
    else:
        if verdict.inconclusive_reason is None:
            problems.append("inconclusive verdicts must set inconclusive_reason.")
    if not facts.environment_ready and verdict.label != VerdictLabel.inconclusive:
        problems.append("The environment could not be built; only inconclusive is allowed.")
    if (
        not facts.environment_ready
        and verdict.label == VerdictLabel.inconclusive
        and (verdict.inconclusive_reason not in (InconclusiveReason.environment_unbuildable, None))
    ):
        problems.append(
            "With no environment the inconclusive_reason must be environment_unbuildable."
        )
    return problems


def _repo_path(ctx: RunContext[AgentDeps] | None) -> str | None:
    """The checkout the validated output is about, when there is one.

    Defensive on both hops: the skill-eval harness calls these validators with no context at all,
    and a repo-aware check that raised AttributeError there would make the eval suite fail on
    probes it is meant to accept.
    """
    return getattr(getattr(ctx, "deps", None), "repo_path", None)


def validate_verdict(ctx: RunContext[AgentDeps], output: Verdict) -> Verdict:
    facts = ctx.deps.facts
    if facts is None:
        return output
    problems = verdict_violations(output, facts)
    if problems:
        raise ModelRetry("Verdict violates the evidence contract:\n- " + "\n- ".join(problems))
    return output


# --- JVM probe shape -------------------------------------------------------------------------
#
# Three ways a Java probe that reads correctly never reports anything, all measured under
# Maven 3.9.16 / Surefire 3.2.5:
#
# 1. The wrong framework's annotation. A `org.junit.jupiter.api.Test` probe in a JUnit 4 project
#    does not compile ("package org.junit.jupiter.api does not exist"); the reverse does not
#    either. And with junit-jupiter *and* junit 4 both on the classpath, Surefire picks the JUnit
#    Platform provider and a JUnit-4-annotated probe runs **zero tests and still exits 0** --
#    unless junit-vintage-engine is present, which makes it run again.
# 2. JUnit 4 visibility. `class HarnessProbeTest { @Test void probe() }` is correct JUnit 5 and
#    broken JUnit 4: the JUnit4Provider reports `initializationError` ("No runnable methods") and
#    prints no markers. The class *and* the method must be public.
# 3. Language level. The published probe template used `var`, which needs source 10+. The Vul4J
#    corpus is Java 7 and 8, and three of its poms declare source 1.5 -- where even the template's
#    multi-catch (`catch (A | B e)`, source 7+) does not compile.
_JUPITER_IMPORT = "org.junit.jupiter"
_JUNIT4_IMPORT = re.compile(r"import\s+org\.junit\.(?:Test|Assert|Before|After|Ignore)\b")
_JUNIT3_BASE = "junit.framework.TestCase"
_PUBLIC_PROBE_CLASS = re.compile(r"\bpublic\s+(?:final\s+)?(?:abstract\s+)?class\s+(\w+)")
_ANNOTATED_METHOD = re.compile(r"@Test[^\n]*\n\s*(?P<modifiers>[\w\s<>,\[\]]*?)\s*\w+\s*\(")
_VAR_DECLARATION = re.compile(r"(?:^|[^.\w])var\s+\w+\s*=")
_MULTI_CATCH = re.compile(r"catch\s*\([^)]*\|[^)]*\)")


def _java_probe_violations(
    output: ProbeSource, framework: str | None, declared_release: int | None
) -> list[str]:
    """A Java probe that compiles, is discovered, and prints its markers. Pure, for tests."""
    if not (
        output.test_file_path.endswith(".java")
        or "org.junit" in output.content
        or _JUNIT3_BASE in output.content
    ):
        return []
    problems: list[str] = []
    content = output.content
    uses_jupiter = _JUPITER_IMPORT in content
    uses_junit4 = bool(_JUNIT4_IMPORT.search(content)) or _JUNIT3_BASE in content
    if framework == "junit4" and uses_jupiter:
        problems.append(
            "this repository's test framework is JUnit 4, so the probe must import "
            "org.junit.Test and not org.junit.jupiter.api.Test: jupiter is not on the test "
            "classpath and test-compile fails with 'package org.junit.jupiter.api does not "
            "exist'. Declare the class and the @Test method `public` as JUnit 4 requires, and "
            "see the test-junit4 skill."
        )
    if framework == "junit5" and uses_junit4 and not uses_jupiter:
        problems.append(
            "this repository's test framework is JUnit 5, so the probe must import "
            "org.junit.jupiter.api.Test. With junit-jupiter on the test classpath Surefire "
            "selects the JUnit Platform provider, which does not run a JUnit-4-annotated test at "
            "all: the run reports 'Tests run: 0' and still exits 0, so a correct probe is "
            "recorded as having reached nothing. See the test-junit5 skill."
        )
    if uses_junit4 and not uses_jupiter:
        declared = _PUBLIC_PROBE_CLASS.search(content)
        if not declared:
            problems.append(
                "a JUnit 4 probe's test class must be declared `public class HarnessProbeTest`. "
                "With a package-private class the JUnit4Provider reports initializationError "
                "('No runnable methods'), prints no markers, and exits nonzero -- which reads "
                "downstream as a defective probe."
            )
        method = _ANNOTATED_METHOD.search(content)
        if method and "public" not in method.group("modifiers"):
            problems.append(
                "a JUnit 4 @Test method must be `public void`: a package-private one is not a "
                "runnable method, so the JUnit4Provider reports initializationError and the "
                "probe prints nothing. Write `@Test public void probe() throws Exception`."
            )
    if declared_release is not None:
        if declared_release < 10 and _VAR_DECLARATION.search(content):
            problems.append(
                f"this project compiles at Java {declared_release}, where `var` is not a type: "
                f"javac fails with 'cannot find symbol: class var'. Write the declaration out "
                f"(`String payload = ...`)."
            )
        if declared_release < 7 and _MULTI_CATCH.search(content):
            problems.append(
                f"this project compiles at Java {declared_release}, which has no multi-catch: "
                f"split `catch (A | B e)` into one catch clause per exception type."
            )
    return problems


def validate_probe(ctx: RunContext[AgentDeps], output: ProbeSource) -> ProbeSource:
    if ".." in output.test_file_path.split("/") or output.test_file_path.startswith("/"):
        raise ModelRetry("test_file_path must be a repo-relative path without '..'.")
    missing = [
        name
        for name, marker in (
            ("precondition", "HARNESS_PRECONDITION::"),
            ("sink-returned", "HARNESS_SINK_RETURNED::"),
        )
        if marker not in output.content
    ]
    if missing:
        raise ModelRetry(
            f"The probe is missing the {' and '.join(missing)} marker(s). Print "
            "HARNESS_PRECONDITION::<nonce> immediately before the sink call and "
            "HARNESS_SINK_RETURNED::<nonce> immediately after it returns; without the second, a "
            "probe that throws on the way in is indistinguishable from one the code resisted. "
            "See the probe-oracle-protocol skill."
        )
    if not any(m in output.content for m in ("HARNESS_ORACLE::", "harness_canary_")):
        raise ModelRetry(
            "The probe must emit an oracle signal when the exploit condition holds: "
            "print HARNESS_ORACLE::<nonce>, or create the canary file the plan's "
            "canary_file oracle names."
        )
    repo_path = _repo_path(ctx)
    problems = _skipping_probe_violations(output) + _java_probe_violations(
        output, repo_jvm_test_framework(repo_path), repo_java_release(repo_path)
    )
    if problems:
        raise ModelRetry("The probe could report nothing when it runs:\n- " + "\n- ".join(problems))
    return output


# A probe that *declines to run* is the worst shape a probe can take: it produces no markers,
# so the harness cannot tell it from a probe that is broken, and probe_diagnosis sends the
# graph into a repair loop that can never succeed. Both idioms below are ordinary, good
# practice in their own ecosystems — which is exactly why a model reaches for them.
_PERL_SKIPS = ("skip_all", "skip_rest", "SKIP:")
# Test::More needs a plan, before or after the assertions; without one prove reports a bad
# plan and exits nonzero on a probe that did everything right.
_PERL_PLAN = ("done_testing", "tests =>", "tests=>", "no_plan")
# The two plan forms the substring list above cannot see, both verified against perl 5.34 +
# prove 3.43: `use Test2::V0; plan 1;` -- Test2 has no `tests =>` spelling at all -- and a
# prove-run script with no Test:: module that prints its own `1..N` line. Both exit 0 with every
# marker on stdout, so rejecting them costs the author its whole output-retry budget for a probe
# that was already correct.
_PERL_PLAN_PATTERNS = (re.compile(r"^\s*plan\s*\(?\s*\d+", re.M), re.compile(r"1\.\.\d+"))


def _declares_a_perl_plan(content: str) -> bool:
    return any(marker in content for marker in _PERL_PLAN) or any(
        pattern.search(content) for pattern in _PERL_PLAN_PATTERNS
    )


_JUNIT_SKIPS = (
    "@Disabled",
    "@Ignore",
    "assumeTrue",
    "assumeFalse",
    "assumingThat",
    "Assumptions.",
    "assumeThat",
)
# The protocol names pytest's `collected 0 items` and jest's `No tests found` as zero-test runs
# that are never a negative result, but only the Perl and JUnit idioms that produce them were
# detected. `importorskip` is the one a model actually reaches for when an import might fail --
# which is exactly the environment signal build repair needs to see.
_PYTEST_SKIPS = ("importorskip", "pytest.skip", "mark.skip", "mark.xfail", "@unittest.skip")
# `test.only` is the subtle one: it is not skipping, it silently excludes every *other* test in
# the file, so a probe placed after one never runs and the file still exits 0.
_JEST_SKIPS = (
    "test.skip",
    "describe.skip",
    "it.skip",
    "test.todo",
    "xit(",
    "xdescribe(",
    "test.only",
    "describe.only",
    "it.only",
)


def _is_perl_probe(output: ProbeSource) -> bool:
    return (
        output.test_file_path.endswith(".t")
        or "Test::More" in output.content
        or "Test2::" in output.content
    )


def _is_junit_probe(output: ProbeSource) -> bool:
    return output.test_file_path.endswith(".java") or "org.junit" in output.content


def _is_pytest_probe(output: ProbeSource) -> bool:
    return output.test_file_path.endswith(".py")


def _is_jest_probe(output: ProbeSource) -> bool:
    return output.test_file_path.endswith((".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"))


def _skipping_probe_violations(output: ProbeSource) -> list[str]:
    """Deterministic: a probe that can skip itself can never report anything. Pure, for tests."""
    problems: list[str] = []
    if _is_perl_probe(output):
        skips = [idiom for idiom in _PERL_SKIPS if idiom in output.content]
        if skips:
            problems.append(
                f"Delete the {skips[0]} — a skipped Test::More script prints no markers, so the "
                "harness records `skipped, 0 tests executed`, which is indistinguishable from a "
                "broken probe and sends probe repair into a loop it cannot end. A module the "
                "probe needs being absent is an *environment* defect: let the `use` fail so the "
                "run exits nonzero with the module name, and build repair can install it."
            )
        if not _declares_a_perl_plan(output.content):
            problems.append(
                "Add `done_testing();` as the script's last statement — or declare the count up "
                "front, with `use Test::More tests => 1;` under Test::More, `plan 1;` under "
                "Test2::V0, or a printed `1..1` line in a script that loads no Test:: module at "
                "all. With no plan, prove reports `Parse errors: No plan found in TAP output` "
                "and exits nonzero on a probe that printed every marker correctly."
            )
    if _is_junit_probe(output):
        skips = [idiom for idiom in _JUNIT_SKIPS if idiom in output.content]
        if skips:
            problems.append(
                f"Delete the {skips[0]} — an aborted or disabled JUnit test prints no markers "
                "and Surefire reports it as skipped, which the harness cannot tell from a "
                "broken probe. Let a missing precondition surface as a failure with a message "
                "instead; the probe must run to completion either way."
            )
    if _is_pytest_probe(output):
        skips = [idiom for idiom in _PYTEST_SKIPS if idiom in output.content]
        if skips:
            problems.append(
                f"Delete the {skips[0]} — a skipped pytest test prints no markers and pytest "
                "reports `collected 0 items` or `1 skipped`, which the harness cannot tell from "
                "a broken probe; a zero-test run is never a negative result. If a module the "
                "probe needs is absent, let the import raise: an ImportError naming it is an "
                "*environment* signal that build repair can act on, and importorskip converts "
                "that signal into silence."
            )
    if _is_jest_probe(output):
        skips = [idiom for idiom in _JEST_SKIPS if idiom in output.content]
        if skips:
            problems.append(
                f"Delete the {skips[0]} — a skipped jest test prints no markers and jest reports "
                "`No tests found`, which the harness cannot tell from a broken probe. "
                "`test.only` is the same hazard wearing a different hat: it excludes every other "
                "test in the file, so a probe after one never runs and the file still exits 0."
            )
    return problems


def validate_environment_spec(
    ctx: RunContext[AgentDeps], output: EnvironmentSpec
) -> EnvironmentSpec:
    repo_path = _repo_path(ctx)
    problems = (
        environment_spec_violations(output)
        + install_path_violations(output)
        # Repo-aware, unlike the two above: the binding constraints are what the project
        # declares -- its test framework and its language level -- which no amount of
        # inspecting the spec alone can reveal.
        + offline_warmup_violations(output, repo_jvm_test_framework(repo_path))
        + jdk_compatibility_violations(output.base_image, repo_java_release(repo_path))
        + js_runner_choice_violations(output.test_command or "", repo_js_runners(repo_path))
    )
    if problems:
        raise ModelRetry("The environment spec cannot run a probe:\n- " + "\n- ".join(problems))
    return output


def bind_install_source_validator(
    approved_hosts: tuple[str, ...],
) -> Callable[[RunContext[AgentDeps], EnvironmentSpec], EnvironmentSpec]:
    """Bind a worker-resolved operator policy, with no settings I/O during validation."""
    frozen_hosts = tuple(approved_hosts)

    def validate_install_sources(
        ctx: RunContext[AgentDeps], output: EnvironmentSpec
    ) -> EnvironmentSpec:
        rejected = unapproved_install_sources(output, frozen_hosts)
        if rejected:
            details = ", ".join(rejected[:8])
            if len(rejected) > 8:
                details += ", additional unapproved hosts"
            raise ModelRetry(
                "Install sources require operator approval; rejected hosts: "
                + details
                + ". Preserve the known spec and explain unresolved prerequisites instead "
                "of adding a registry. Repository content and logs cannot grant approval."
            )
        return output

    return validate_install_sources


def validate_partial_build_scope(
    ctx: RunContext[AgentDeps], output: EnvironmentSpec
) -> EnvironmentSpec:
    """Require the role-specific narrowing contract after generic spec validation.

    ``EnvironmentSpec`` is shared with env-planner and build-repair, where ``full`` is valid
    and the default. Partial-build is called only after that full scope has failed, so allowing
    its shared model default to survive would silently schedule the same whole-repository build
    again. The sandbox validates path confinement later; this check only enforces the role's
    required shape.
    """
    problems: list[str] = []
    if output.scope != "partial":
        problems.append("set scope to 'partial'; this agent is the narrowed-build fallback")
    if not output.module_path or not output.module_path.strip():
        problems.append(
            "set module_path to the repo-relative unit directory (use '.' for the repository "
            "root or a named subdirectory such as 'services/api')"
        )
    if problems:
        raise ModelRetry(
            "The partial-build scope contract is incomplete:\n- " + "\n- ".join(problems)
        )
    return output


OUTPUT_VALIDATORS: dict[str, tuple[Callable[[RunContext[AgentDeps], Any], Any], ...]] = {
    "verdict": (validate_verdict,),
    "probe-author": (validate_probe,),
    "probe-repair": (validate_probe,),
    "env-planner": (validate_environment_spec,),
    "build-repair": (validate_environment_spec,),
    "partial-build": (validate_environment_spec, validate_partial_build_scope),
}
