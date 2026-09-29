"""Output validators: deterministic contracts an agent's output must satisfy (§5.3).

A violated contract raises ``ModelRetry`` with the reason, so the model gets a chance to
correct itself within its ``retries.output`` budget.
"""

from __future__ import annotations

import contextlib
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic_ai import ModelRetry, RunContext

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.domain.models import (
    DiagnosisKind,
    EnvironmentSpec,
    InconclusiveReason,
    ProbeSource,
    Reachability,
    Verdict,
    VerdictFacts,
    VerdictLabel,
)

# The fingerprinter's build-file readers, reused rather than reimplemented: the recon profile the
# probe author reads, the recipe cache key, and the warm-up this module demands all have to agree
# on the framework and the language level, and copies of those rules would drift.
from infosec_harness.repo.detect import declared_java_release, jvm_test_framework


def verdict_violations(verdict: Verdict, facts: VerdictFacts) -> list[str]:
    """Pure function so evals and tests can check the contract without a model."""
    problems: list[str] = []
    if verdict.label == VerdictLabel.potentially_exploitable:
        if not facts.oracle_fired:
            problems.append("potentially_exploitable requires the oracle to have fired; it did not.")
        if facts.last_diagnosis not in (None, DiagnosisKind.valid_positive):
            problems.append(f"potentially_exploitable requires a valid positive execution, "
                            f"but the diagnosis was {facts.last_diagnosis}.")
    elif verdict.label == VerdictLabel.likely_not_exploitable:
        valid_negative = (facts.last_diagnosis == DiagnosisKind.valid_negative
                          and facts.precondition_reached and not facts.oracle_fired)
        unreachable = facts.reachability == Reachability.unreachable and bool(verdict.evidence)
        if not (valid_negative or unreachable):
            problems.append("likely_not_exploitable requires either a valid negative execution that "
                            "reached the precondition checkpoint, or an unreachable sink with cited evidence.")
    else:
        if verdict.inconclusive_reason is None:
            problems.append("inconclusive verdicts must set inconclusive_reason.")
    if not facts.environment_ready and verdict.label != VerdictLabel.inconclusive and not (
        verdict.label == VerdictLabel.likely_not_exploitable and facts.reachability == Reachability.unreachable
    ):
        problems.append("The environment could not be built; only inconclusive (or an evidenced "
                        "unreachable finding) is allowed.")
    if not facts.environment_ready and verdict.label == VerdictLabel.inconclusive and (
        verdict.inconclusive_reason not in (InconclusiveReason.environment_unbuildable, None)
    ):
        problems.append("With no environment the inconclusive_reason must be environment_unbuildable.")
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


def _java_probe_violations(output: ProbeSource, framework: str | None,
                           declared_release: int | None) -> list[str]:
    """A Java probe that compiles, is discovered, and prints its markers. Pure, for tests."""
    if not (output.test_file_path.endswith(".java") or "org.junit" in output.content
            or _JUNIT3_BASE in output.content):
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
    missing = [name for name, marker in (
        ("precondition", "HARNESS_PRECONDITION::"),
        ("sink-returned", "HARNESS_SINK_RETURNED::"),
    ) if marker not in output.content]
    if missing:
        raise ModelRetry(
            f"The probe is missing the {' and '.join(missing)} marker(s). Print "
            "HARNESS_PRECONDITION::<nonce> immediately before the sink call and "
            "HARNESS_SINK_RETURNED::<nonce> immediately after it returns; without the second, a "
            "probe that throws on the way in is indistinguishable from one the code resisted. "
            "See the probe-oracle-protocol skill."
        )
    if not any(m in output.content for m in ("HARNESS_ORACLE::", "harness_canary_")):
        raise ModelRetry("The probe must emit an oracle signal when the exploit condition holds: "
                         "print HARNESS_ORACLE::<nonce>, or create the canary file the plan's "
                         "canary_file oracle names.")
    repo_path = _repo_path(ctx)
    problems = _skipping_probe_violations(output) + _java_probe_violations(
        output, repo_jvm_test_framework(repo_path), repo_java_release(repo_path))
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
_JUNIT_SKIPS = ("@Disabled", "@Ignore", "assumeTrue", "assumeFalse", "assumingThat",
                "Assumptions.", "assumeThat")
# The protocol names pytest's `collected 0 items` and jest's `No tests found` as zero-test runs
# that are never a negative result, but only the Perl and JUnit idioms that produce them were
# detected. `importorskip` is the one a model actually reaches for when an import might fail --
# which is exactly the environment signal build repair needs to see.
_PYTEST_SKIPS = ("importorskip", "pytest.skip", "mark.skip", "mark.xfail", "@unittest.skip")
# `test.only` is the subtle one: it is not skipping, it silently excludes every *other* test in
# the file, so a probe placed after one never runs and the file still exits 0.
_JEST_SKIPS = ("test.skip", "describe.skip", "it.skip", "test.todo", "xit(", "xdescribe(",
               "test.only", "describe.only", "it.only")


def _is_perl_probe(output: ProbeSource) -> bool:
    return (output.test_file_path.endswith(".t")
            or "Test::More" in output.content or "Test2::" in output.content)


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
        if not any(marker in output.content for marker in _PERL_PLAN):
            problems.append(
                "Add `done_testing();` as the script's last statement (or declare the count up "
                "front with `use Test::More tests => 1;`). With no plan, prove reports a bad "
                "plan and exits nonzero on a probe that printed every marker correctly."
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


# pytest buffers stdout unless told not to, and the oracle markers are stdout. Either of
# these disables that capture.
_PYTEST_UNBUFFERED = ("-s", "--capture=no", "--capture no")
# prove parses its child's TAP stream and throws away everything that is not TAP unless it is
# verbose, so a non-verbose `prove` swallows every marker exactly as an un-`-s`ed pytest does.
# JVM runners select a test by class name rather than by file path.
_CLASS_SELECTORS = ("-Dtest=", "--tests")
# Maven relays the forked test JVM's stdout through its own logger at INFO level, so -q raises
# the threshold above the markers and they never reach the runner's stdout.
_MAVEN_REDIRECT_OFF = ("-Dmaven.test.redirectTestOutputToFile=false",
                       "-DredirectTestOutputToFile=false")
# Maven 3.x binds maven-surefire-plugin **2.12.4** to the `test` phase by default, and 2.12.4
# has no JUnit Platform provider: a JUnit 5 probe is simply never discovered ("No tests were
# executed"). The plugin version bound to a phase cannot be overridden from the command line,
# so the only fix available to an EnvironmentSpec (which may not edit the repo's pom.xml) is to
# compile with `test-compile` and then invoke a pinned surefire goal directly.
_SUREFIRE_PIN = re.compile(r"maven-surefire-plugin:(\d+)[.:]")
# Lifecycle phases that run the pom's own (2.12.4) surefire execution on the way past.
_PHASES_RUNNING_SUREFIRE = frozenset(
    {"test", "integration-test", "verify", "package", "install", "deploy"})
_COMPILES_TESTS = "test-compile"
# Every Maven retry message points the agent at this string, so it must itself satisfy every
# check in this module. It did not: it omitted -Dmaven.repo.local, so an agent that copied it
# verbatim was rejected for a *different* violation than the one it had just fixed. Measured on
# java-sqli-vulnerable, which oscillated between the two and exhausted its output retries into
# `environment_unbuildable`. test_validators.py now asserts the exemplars are clean.
MAVEN_TEST_COMMAND = (
    "mvn -B -o test-compile "
    "org.apache.maven.plugins:maven-surefire-plugin:3.2.5:test "
    "-Dtest=HarnessProbeTest -Dmaven.repo.local=/work/home/.m2/repository "
    "-Dmaven.test.redirectTestOutputToFile=false"
)
# `--rerun-tasks` is the Gradle half of the "a run that executes nothing still exits 0" family.
# Measured on Gradle 8.14.3 / JDK 17: the first `test` run printed all three markers, and running
# the identical command again printed none and exited 0, with `> Task :test UP-TO-DATE` as the only
# difference. `cleanTest test` is the other way to say it.
_GRADLE_UNCONDITIONAL = ("--rerun-tasks", "--rerun")
GRADLE_TEST_COMMAND = ("./gradlew --no-daemon --offline --rerun-tasks -i test "
                       "--tests '*HarnessProbeTest'")
# `cmd || true` makes a failed dependency install invisible: the image builds, the smoke test
# passes, and the absence surfaces at probe time as a compile error inside the probe — past
# build repair, the only stage that could have installed anything.
_SWALLOWED_FAILURE = re.compile(r"\|\|\s*(?:true|:)\s*(?=$|[;&|])|;\s*true\s*$")
# cpanm into a local lib puts the modules somewhere perl does not look by default.
_CPANM_LOCAL_LIB = re.compile(r"cpanm\b.*?(?:\s-[lL]\s|--local-lib(?:-contained)?)")


def _selects_by_class_name(command: str) -> bool:
    return any(sel in command for sel in _CLASS_SELECTORS)


def _is_jvm_runner(command: str) -> bool:
    """A Maven or Gradle command, selector or not.

    Routing on the selector alone misfiled `mvn test` with no `-Dtest=` as a path runner and
    told it to add `{test_file}`, which Maven does not accept — the opposite of the advice it
    needs, which is to name a class.
    """
    return any(token.rsplit("/", 1)[-1].removesuffix(".cmd") in ("mvn", "mvnw", "gradle", "gradlew")
               for token in command.split())


def _short_flag(command: str, letter: str) -> bool:
    """Whether a standalone or clustered short flag carries `letter` (`-v`, `-lv`).

    `-D` properties and `--long` options are skipped: `-Dmaven.test.redirect...` contains an
    `i`, and reading it as `--info` would silently satisfy the check it is unrelated to.
    """
    for token in command.split():
        if not token.startswith("-") or token.startswith(("--", "-D")):
            continue
        if letter in token[1:]:
            return True
    return False


def _long_flag(command: str, *names: str) -> bool:
    tokens = command.split()
    return any(name in tokens for name in names)


def _maven_goals(command: str) -> list[str]:
    """The phases and goals a `mvn` invocation asks for, with flags and properties removed."""
    tokens = command.split()
    start = next((i for i, t in enumerate(tokens)
                  if t.rsplit("/", 1)[-1] in ("mvn", "mvnw", "mvn.cmd", "./mvnw")), None)
    if start is None:
        return []
    return [t for t in tokens[start + 1:] if not t.startswith("-")]


def _install_violations(spec: EnvironmentSpec) -> list[str]:
    """Install steps whose failure, or whose success, the probe run cannot see."""
    problems: list[str] = []
    for command in spec.install_commands:
        if _SWALLOWED_FAILURE.search(command):
            fixed = _SWALLOWED_FAILURE.sub("", command).strip().rstrip(";").strip()
            problems.append(
                f"Drop the failure-swallowing suffix from the install command: use {fixed!r}. "
                "A dependency install that reports success when it failed makes the image build "
                "and the smoke test pass, and the missing module surfaces only at probe time as "
                "a compile error inside the probe (`Can't locate DBI.pm in @INC`), which "
                "probe repair cannot fix and build repair never sees."
            )
        if _CPANM_LOCAL_LIB.search(command) and not (
            "PERL5LIB" in spec.env or "PERL5LIB" in (spec.test_command or "")
            or _short_flag(spec.test_command or "", "I")
        ):
            problems.append(
                "This install puts the modules in a local lib, so set "
                "env.PERL5LIB=/work/home/perl5/lib/perl5 (matching the -l/-L path) or drop the "
                "local lib entirely. Without it prove runs with the stock @INC and the probe "
                "dies on the modules that were just installed."
            )
    return problems


def _jvm_violations(command: str) -> list[str]:
    """Maven and Gradle: the ways a JVM probe runs and reports nothing anyway."""
    problems: list[str] = []
    if "mvn" in command:
        if _short_flag(command, "q") or _long_flag(command, "--quiet"):
            problems.append(
                f"Drop -q and use -B instead: {MAVEN_TEST_COMMAND}. Maven relays the forked "
                "test JVM's stdout through its own logger at INFO level, so -q raises the "
                "threshold above the probe's HARNESS_ markers and a correct probe is recorded "
                "as having reached nothing."
            )
        if not any(flag in command for flag in _MAVEN_REDIRECT_OFF):
            problems.append(
                "Add -Dmaven.test.redirectTestOutputToFile=false. A pom that turns the "
                "redirect on writes the markers to target/surefire-reports/*-output.txt "
                "instead of stdout, and the harness only reads stdout."
            )
        pinned = _SUREFIRE_PIN.search(command)
        if not pinned or int(pinned.group(1)) < 3:
            problems.append(
                f"Pin a JUnit-Platform-capable Surefire and invoke it directly: "
                f"{MAVEN_TEST_COMMAND}. Maven 3.x binds maven-surefire-plugin 2.12.4 to the "
                "`test` phase, which has no JUnit Platform provider, so a JUnit 5 probe is "
                "never discovered and the run fails with 'No tests were executed'. A plugin "
                "version bound to a phase cannot be overridden from the command line."
            )
        goals = _maven_goals(command)
        reached = sorted(_PHASES_RUNNING_SUREFIRE.intersection(goals))
        if reached:
            problems.append(
                f"Remove the `{reached[0]}` phase and keep only test-compile plus the pinned "
                f"goal: {MAVEN_TEST_COMMAND}. Reaching `{reached[0]}` also runs the pom's own "
                "Surefire 2.12.4 execution, which fails the build with 'No tests were executed' "
                "before the pinned goal ever runs."
            )
        elif _COMPILES_TESTS not in goals:
            problems.append(
                f"Compile the probe: the command must run the test-compile phase, as in "
                f"{MAVEN_TEST_COMMAND}. The probe file is written into the container at probe "
                "time, so a command that only invokes a surefire goal runs against the test "
                "classes baked into the image and never sees the probe at all."
            )
    if "gradle" in command:
        if not (_short_flag(command, "i") or _short_flag(command, "d")
                or _long_flag(command, "--info", "--debug")):
            problems.append(
                f"Add -i: {GRADLE_TEST_COMMAND}. Gradle's Test task forwards a test's standard "
                "streams only from the INFO log level up, so at the default level the probe's "
                "HARNESS_ markers are dropped and a correct probe reports nothing."
            )
        if not (_long_flag(command, *_GRADLE_UNCONDITIONAL) or "cleanTest" in command):
            problems.append(
                f"Add --rerun-tasks: {GRADLE_TEST_COMMAND}. Gradle's `test` task is incremental, "
                "so a second run with the same inputs is reported UP-TO-DATE: no test executes, "
                "no marker is printed, and the build still exits 0. Measured on Gradle 8.14.3 — "
                "the first run printed all three markers and the next two printed none, with "
                "`> Task :test UP-TO-DATE` as the only difference. Maven has no equivalent, so "
                "this is a Gradle-only flag and the reason it is not optional is that the failure "
                "is silent."
            )
    return problems


def _has_class_selector_value(command: str) -> bool:
    """The selector must actually name something, not sit empty."""
    for sel in _CLASS_SELECTORS:
        _, found, rest = command.partition(sel)
        if found and rest.lstrip(" =\"'").strip():
            return True
    return False


def _class_selector_value(command: str) -> str:
    """The raw text a JVM selector was given, unquoted. Empty when there is no selector."""
    for sel in _CLASS_SELECTORS:
        _, found, rest = command.partition(sel)
        if found:
            value = rest.lstrip(" =")
            if value[:1] in ("'", '"'):
                quote = value[0]
                value = value[1:].partition(quote)[0]
            else:
                value = value.split()[0] if value.split() else ""
            return value.strip()
    return ""


# Surefire and Gradle select by *class*, so a selector handed a file path matches nothing. The
# run then exits having executed no test -- Surefire says `No tests matching pattern "<path>"
# were executed!` -- which looks like a probe defect and is not one. Measured on
# java-sqli-fixed: the planner wrote `-Dtest={test_file}`, the harness substituted
# `src/test/java/com/example/UserDaoTest.java`, and the case burned its whole repair budget to
# `inconclusive`. `{test_file}` is the giveaway, but a hardcoded path fails identically.
_PATHISH_SELECTOR = re.compile(r"[/\\]|\.(?:java|kt|kts|groovy|scala)\b|\{test_file\}")


def _pathish_selector_violation(command: str) -> str | None:
    """Reject a JVM selector given a path rather than a class name, naming the correction."""
    value = _class_selector_value(command)
    if not value or not _PATHISH_SELECTOR.search(value):
        return None
    stem = value.replace("\\", "/").rstrip("/").rpartition("/")[2]
    for suffix in (".java", ".kt", ".kts", ".groovy", ".scala"):
        stem = stem.removesuffix(suffix)
    named = stem if stem and "{" not in stem else "HarnessProbeTest"
    hint = (f"-Dtest={named}" if "-Dtest=" in command else f"--tests '*{named}'")
    return (
        f"the test selector was given {value!r}, which is a file path, not a class name. Write "
        f"{hint} instead. Surefire and Gradle match selectors against class names, so a path "
        f"matches nothing and the run executes zero tests -- Surefire reports "
        f"`No tests matching pattern \"{value}\" were executed!`. Do not use {{test_file}} in a "
        f"JVM selector: the harness substitutes the probe's path there, which is exactly the "
        f"value that matches nothing. The coupling is by name -- the probe's test class must be "
        f"the one the selector names."
    )


# --- JDK / language-level compatibility -----------------------------------------------------
#
# Vul4J's 79 reproducible Java vulnerabilities span projects targeting Java 7 through 16, so a
# single pinned base image cannot build the corpus. Both directions of mismatch fail, and both
# fail in ways build repair cannot reason its way out of, so they are caught at plan time.
#
# Floors come from JEP 182's "one plus three back" retirement policy. Only the two removals that
# actually shipped are encoded; an unknown JDK gets no floor rather than a guessed one, because
# a wrong floor would reject a spec that builds.
_JAVAC_SOURCE_FLOOR = (
    (20, 8),   # JDK 20 removed -source/-target 7: "Source option 7 is no longer supported."
    (12, 7),   # JDK 12 removed 6 (deprecated in 11).
    (11, 6),   # JDK 11 removed 5: "Source option 5 is no longer supported. Use 6 or later."
)
# Each floor above was executed rather than read off JEP 182: javac from Zulu 8/11/17/21 was
# asked for -source 1.5/1.6/1.7/1.8 under Maven 3.9.16. JDK 8 accepted all four; JDK 11 rejected
# 5; JDK 17 rejected 6; JDK 21 rejected 7. The 11-floor was missing, and three poms in the
# harvested Vul4J corpus declare `<source>1.5</source>` -- so a spec pinning temurin-11 for them
# was accepted here and then died in the image build on a message this check exists to predict.
# The oldest JDK the allowlisted images offer is 8, so that is the floor of the advice as well.
# The JDKs the official `maven:3.9-eclipse-temurin-*` line actually publishes, confirmed
# against the registry tag list rather than assumed: 8, 11, 17 and 21 all exist (as do 19,
# 20 and 22+), so every image this module names can be pulled. 9, 10 and 12-16 do not.
_MAVEN_IMAGE_JDKS = (8, 11, 17, 21)


def _javac_floor(jdk: int) -> int | None:
    """The oldest -source level ``jdk``'s javac still accepts, or None when it accepts any."""
    return next((floor for threshold, floor in _JAVAC_SOURCE_FLOOR if jdk >= threshold), None)


# The default JDK, and the ceiling on what this function recommends for old code. 21 compiles
# source 8 perfectly well (measured), so the cap is not a compatibility floor -- it keeps this
# function's answer identical to the table skills/build-maven publishes, and it keeps 2017-era
# projects on the LTS they are most likely to have been built under. A project that declares 21
# still gets 21, because `declared_release` overrides the cap below.
_PREFERRED_IMAGE_JDK = 17


def maven_image_for_release(declared_release: int) -> str:
    """An allowlisted Maven image whose JDK still compiles ``declared_release``.

    Naming temurin-11 unconditionally was wrong for the levels JDK 11 itself removed: the
    message told the planner to pin the very image that fails with the error being reported.
    """
    usable = [jdk for jdk in _MAVEN_IMAGE_JDKS
              if jdk >= declared_release and (_javac_floor(jdk) or 0) <= declared_release]
    if not usable:
        return f"maven:3.9-eclipse-temurin-{max(_MAVEN_IMAGE_JDKS)}"
    capped = [jdk for jdk in usable if jdk <= _PREFERRED_IMAGE_JDK]
    return f"maven:3.9-eclipse-temurin-{max(capped) if capped else min(usable)}"
_IMAGE_JDK_PATTERNS = (
    re.compile(r"-jdk[-]?(\d+)"),              # gradle:8-jdk21, eclipse-temurin:17-jdk
    re.compile(r"eclipse-temurin[:-](\d+)"),   # maven:3.9-eclipse-temurin-17
    re.compile(r"\bopenjdk[:-](\d+)"),         # openjdk:11
    re.compile(r"\bamazoncorretto[:-](\d+)"),
)
def image_jdk_major(base_image: str) -> int | None:
    """The JDK major version a base image provides, or None when it cannot be read."""
    for pattern in _IMAGE_JDK_PATTERNS:
        match = pattern.search(base_image)
        if match:
            return int(match.group(1))
    return None


def jdk_compatibility_violations(base_image: str, declared_release: int | None) -> list[str]:
    """Reject a base image that cannot compile the language level the repo asks for.

    Both directions are hard failures with fixed messages that build repair cannot argue with,
    so naming the right image here saves the whole repair loop.
    """
    jdk = image_jdk_major(base_image)
    if jdk is None or declared_release is None:
        return []
    if declared_release > jdk:
        return [
            f"base_image {base_image!r} provides JDK {jdk}, but the project declares Java "
            f"{declared_release}. javac fails with 'invalid target release: {declared_release}'. "
            f"Use an image providing JDK {declared_release} or newer, e.g. "
            f"'maven:3.9-eclipse-temurin-{declared_release}'."
        ]
    floor = _javac_floor(jdk)
    if floor is not None and declared_release < floor:
        return [
            f"base_image {base_image!r} provides JDK {jdk}, which no longer accepts "
            f"-source/-target {declared_release}: javac fails with 'Source option "
            f"{declared_release} is no longer supported. Use {floor} or later.' The project "
            f"declares Java {declared_release}, so pin an older JDK -- "
            f"{maven_image_for_release(declared_release)!r} still compiles Java "
            f"{declared_release} -- rather than editing the project's compiler level, which "
            "changes what is being tested."
        ]
    return []


def environment_spec_violations(spec: EnvironmentSpec) -> list[str]:
    """Deterministic requirements on a test command. Pure, so evals and tests can check it.

    Both of these were produced by a live model and both silently destroyed a run, because
    neither the probe nor the diagnosis can see the cause: the probe looks correct, exits
    cleanly, and reports nothing.
    """
    problems: list[str] = _install_violations(spec)
    command = spec.test_command or ""
    if _selects_by_class_name(command) or _is_jvm_runner(command):
        # Maven and Gradle select tests by *class*, not by path: `-Dtest=HarnessProbeTest`,
        # `--tests '*HarnessProbeTest'`. Substituting a file path there matches nothing, so
        # these commands legitimately carry no {test_file} — the coupling is that the probe's
        # class name must be the one the selector names, which is the author's job and what
        # the test-junit5 skill specifies.
        if not _has_class_selector_value(command):
            problems.append(
                "a JVM test command must name the probe's test class in its selector, e.g. "
                "'mvn -q -B -o test -Dtest=HarnessProbeTest' or "
                "\"./gradlew --offline test --tests '*HarnessProbeTest'\"."
            )
        elif (pathish := _pathish_selector_violation(command)):
            problems.append(pathish)
        return problems + _jvm_violations(command)
    if "{test_file}" not in command:
        # The harness writes the probe to the path the author chose and substitutes it here.
        # A hardcoded path means the probe file that was actually written is never run: pytest
        # reports "file or directory not found" and exits 4, having executed no test.
        problems.append(
            "test_command must contain the literal placeholder {test_file}; the harness "
            "substitutes the probe's real path into it. Replace the hardcoded test path with "
            "{test_file}, e.g. 'python -m pytest -q -s {test_file}'."
        )
    if "pytest" in command and not any(flag in command for flag in _PYTEST_UNBUFFERED):
        # Without this the probe runs, passes, and prints its markers into pytest's capture
        # buffer, so the harness sees precondition_reached=false on a probe that was correct.
        problems.append(
            "a pytest test_command must disable output capture with -s (or --capture=no), "
            "otherwise the probe's HARNESS_ markers never reach the runner and a correct "
            "probe is recorded as having reached nothing."
        )
    if "prove" in command and not (
        _short_flag(command, "v") or _long_flag(command, "--verbose")
    ):
        # prove is a TAP consumer: it parses the child's stream and reports the plan, and
        # everything that is not TAP — which is every HARNESS_ marker — is discarded unless it
        # is verbose. Same failure as an un-`-s`ed pytest, and just as invisible downstream.
        problems.append(
            "a prove test_command must be verbose: 'prove -v {test_file}'. prove discards "
            "non-TAP output from the test it runs, so without -v the probe's HARNESS_ markers "
            "never reach the runner and a correct probe is recorded as having reached nothing."
        )
    return problems


# The image is built with HOME=/opt/home; run_probe then copies /opt/home to a writable
# /work/home tmpfs and runs the test from there. So an install writes under /opt and anything
# resolved at probe time reads from /work. Getting that backwards fails in two different
# directions, and one of them is silent.
BUILD_HOME = "/opt/home"
RUNTIME_HOME = "/work/home"


def install_path_violations(spec: EnvironmentSpec) -> list[str]:
    """Install commands must write where they can, and env must point where things end up."""
    problems: list[str] = []
    installs = " ".join(spec.install_commands or [])
    if RUNTIME_HOME in installs or "/work/" in installs:
        problems.append(
            f"an install command writes under /work, which does not exist at build time: the "
            f"probe tmpfs is mounted later. Install under {BUILD_HOME} and point the matching "
            f"environment variable at {RUNTIME_HOME}, which is where it is copied."
        )
    # cpanm as the non-root sandbox user cannot write perl's site dir. It warns, "succeeds",
    # and installs nowhere on @INC -- so the build exits 0 with the dependency absent and the
    # failure only appears inside the probe as "Can't locate X.pm". Verified against the corpus.
    if "cpanm" in installs and not any(f in installs for f in ("--local-lib", " -l ", " -L ")):
        problems.append(
            "a cpanm install must use --local-lib, e.g. "
            f"'cpanm --notest --local-lib={BUILD_HOME}/perl5 --installdeps .' with "
            f"env PERL5LIB={RUNTIME_HOME}/perl5/lib/perl5. Without it cpanm cannot write perl's "
            "site directory as the non-root sandbox user: it reports success, installs nothing "
            "importable, and the build goes green with the dependency missing."
        )
    # Maven resolves its local repository from the JVM's user.home. The sandbox user has no
    # passwd entry, so that is /root, and the build dies with
    # "mkdir: cannot create directory '/root': Permission denied". Verified against the corpus.
    if "mvn" in installs and "-Dmaven.repo.local=" not in installs:
        problems.append(
            f"a Maven install must set -Dmaven.repo.local={BUILD_HOME}/.m2/repository. Maven "
            "takes its local repository from the JVM's user.home, which is /root for the "
            "sandbox user's unmapped uid, so the build fails with \"cannot create directory "
            "'/root'\" before it resolves anything."
        )
    command = spec.test_command or ""
    if "mvn" in command and "-Dmaven.repo.local=" not in command:
        problems.append(
            f"a Maven test command must set -Dmaven.repo.local={RUNTIME_HOME}/.m2/repository — "
            f"the repository populated under {BUILD_HOME} at build time is copied there for the "
            "probe, and without the flag Maven looks in /root and cannot write it."
        )
    if "--local-lib" in installs or "cpanm" in installs:
        perl5lib = (spec.env or {}).get("PERL5LIB", "")
        if not perl5lib:
            problems.append(
                f"a cpanm install needs env PERL5LIB={RUNTIME_HOME}/perl5/lib/perl5 so the probe "
                "can find what was installed; without it prove fails with 'Can't locate X.pm'."
            )
        elif not perl5lib.startswith(RUNTIME_HOME):
            problems.append(
                f"env PERL5LIB is {perl5lib!r}, but at probe time the local-lib lives under "
                f"{RUNTIME_HOME}. Point it at {RUNTIME_HOME}/perl5/lib/perl5."
            )
    return problems


# The warm-up that populates the local repository has to *execute a test*, because Surefire
# resolves its provider lazily -- at test-execution time, from the JUnit version it finds on the
# test classpath -- and not during dependency resolution. Two flags turn "no test ran" into a
# success, and they are exactly what makes a warm-up a silent no-op.
_WARMUP_NO_OPS = ("-DfailIfNoTests=false", "-Dsurefire.failIfNoTests=false",
                  "-DfailIfNoSpecifiedTests=false", "-Dsurefire.failIfNoSpecifiedTests=false")
# A throwaway test, written and removed inside one install step, so the warm-up has something to
# run in a project whose test tree is empty. One line of Java on purpose: render_dockerfile emits
# each install command as a single `RUN`, so a heredoc would not survive.
#
# **The throwaway test has to be written in the project's own framework.** The warm-up used to be
# JUnit 5 unconditionally, and that is not a detail: in a JUnit-4 project the `test-compile` in
# this very command fails with
#   HarnessWarmupTest.java:[1,63] cannot find symbol / symbol: class Test
# so the image never builds at all. Executed against three real corpus repositories (zt-zip,
# commons-imaging, commons-fileupload at their harvested revisions) and against minimal fixtures:
# the JUnit 5 warm-up fails the build on every one of them, and the matching-framework warm-up
# then makes the offline probe pass with all three markers. The corpus is 50 JUnit-4 Maven
# entries to 1 JUnit 5, so the old default was wrong for essentially the whole of it.
def _warmup(import_line: str, declaration: str) -> str:
    return (
        f"mkdir -p src/test/java && echo '{import_line} {declaration}' > "
        "src/test/java/HarnessWarmupTest.java && "
        f"mvn -B -Dmaven.repo.local={BUILD_HOME}/.m2/repository test-compile "
        "org.apache.maven.plugins:maven-surefire-plugin:3.2.5:test -Dtest=HarnessWarmupTest && "
        "rm -f src/test/java/HarnessWarmupTest.java target/test-classes/HarnessWarmupTest.class"
    )


MAVEN_WARMUP_COMMANDS: dict[str, str] = {
    # JUnit 4 wants a *public* class and a *public* method: with either left package-private the
    # JUnit4Provider reports `initializationError` and prints no markers (measured).
    "junit4": _warmup("import org.junit.Test;",
                      "public class HarnessWarmupTest { @Test public void warm() {} }"),
    "junit5": _warmup("import org.junit.jupiter.api.Test;",
                      "class HarnessWarmupTest { @Test void warm() {} }"),
    "testng": _warmup("import org.testng.annotations.Test;",
                      "public class HarnessWarmupTest { @Test public void warm() {} }"),
}
# Kept under its original name because every existing Maven retry message and test names it.
MAVEN_WARMUP_COMMAND = MAVEN_WARMUP_COMMANDS["junit5"]
# What each framework's warm-up (and probe) must import, and what it must not. Order matters:
# `org.junit.jupiter` also contains `org.junit`, so jupiter is tested first.
_FRAMEWORK_IMPORTS: dict[str, str] = {
    "junit5": "org.junit.jupiter.api.Test",
    "junit4": "org.junit.Test",
    "testng": "org.testng.annotations.Test",
}


def warmup_framework(command: str) -> str | None:
    """Which framework a warm-up command's throwaway test is written in, if it can be read."""
    if "org.junit.jupiter" in command:
        return "junit5"
    if "org.testng" in command:
        return "testng"
    if "org.junit" in command or "junit.framework.TestCase" in command:
        return "junit4"
    return None


def _warms_the_surefire_provider(install_commands: list[str]) -> bool:
    """Whether some install step really runs a test under a JUnit-Platform-capable Surefire.

    Invoking the pinned plugin with nothing to run is not enough, which is the whole point: it
    downloads the plugin and every one of its own dependencies and stops there.
    """
    for command in install_commands or ():
        pinned = _SUREFIRE_PIN.search(command)
        if not pinned or int(pinned.group(1)) < 3 or ":test" not in command:
            continue
        if not _has_class_selector_value(command):
            continue
        if any(flag in command for flag in _WARMUP_NO_OPS):
            continue
        return True
    return False


def offline_warmup_violations(spec: EnvironmentSpec, framework: str | None = None) -> list[str]:
    """A Maven probe runs with no network, so the build must have fetched *everything* first.

    Sibling of ``install_path_violations``: same two-phase layout, but about what is in the
    local repository rather than where it lives. Verified against the Java corpus, where the
    naive warm-up (`surefire:3.2.5:test -DfailIfNoTests=false`, with an empty test tree) left
    the offline probe dying on `surefire-junit-platform:jar:3.2.5 ... has not been downloaded
    from it before` — a build that exits 0 and a probe that reports nothing, which is the
    failure shape neither probe repair nor build repair can see the cause of.

    ``framework`` is the repository's own test framework, when it is known. The warm-up's
    throwaway test is compiled against the project's test classpath, so a warm-up written in the
    wrong framework does not compile and the image never builds — and the provider Surefire
    fetches is the one the *project's* classpath selects (surefire-junit4, surefire-testng,
    surefire-junit-platform), so the absent-artifact message differs per framework too.
    """
    problems: list[str] = []
    command = spec.test_command or ""
    if "mvn" not in command:
        return problems
    wanted = MAVEN_WARMUP_COMMANDS.get(framework or "", MAVEN_WARMUP_COMMAND)
    provider = {"junit4": "surefire-junit4", "testng": "surefire-testng"}.get(
        framework or "", "surefire-junit-platform")
    if not _warms_the_surefire_provider(spec.install_commands):
        problems.append(
            f"the build must warm Surefire's {provider} provider by *running* a test, not by "
            f"invoking the plugin with nothing to run: add the install command {wanted!r}. "
            "Surefire resolves its provider lazily at test-execution time, from the test "
            "framework on the test classpath, so a warm-up with an empty test tree (or with "
            "-DfailIfNoTests=false, which makes 'no tests ran' a success) fetches the plugin and "
            f"all of its own dependencies and never the provider. The offline probe then fails "
            f"with \"{provider}:jar:3.2.5 (absent) ... has not been downloaded from "
            "it before\". Pinning the provider with dependency:get does not fix it either: the "
            "next missing artifact is junit-platform-launcher, whose version Surefire derives "
            "from the project's own JUnit and which no fixed artifact list can predict."
        )
    elif framework in _FRAMEWORK_IMPORTS:
        # The warm-up runs a test, but in which framework? A JUnit 5 warm-up in a JUnit 4
        # project fails `test-compile` with "cannot find symbol: class Test" and the image is
        # never built; the reverse fails identically. Measured on zt-zip, commons-imaging and
        # commons-fileupload at their harvested revisions.
        for install in spec.install_commands or ():
            if not (_SUREFIRE_PIN.search(install) and ":test" in install):
                continue
            written = warmup_framework(install)
            if written and written != framework:
                problems.append(
                    f"the warm-up's throwaway test is written in {written}, but this project's "
                    f"test framework is {framework}: use {wanted!r}. The warm-up is compiled "
                    f"against the project's own test classpath, so its test must import "
                    f"{_FRAMEWORK_IMPORTS[framework]} — otherwise test-compile fails with "
                    f"\"cannot find symbol: class Test\" and the image never builds, which is a "
                    f"build failure in the *harness's* command rather than in the repository."
                )
                break
    return problems


# Build files whose declared language level binds the choice of JDK. Read at most a few, from
# the repo root and one level down, because a multi-module project's root pom usually carries
# the compiler properties and walking a whole tree here would be slow and rarely add anything.
_JAVA_BUILD_FILES = ("pom.xml", "build.gradle", "build.gradle.kts")


def repo_java_release(repo_path: str | None) -> int | None:
    """The oldest Java language level the repository's build files ask for.

    None when there is no repo, no Java build file, or nothing declared -- in which case the
    JDK check stays silent rather than guessing.
    """
    if not repo_path:
        return None
    root = Path(repo_path)
    if not root.is_dir():
        return None
    candidates = [root / name for name in _JAVA_BUILD_FILES]
    candidates += [child / name for child in sorted(root.iterdir())[:40]
                   if child.is_dir() for name in _JAVA_BUILD_FILES]
    declared = []
    for path in candidates:
        try:
            if path.is_file():
                found = declared_java_release(path.read_text(errors="replace"))
                if found is not None:
                    declared.append(found)
        except OSError:
            continue
    return min(declared) if declared else None


def _java_build_texts(repo_path: str | None) -> list[str]:
    """The repository's own build files, root and one level down. Same reach as the JDK check."""
    if not repo_path:
        return []
    root = Path(repo_path)
    if not root.is_dir():
        return []
    candidates = [root / name for name in _JAVA_BUILD_FILES]
    with contextlib.suppress(OSError):
        candidates += [child / name for child in sorted(root.iterdir())[:40]
                       if child.is_dir() for name in _JAVA_BUILD_FILES]
    texts = []
    for path in candidates:
        try:
            if path.is_file():
                texts.append(path.read_text(errors="replace"))
        except OSError:
            continue
    return texts


def repo_jvm_test_framework(repo_path: str | None) -> str | None:
    """The repository's JVM test framework: junit5, junit4, testng, or None when unreadable.

    The warm-up command and the probe's own shape both depend on this, and getting it from the
    repository is the only honest way: the harness's previous assumption (always JUnit 5) is
    wrong for 50 of the 51 Maven entries in the harvested Vul4J corpus.
    """
    for text in _java_build_texts(repo_path):
        framework = jvm_test_framework(text)
        if framework:
            return framework
    return None


# Two Surefire settings a repository can put in its *plugin-level* `<configuration>` that the
# corresponding `-D` flag cannot undo, because an explicit plugin configuration beats a
# parameter's default-value user property. Both were executed under Surefire 3.2.5, and neither
# is a violation here, because neither has a fix an EnvironmentSpec could name:
#
#   <redirectTestOutputToFile>true</redirectTestOutputToFile>
#       the probe runs and passes, `-Dmaven.test.redirectTestOutputToFile=false` is ignored, and
#       every marker goes to target/surefire-reports/<class>-output.txt. Exit 0, no markers.
#       Handled in run_probe, which now reads those files back onto stdout.
#   <skipTests>true</skipTests>
#       the probe is never run, `-DskipTests=false` is ignored, and no reports are written.
#       Exit 0, no markers. `no_tests_executed` names Surefire's "Tests are skipped." so the
#       diagnosis says what happened instead of sending repair after a correct probe.
#
# The same settings inside an `<executions><execution>` block do *not* apply to a direct CLI goal
# invocation (measured), and as a pom `<properties>` entry they *are* overridable from the command
# line (measured: `-DskipTests=false` restored the markers), so only the plugin-level and
# pluginManagement-level forms behave this way.


def validate_environment_spec(ctx: RunContext[AgentDeps], output: EnvironmentSpec) -> EnvironmentSpec:
    repo_path = _repo_path(ctx)
    problems = (environment_spec_violations(output) + install_path_violations(output)
                # Repo-aware, unlike the two above: the binding constraints are what the project
                # declares -- its test framework and its language level -- which no amount of
                # inspecting the spec alone can reveal.
                + offline_warmup_violations(output, repo_jvm_test_framework(repo_path))
                + jdk_compatibility_violations(
                    output.base_image, repo_java_release(repo_path)))
    if problems:
        raise ModelRetry("The environment spec cannot run a probe:\n- " + "\n- ".join(problems))
    return output


OUTPUT_VALIDATORS: dict[str, tuple[Callable[[RunContext[AgentDeps], Any], Any], ...]] = {
    "verdict": (validate_verdict,),
    "probe-author": (validate_probe,),
    "probe-repair": (validate_probe,),
    "env-planner": (validate_environment_spec,),
    "build-repair": (validate_environment_spec,),
    "partial-build": (validate_environment_spec,),
}
