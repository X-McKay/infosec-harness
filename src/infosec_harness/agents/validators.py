"""Output validators: deterministic contracts an agent's output must satisfy (§5.3).

A violated contract raises ``ModelRetry`` with the reason, so the model gets a chance to
correct itself within its ``retries.output`` budget.
"""

from __future__ import annotations

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
from infosec_harness.repo.detect import js_test_runners


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


def validate_verdict(ctx: RunContext[AgentDeps], output: Verdict) -> Verdict:
    facts = ctx.deps.facts
    if facts is None:
        return output
    problems = verdict_violations(output, facts)
    if problems:
        raise ModelRetry("Verdict violates the evidence contract:\n- " + "\n- ".join(problems))
    return output


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
    problems = _skipping_probe_violations(output)
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
_PERL_PLAN_PATTERNS = (re.compile(r"^\s*plan\s*\(?\s*\d+", re.M),
                       re.compile(r"1\.\.\d+"))


def _declares_a_perl_plan(content: str) -> bool:
    return (any(marker in content for marker in _PERL_PLAN)
            or any(pattern.search(content) for pattern in _PERL_PLAN_PATTERNS))
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
GRADLE_TEST_COMMAND = "./gradlew --no-daemon --offline -i test --tests '*HarnessProbeTest'"
# The two Node runners that intercept a test's console. Measured on real fixtures under node 22:
# a repository `jest.config.js` or `vitest.config.js` carrying `silent: true` -- an ordinary thing
# for a project with chatty tests to do -- replaces the test's console, so ALL THREE markers
# vanish while the run still exits 0. `--silent=false` on the command line overrides it, and is a
# no-op when nothing was silencing anything. mocha and node:test never capture stdout.
JEST_TEST_COMMAND = "npx jest --silent=false --runTestsByPath {test_file}"
VITEST_TEST_COMMAND = "npx vitest run --silent=false {test_file}"
_JS_CAPTURING_RUNNERS = {"jest": JEST_TEST_COMMAND, "vitest": VITEST_TEST_COMMAND}
_JS_SILENT_OFF = "--silent=false"
# `--runTestsByPath` is jest's. vitest takes a bare path and dies in its own argument parser on
# this flag, before loading a single test file, so the pairing costs the run with no test output
# to diagnose from.
_JEST_ONLY_SELECTOR = "--runTestsByPath"
# `cmd || true` makes a failed dependency install invisible: the image builds, the smoke test
# passes, and the absence surfaces at probe time as a compile error inside the probe — past
# build repair, the only stage that could have installed anything.
_SWALLOWED_FAILURE = re.compile(r"\|\|\s*(?:true|:)\s*(?=$|[;&|])|;\s*true\s*$")
# cpanm into a local lib puts the modules somewhere perl does not look by default.
_CPANM_LOCAL_LIB = re.compile(r"cpanm\b.*?(?:\s-[lL]\s|--local-lib(?:-contained)?)")


def _js_runner(command: str) -> str | None:
    """Which Node test runner a command invokes, or None. vitest before jest: a command may
    legitimately mention both (`npx vitest run` in a repo whose config file is named jest.*),
    and the runner is the executable, which is the first of the two to appear as a bare token."""
    tokens = [t.rsplit("/", 1)[-1] for t in command.split() if not t.startswith("-")]
    for token in tokens:
        for runner in ("vitest", "jest", "mocha", "jasmine"):
            if token == runner:
                return runner
    return None


def _js_runner_violations(command: str) -> list[str]:
    """Node runners: the ways a JS probe runs and its markers never reach the harness."""
    runner = _js_runner(command)
    if runner is None:
        return []
    problems: list[str] = []
    if runner == "vitest" and _JEST_ONLY_SELECTOR in command:
        problems.append(
            f"Drop {_JEST_ONLY_SELECTOR} and pass the path on its own: {VITEST_TEST_COMMAND}. "
            f"{_JEST_ONLY_SELECTOR} is a jest flag; vitest rejects it in its own argument parser "
            "and exits before loading a single test file, so the run produces no test output at "
            "all and the probe is recorded as having reached nothing."
        )
    if runner in _JS_CAPTURING_RUNNERS and _JS_SILENT_OFF not in command:
        problems.append(
            f"Add {_JS_SILENT_OFF}: {_JS_CAPTURING_RUNNERS[runner]}. A repository "
            f"{runner}.config.js that sets `silent: true` replaces the test's console, so all "
            "three HARNESS_ markers disappear while the run still exits 0 — a correct probe "
            "recorded as having reached nothing, with nothing in the output to say why. The flag "
            "overrides the config and is a no-op when the project silences nothing."
        )
    return problems


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
    if "gradle" in command and not (
        _short_flag(command, "i") or _short_flag(command, "d")
        or _long_flag(command, "--info", "--debug")
    ):
        problems.append(
            f"Add -i: {GRADLE_TEST_COMMAND}. Gradle's Test task forwards a test's standard "
            "streams only from the INFO log level up, so at the default level the probe's "
            "HARNESS_ markers are dropped and a correct probe reports nothing."
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
)
_IMAGE_JDK_PATTERNS = (
    re.compile(r"-jdk[-]?(\d+)"),              # gradle:8-jdk21, eclipse-temurin:17-jdk
    re.compile(r"eclipse-temurin[:-](\d+)"),   # maven:3.9-eclipse-temurin-17
    re.compile(r"\bopenjdk[:-](\d+)"),         # openjdk:11
    re.compile(r"\bamazoncorretto[:-](\d+)"),
)
# `maven:3.9-...` and `gradle:8-...` lead with the BUILD TOOL's version, so a naive "first
# number" read picks 3 or 8 and silently validates against the wrong JDK.
_JAVA_RELEASE_TAGS = (
    re.compile(r"<maven\.compiler\.release>\s*(\d+)\s*</maven\.compiler\.release>"),
    re.compile(r"<maven\.compiler\.source>\s*(?:1\.)?(\d+)\s*</maven\.compiler\.source>"),
    re.compile(r"<maven\.compiler\.target>\s*(?:1\.)?(\d+)\s*</maven\.compiler\.target>"),
    re.compile(r"<java\.version>\s*(?:1\.)?(\d+)\s*</java\.version>"),
    re.compile(r"<source>\s*(?:1\.)?(\d+)\s*</source>"),
    re.compile(r"<target>\s*(?:1\.)?(\d+)\s*</target>"),
)
_GRADLE_RELEASE_TAGS = (
    re.compile(r"sourceCompatibility\s*=?\s*['\"]?(?:1\.)?(\d+)"),
    re.compile(r"targetCompatibility\s*=?\s*['\"]?(?:1\.)?(\d+)"),
    re.compile(r"languageVersion\s*=\s*JavaLanguageVersion\.of\((\d+)\)"),
)


def image_jdk_major(base_image: str) -> int | None:
    """The JDK major version a base image provides, or None when it cannot be read."""
    for pattern in _IMAGE_JDK_PATTERNS:
        match = pattern.search(base_image)
        if match:
            return int(match.group(1))
    return None


def declared_java_release(build_file_text: str) -> int | None:
    """The oldest language level a build file asks for, or None if it says nothing.

    The *oldest* rather than the newest: a pom setting source 7 and target 8 has to be compiled
    by a JDK that still accepts 7, so the lower number is the binding constraint.
    """
    found = [int(m.group(1))
             for pattern in _JAVA_RELEASE_TAGS + _GRADLE_RELEASE_TAGS
             for m in pattern.finditer(build_file_text)]
    return min(found) if found else None


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
    floor = next((f for threshold, f in _JAVAC_SOURCE_FLOOR if jdk >= threshold), None)
    if floor is not None and declared_release < floor:
        return [
            f"base_image {base_image!r} provides JDK {jdk}, which no longer accepts "
            f"-source/-target {declared_release}: javac fails with 'Source option "
            f"{declared_release} is no longer supported. Use {floor} or later.' The project "
            f"declares Java {declared_release}, so pin an older JDK -- "
            f"'maven:3.9-eclipse-temurin-11' builds Java {declared_release} -- rather than "
            f"editing the project's compiler level, which changes what is being tested."
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
    problems += _js_runner_violations(command)
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
# A throwaway JUnit 5 test, written and removed inside one install step, so the warm-up has
# something to run in a project whose test tree is empty. One line of Java on purpose:
# render_dockerfile emits each install command as a single `RUN`, so a heredoc would not survive.
MAVEN_WARMUP_COMMAND = (
    "mkdir -p src/test/java && echo 'import org.junit.jupiter.api.Test; class HarnessWarmupTest "
    "{ @Test void warm() {} }' > src/test/java/HarnessWarmupTest.java && "
    f"mvn -B -Dmaven.repo.local={BUILD_HOME}/.m2/repository test-compile "
    "org.apache.maven.plugins:maven-surefire-plugin:3.2.5:test -Dtest=HarnessWarmupTest && "
    "rm -f src/test/java/HarnessWarmupTest.java target/test-classes/HarnessWarmupTest.class"
)


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


def offline_warmup_violations(spec: EnvironmentSpec) -> list[str]:
    """A Maven probe runs with no network, so the build must have fetched *everything* first.

    Sibling of ``install_path_violations``: same two-phase layout, but about what is in the
    local repository rather than where it lives. Verified against the Java corpus, where the
    naive warm-up (`surefire:3.2.5:test -DfailIfNoTests=false`, with an empty test tree) left
    the offline probe dying on `surefire-junit-platform:jar:3.2.5 ... has not been downloaded
    from it before` — a build that exits 0 and a probe that reports nothing, which is the
    failure shape neither probe repair nor build repair can see the cause of.
    """
    problems: list[str] = []
    command = spec.test_command or ""
    if "mvn" not in command:
        return problems
    if not _warms_the_surefire_provider(spec.install_commands):
        problems.append(
            "the build must warm Surefire's JUnit Platform provider by *running* a test, not by "
            f"invoking the plugin with nothing to run: add the install command {MAVEN_WARMUP_COMMAND!r}. "
            "Surefire resolves its provider lazily at test-execution time, from the JUnit "
            "version on the test classpath, so a warm-up with an empty test tree (or with "
            "-DfailIfNoTests=false, which makes 'no tests ran' a success) fetches the plugin and "
            "all of its own dependencies and never the provider. The offline probe then fails "
            "with \"surefire-junit-platform:jar:3.2.5 (absent) ... has not been downloaded from "
            "it before\". Pinning the provider with dependency:get does not fix it either: the "
            "next missing artifact is junit-platform-launcher, whose version Surefire derives "
            "from the project's own JUnit and which no fixed artifact list can predict."
        )
    return problems


# Build files whose declared language level binds the choice of JDK. Read at most a few, from
# the repo root and one level down, because a multi-module project's root pom usually carries
# the compiler properties and walking a whole tree here would be slow and rarely add anything.
_JAVA_BUILD_FILES = ("pom.xml", "build.gradle", "build.gradle.kts")


def js_runner_choice_violations(test_command: str, declared: list[str]) -> list[str]:
    """Reject a Node runner the repository does not have. Pure, so tests can check it.

    The probe container has no network, and `npx <runner>` for a runner that is not installed
    does not fall back to anything: measured on a vitest-only fixture, `npx --no-install jest
    --runTestsByPath probe.test.js` exits 1 with `npx canceled due to missing packages` and no
    test output whatsoever — a failure that looks like a probe defect, routes to probe repair,
    and cannot be fixed there. A repository mid-migration carries both runners, which is why the
    *first* declared one (the one its own `test` script invokes) is the one to name.
    """
    runner = _js_runner(test_command)
    if runner is None or not declared or runner in declared:
        return []
    wanted = declared[0]
    exemplar = _JS_CAPTURING_RUNNERS.get(wanted)
    hint = (f" Use {exemplar}" if exemplar else
            f" Invoke {wanted} instead") + ", and match the selector to it."
    return [
        f"test_command invokes {runner}, which this repository does not declare; its package.json "
        f"declares {', '.join(declared)} and its own `test` script runs {wanted}.{hint} "
        f"`npx {runner}` cannot install a missing runner in an offline probe container — it exits "
        f"with `npx canceled due to missing packages` and no test output at all, which reads as a "
        f"probe defect and sends repair to the one stage that cannot fix it."
    ]


def repo_js_runners(repo_path: str | None) -> list[str]:
    """The Node test runners the repository declares, its own `test` script's choice first.

    Empty when there is no repo or no package.json, in which case the runner check stays silent
    rather than guessing — the same discipline as ``repo_java_release``.
    """
    if not repo_path:
        return []
    root = Path(repo_path)
    if not root.is_dir():
        return []
    try:
        return js_test_runners(root)
    except OSError:
        return []


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


def validate_environment_spec(ctx: RunContext[AgentDeps], output: EnvironmentSpec) -> EnvironmentSpec:
    problems = (environment_spec_violations(output) + install_path_violations(output)
                + offline_warmup_violations(output)
                # Repo-aware, unlike the three above: the binding constraint is what the
                # project declares, which no amount of inspecting the spec alone can reveal.
                + jdk_compatibility_violations(
                    output.base_image, repo_java_release(getattr(ctx.deps, "repo_path", None)))
                + js_runner_choice_violations(
                    output.test_command or "",
                    repo_js_runners(getattr(ctx.deps, "repo_path", None))))
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
