"""Following a validator's own advice must terminate.

The deterministic validators are the highest-leverage part of this system: every durable fix
this month was one. But they are only useful if an agent that does exactly what they say
converges. The failure mode is not a wrong message, it is a *cycle* -- fixing violation A
introduces B, and fixing B reintroduces A -- and it is not hypothetical:

    `MAVEN_TEST_COMMAND` is cited by name in several ModelRetry messages as the command to
    write, and the validators rejected it: it omitted -Dmaven.repo.local. An agent that fixed
    its selector by copying the exemplar was immediately rejected for a *different* violation
    than the one it had just corrected. java-sqli-vulnerable oscillated between the two and
    burned its output retries into `environment_unbuildable`.

That cost a corpus case, and it was found by a live run rather than by a test. These are the
properties that would have caught it without one.
"""
import pytest

from infosec_harness.agents.validators import (
    GRADLE_TEST_COMMAND,
    MAVEN_TEST_COMMAND,
    MAVEN_WARMUP_COMMAND,
    environment_spec_violations,
    install_path_violations,
    offline_warmup_violations,
)
from infosec_harness.domain.models import EnvironmentSpec

# Every check a spec must pass, applied together, exactly as `validate_environment_spec` does.
# Applied separately they can each look satisfiable while no single spec satisfies all of them.
ALL_CHECKS = (environment_spec_violations, install_path_violations, offline_warmup_violations)


def violations(spec: EnvironmentSpec) -> list[str]:
    return [problem for check in ALL_CHECKS for problem in check(spec)]


def maven_spec(**kw) -> EnvironmentSpec:
    base = {
        "base_image": "maven:3.9-eclipse-temurin-17",
        "install_commands": ["mvn -B -Dmaven.repo.local=/opt/home/.m2/repository "
                             "-DskipTests test-compile", MAVEN_WARMUP_COMMAND],
        "test_command": MAVEN_TEST_COMMAND,
    }
    return EnvironmentSpec(**{**base, **kw})


def gradle_spec(**kw) -> EnvironmentSpec:
    base = {
        "base_image": "gradle:8-jdk17",
        "install_commands": ["./gradlew --no-daemon --offline testClasses"],
        "test_command": GRADLE_TEST_COMMAND,
    }
    return EnvironmentSpec(**{**base, **kw})


def pytest_spec(**kw) -> EnvironmentSpec:
    base = {
        "base_image": "python:3.12-slim",
        "install_commands": ["pip install -e ."],
        "test_command": "python -m pytest -q -s {test_file}",
    }
    return EnvironmentSpec(**{**base, **kw})


# Each entry breaks exactly one property of an otherwise-clean spec. Breaking one at a time is
# what makes a cycle visible: if fixing the broken property reintroduces a different violation,
# the spec never reaches a fixed point even though every individual rule is satisfiable.
MUTATIONS = {
    "maven: selector given a file path":
        lambda: maven_spec(test_command=MAVEN_TEST_COMMAND.replace(
            "-Dtest=HarnessProbeTest", "-Dtest={test_file}")),
    "maven: probe-time repo path missing":
        lambda: maven_spec(test_command=MAVEN_TEST_COMMAND.replace(
            " -Dmaven.repo.local=/work/home/.m2/repository", "")),
    "maven: quiet flag hides the markers":
        lambda: maven_spec(test_command=MAVEN_TEST_COMMAND.replace("mvn -B", "mvn -q -B")),
    "maven: surefire not pinned":
        lambda: maven_spec(test_command=MAVEN_TEST_COMMAND.replace(
            "org.apache.maven.plugins:maven-surefire-plugin:3.2.5:test", "test")),
    "maven: warm-up that runs no test":
        lambda: maven_spec(install_commands=[
            "mvn -B -Dmaven.repo.local=/opt/home/.m2/repository -DskipTests test-compile"]),
    "maven: install writes to the probe-time path":
        lambda: maven_spec(install_commands=[
            "mvn -B -Dmaven.repo.local=/work/home/.m2/repository -DskipTests test-compile",
            MAVEN_WARMUP_COMMAND]),
    "maven: swallowed install failure":
        lambda: maven_spec(install_commands=[
            "mvn -B -Dmaven.repo.local=/opt/home/.m2/repository -DskipTests test-compile || true",
            MAVEN_WARMUP_COMMAND]),
    "gradle: no log level, so markers are dropped":
        lambda: gradle_spec(test_command=GRADLE_TEST_COMMAND.replace(" -i ", " ")),
    "gradle: selector given a file path":
        lambda: gradle_spec(test_command=GRADLE_TEST_COMMAND.replace(
            "'*HarnessProbeTest'", "'src/test/java/FooTest.java'")),
    "pytest: output captured away":
        lambda: pytest_spec(test_command="python -m pytest -q {test_file}"),
    "pytest: hardcoded path instead of the placeholder":
        lambda: pytest_spec(test_command="python -m pytest -q -s tests/test_app.py"),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_a_broken_spec_is_actually_rejected(name):
    """The mutation corpus is only meaningful if each mutation really trips a check."""
    assert violations(MUTATIONS[name]()), f"{name}: mutation produced no violation"


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_every_rejection_names_something_the_agent_can_write(name):
    """A message that states a problem without naming the corrected value cannot be converged on.

    This is not a style rule. `describe_callables` rejected a fully-qualified class name with
    `'com.example.UserDao' does not exist.` -- true, and unactionable -- and three of those in a
    row aborted a finding, because UnexpectedModelBehavior is non-retryable. A validator that
    cannot be obeyed is a validator that burns the budget.
    """
    for message in violations(MUTATIONS[name]()):
        # Something quoted, a flag, or a concrete path: any of these gives the agent a value to
        # write. Prose alone does not.
        assert ("`" in message or "'" in message or " -" in message or "/" in message), (
            f"{name}: message names no corrected value:\n  {message}"
        )


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_replacing_the_broken_part_with_the_exemplar_converges_in_one_step(name):
    """Every rejection has a fix that terminates, and the exemplars are it.

    The exemplars are what the messages tell the agent to write, so substituting one must
    produce a *clean* spec rather than a differently-broken one. When MAVEN_TEST_COMMAND itself
    failed install_path_violations, this is the assertion that would have failed.
    """
    spec = MUTATIONS[name]()
    canonical = maven_spec() if "mvn" in (spec.test_command or "") else (
        gradle_spec() if "gradle" in (spec.test_command or "") else pytest_spec())
    assert violations(canonical) == [], (
        f"{name}: the exemplar an agent is told to copy is itself rejected: "
        f"{violations(canonical)}"
    )


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_fixing_one_violation_never_reintroduces_another(name):
    """The convergence property, stated as a fixed point.

    Repair by substituting the canonical spec for the part the validators objected to, then
    re-validate, and keep going. The run must reach zero violations without ever revisiting a
    violation set it has already produced. A repeated set is a cycle: the agent is being sent
    back and forth between two corrections and will exhaust its retries, which is exactly what
    java-sqli-vulnerable did.
    """
    spec = MUTATIONS[name]()
    seen: list[frozenset[str]] = []
    for _ in range(6):
        current = frozenset(violations(spec))
        if not current:
            return
        assert current not in seen, (
            f"{name}: the validators cycle. Violation set repeated:\n  " + "\n  ".join(sorted(current))
        )
        seen.append(current)
        # Stand in for "the agent does what the message says": adopt the exemplar wholesale.
        spec = (maven_spec() if "mvn" in (spec.test_command or "")
                else gradle_spec() if "gradle" in (spec.test_command or "") else pytest_spec())
    pytest.fail(f"{name}: did not converge in 6 rounds; last violations: {violations(spec)}")


def test_the_checks_are_jointly_satisfiable_not_only_separately():
    """Each rule can be satisfiable alone while no single spec satisfies all of them at once.

    That is the shape of the bug this file exists for: `-Dtest=<class>` satisfied the selector
    rule, `-Dmaven.repo.local` satisfied the path rule, and the exemplar that taught the first
    violated the second. Asserting a real spec passes every check *together* is the guard.
    """
    for spec in (maven_spec(), gradle_spec(), pytest_spec()):
        assert violations(spec) == [], f"{spec.test_command}: {violations(spec)}"
