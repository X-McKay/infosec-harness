"""The adapter contract's own invariants: exemplars it cites are clean, and runners are read
from executables rather than found by substring.

Two defects motivate this file. Retry messages cited commands that the same module rejected
(`'mvn -q -B -o test -Dtest=HarnessProbeTest'` fails five Maven checks, and
`'python -m pytest -q -s {test_file}'` lacks `-o addopts=`), so an agent that obeyed one message
was rejected by the next. And runner detection by substring told a pytest command whose path
was `tests/test_approve.py` to use `prove -v`, while a pytest command mentioning `/tmp/mvn` or
`-k gradle` was routed down the JVM branch and skipped every pytest check.
"""

from __future__ import annotations

import ast
import inspect
import re

import pytest

from infosec_harness.agents import ecosystem_contract as contract
from infosec_harness.agents.stubs import _env_plan
from infosec_harness.domain.models import EnvironmentSpec, StackFingerprint
from infosec_harness.repo.detect import detect_stack, java_release
from infosec_harness.sandbox.image import HOME_STAGE, WORK_HOME

C = contract
MAVEN_IMAGE = "maven:3.9-eclipse-temurin-17"


# --- every exemplar a message cites passes every check ---------------------------------------


def _maven_context(framework: str) -> tuple[EnvironmentSpec, str, list[str]]:
    spec = EnvironmentSpec(
        base_image=MAVEN_IMAGE,
        install_commands=[C.MAVEN_INSTALL_COMMAND, C.MAVEN_WARMUP_COMMANDS[framework]],
        test_command=C.MAVEN_TEST_COMMAND,
    )
    return spec, framework, []


def _perl_context() -> tuple[EnvironmentSpec, None, list[str]]:
    spec = EnvironmentSpec(
        base_image="perl:5.38-slim",
        install_commands=[C.CPANM_INSTALL_COMMAND],
        env={"PERL5LIB": C.PERL5LIB_PATH},
        test_command=C.PROVE_TEST_COMMAND,
    )
    return spec, None, []


def _node_context(runner: str) -> tuple[EnvironmentSpec, None, list[str]]:
    spec = EnvironmentSpec(base_image="node:22-slim", test_command=C.JS_TEST_COMMANDS[runner])
    return spec, None, [runner]


# The spec each exemplar is meant to be written into. Every exemplar must have one: an exemplar
# with no context is an exemplar nothing checks.
CONTEXTS = {
    "PYTEST_TEST_COMMAND": lambda: (
        EnvironmentSpec(base_image="python:3.12-slim", test_command=C.PYTEST_TEST_COMMAND),
        None,
        [],
    ),
    "PROVE_TEST_COMMAND": _perl_context,
    "CPANM_INSTALL_COMMAND": _perl_context,
    "MAVEN_TEST_COMMAND": lambda: _maven_context("junit5"),
    "MAVEN_INSTALL_COMMAND": lambda: _maven_context("junit4"),
    "GRADLE_TEST_COMMAND": lambda: (
        EnvironmentSpec(base_image="gradle:8-jdk17", test_command=C.GRADLE_TEST_COMMAND),
        None,
        [],
    ),
    "JEST_TEST_COMMAND": lambda: _node_context("jest"),
    "VITEST_TEST_COMMAND": lambda: _node_context("vitest"),
    "MOCHA_TEST_COMMAND": lambda: _node_context("mocha"),
    "NODE_TEST_COMMAND": lambda: _node_context("node:test"),
    "JASMINE_TEST_COMMAND": lambda: _node_context("jasmine"),
    **{
        f"MAVEN_WARMUP_COMMANDS[{framework}]": (lambda framework=framework: _maven_context(framework))
        for framework in C.MAVEN_WARMUP_COMMANDS
    },
}


def all_violations(spec: EnvironmentSpec, framework: str | None = None,
                   declared: list[str] | None = None) -> list[str]:
    """Every check in the contract, applied together as the env-planner validator applies them."""
    return (
        C.environment_spec_violations(spec)
        + C.install_path_violations(spec)
        + C.offline_warmup_violations(spec, framework)
        + C.js_runner_choice_violations(spec.test_command or "", declared or [])
        + C.jdk_compatibility_violations(spec.base_image, 17 if framework else None)
    )


def test_every_registered_exemplar_has_a_context():
    assert set(CONTEXTS) == set(C.MESSAGE_EXEMPLARS)


@pytest.mark.parametrize("name", sorted(C.MESSAGE_EXEMPLARS))
def test_every_exemplar_a_message_cites_passes_every_check(name):
    spec, framework, declared = CONTEXTS[name]()
    exemplar = C.MESSAGE_EXEMPLARS[name]
    assert exemplar in [spec.test_command, *spec.install_commands], name
    assert all_violations(spec, framework, declared) == [], name


# A corpus that reaches every message branch in the module. The messages are the thing under
# test here, so each spec is broken in the way that makes one particular message fire.
def _spec(test_command: str, image: str = "python:3.12-slim", installs=(), env=None):
    return EnvironmentSpec(base_image=image, test_command=test_command,
                           install_commands=list(installs), env=env or {})


BROKEN = [
    # path runners
    (_spec("python -m pytest -q -s tests/test_app.py"), None, []),
    (_spec("python -m pytest -q {test_file}"), None, []),
    (_spec("python -m pytest -q -s {test_file}"), None, []),
    (_spec("prove {test_file}", "perl:5.38-slim"), None, []),
    (_spec("prove -v t/probe.t", "perl:5.38-slim"), None, []),
    (_spec("npx jest --runTestsByPath {test_file}", "node:22-slim"), None, []),
    (_spec("npx jest --silent=false --runTestsByPath __tests__/p.test.js", "node:22-slim"), None, []),
    (_spec("npx vitest run --silent=false --runTestsByPath {test_file}", "node:22-slim"), None, []),
    (_spec("npx vitest run {test_file}", "node:22-slim"), None, []),
    (_spec("npx mocha test/probe.js", "node:22-slim"), None, []),
    (_spec("node --test test/probe.js", "node:22-slim"), None, []),
    (_spec("npx jasmine spec/probe.js", "node:22-slim"), None, []),
    (_spec("sh tests/probe.sh", "debian:bookworm-slim"), None, []),
    # JVM
    (_spec("mvn -q -B test -Dtest=", MAVEN_IMAGE), None, []),
    (_spec("mvn -B test", MAVEN_IMAGE), None, []),
    (_spec("./gradlew --offline test", "gradle:8-jdk17"), None, []),
    (_spec("sh run.sh -Dtest=", MAVEN_IMAGE), None, []),
    (_spec(C.MAVEN_TEST_COMMAND.replace("-Dtest=HarnessProbeTest", "-Dtest={test_file}"),
           MAVEN_IMAGE), None, []),
    (_spec(C.GRADLE_TEST_COMMAND.replace("'*HarnessProbeTest'", "src/test/java/FooTest.java"),
           "gradle:8-jdk17"), None, []),
    (_spec("mvn -q -B -o test -Dtest=HarnessProbeTest", MAVEN_IMAGE), None, []),
    (_spec("mvn -B -o org.apache.maven.plugins:maven-surefire-plugin:3.2.5:test "
           "-Dtest=HarnessProbeTest", MAVEN_IMAGE), None, []),
    (_spec("./gradlew --offline test --tests '*HarnessProbeTest'", "gradle:8-jdk17"), None, []),
    # installs
    (_spec(C.MAVEN_TEST_COMMAND, MAVEN_IMAGE,
           [C.MAVEN_INSTALL_COMMAND + " || true", C.MAVEN_WARMUP_COMMAND]), "junit5", []),
    (_spec(C.PROVE_TEST_COMMAND, "perl:5.38-slim", [C.CPANM_INSTALL_COMMAND + " || true"],
           {"PERL5LIB": C.PERL5LIB_PATH}), None, []),
    (_spec(C.PROVE_TEST_COMMAND, "perl:5.38-slim", ["cpanm --notest --installdeps ."]), None, []),
    (_spec("prove -v {test_file}", "perl:5.38-slim",
           ["cpanm --notest -l /opt/home/perl5 --installdeps ."]), None, []),
    (_spec(C.PROVE_TEST_COMMAND, "perl:5.38-slim", [C.CPANM_INSTALL_COMMAND],
           {"PERL5LIB": "/usr/lib/perl5"}), None, []),
    (_spec(C.PROVE_TEST_COMMAND, "perl:5.38-slim",
           ["cpanm --notest --local-lib=/work/home/perl5 --installdeps ."]), None, []),
    (_spec(C.MAVEN_TEST_COMMAND, MAVEN_IMAGE, ["mvn -B -DskipTests test-compile"]), "junit4", []),
    # offline warm-up, every framework, both message variants
    *[(_spec(C.MAVEN_TEST_COMMAND, MAVEN_IMAGE, [C.MAVEN_INSTALL_COMMAND]), fw, [])
      for fw in (None, *C.MAVEN_WARMUP_COMMANDS)],
    *[(_spec(C.MAVEN_TEST_COMMAND, MAVEN_IMAGE, [C.MAVEN_INSTALL_COMMAND, C.MAVEN_WARMUP_COMMAND]),
       fw, []) for fw in ("junit4", "testng")],
    # JDK and runner choice
    (_spec(C.MAVEN_TEST_COMMAND, "maven:3.9-eclipse-temurin-8",
           [C.MAVEN_INSTALL_COMMAND, C.MAVEN_WARMUP_COMMAND]), "junit5", []),
    *[(_spec(C.JEST_TEST_COMMAND, "node:22-slim"), None, [declared])
      for declared in ("vitest", "mocha", "node:test", "jasmine", "ava")],
    (_spec(C.VITEST_TEST_COMMAND, "node:22-slim"), None, ["jest"]),
]

# Where a whole command starts inside a message. A match must be the start of a registered
# exemplar; a command spelled inline, or echoed back wrong, fails here.
_COMMAND_START = re.compile(
    r"(?<![\w./-])(?:\./)?(?:mvnw?|gradlew?)\s+-"
    r"|\bpython3?\s+-m\s+pytest"
    r"|(?<![\w./-])prove\s+-"
    r"|\bnpx\s+(?:-|jest|vitest|mocha|jasmine|tsx)"
    r"|\bnode\s+--test"
    r"|\bcpanm\s+-"
    r"|\bmkdir\s+-p"
)


def _messages() -> list[str]:
    return [
        message
        for spec, framework, declared in BROKEN
        for message in all_violations(spec, framework, declared)
    ]


def _cited(message: str) -> list[str]:
    """The exemplars a message cites, failing on any command that is not one."""
    cited: list[str] = []
    covered_until = -1
    exemplars = sorted(C.MESSAGE_EXEMPLARS.values(), key=len, reverse=True)
    for match in _COMMAND_START.finditer(message):
        if match.start() < covered_until:
            continue  # inside an exemplar already matched, e.g. the mvn in a warm-up
        exemplar = next((e for e in exemplars if message.startswith(e, match.start())), None)
        assert exemplar is not None, (
            f"message cites a command that is not a registered exemplar, at "
            f"{message[match.start():match.start() + 90]!r}\n  in: {message}"
        )
        cited.append(exemplar)
        covered_until = match.start() + len(exemplar)
    return cited


def test_the_broken_corpus_is_actually_broken():
    for spec, framework, declared in BROKEN:
        assert all_violations(spec, framework, declared), spec.test_command


def test_every_command_a_message_cites_is_a_clean_registered_exemplar():
    """The guard that keeps exemplars from drifting again: scan what the agent is really shown."""
    cited = {exemplar for message in _messages() for exemplar in _cited(message)}
    # And the corpus reaches every exemplar, so none is registered without being exercised.
    assert cited == set(C.MESSAGE_EXEMPLARS.values()), (
        set(C.MESSAGE_EXEMPLARS.values()) - cited
    )


def test_no_message_spells_a_command_inline():
    """Static half of the guard: inside functions, no string literal spells out a command.

    Messages must interpolate the module's constants. `_warmup` is exempt because it is the
    builder of the MAVEN_WARMUP_COMMANDS exemplars, which the dynamic test checks.
    """
    tree = ast.parse(inspect.getsource(contract))
    offenders = []
    for function in ast.walk(tree):
        if not isinstance(function, ast.FunctionDef) or function.name == "_warmup":
            continue
        docstring = ast.get_docstring(function, clean=False)
        for node in ast.walk(function):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and node.value != docstring and _COMMAND_START.search(node.value)):
                offenders.append((function.name, node.value))
    assert offenders == []


# --- runners are read from executables -------------------------------------------------------


@pytest.mark.parametrize(
    "command,runners",
    [
        (C.MAVEN_TEST_COMMAND, {"maven"}),
        (C.GRADLE_TEST_COMMAND, {"gradle"}),
        (C.PYTEST_TEST_COMMAND, {"pytest"}),
        (C.PROVE_TEST_COMMAND, {"prove"}),
        (C.MAVEN_WARMUP_COMMAND, {"maven"}),
        (C.CPANM_INSTALL_COMMAND, {"cpanm"}),
        # the paths and words that substring matching misread
        ("python -m pytest -q -s -o addopts= tests/test_approve.py", {"pytest"}),
        ("python -m pytest -q -s -o addopts= {test_file} -k improve", {"pytest"}),
        ("python -m pytest -q -s -o addopts= {test_file} --basetemp /tmp/mvn", {"pytest"}),
        ("python -m pytest -q -s -o addopts= {test_file} -k gradle", {"pytest"}),
        ("python -m pytest -q -s -o addopts= {test_file} --rootdir tests/jest", {"pytest"}),
        ("cd vitest-compat && npx jest --silent=false --runTestsByPath {test_file}", {"jest"}),
        ("python -m pip install --user -r requirements-mvn.txt", set()),
        ("curl -fsSL -o /tmp/cpanm-bootstrap https://cpanmin.us", set()),
        # the shells and wrappers it must still see through
        ("bash -o pipefail -c 'cd app && mvn -B test'", {"maven"}),
        ("sh ./gradlew test", {"gradle"}),
        ("FOO=1 timeout 60 python3 -X dev -m pytest -q {test_file}", {"pytest"}),
        ("env CI=1 py.test {test_file}", {"pytest"}),
        ("uv run pytest {test_file}", {"pytest"}),
        ("coverage run -m pytest {test_file}", {"pytest"}),
        ("perl -S prove -v {test_file}", {"prove"}),
        ("npx --no-install jest@29 --runTestsByPath {test_file}", {"jest"}),
        ("node node_modules/.bin/jest {test_file}", {"jest"}),
        ("yarn vitest run {test_file}", {"vitest"}),
        ("npx tsx --test {test_file}", {"node:test"}),
        ("mvn.cmd -B test", {"maven"}),
        ("mvn test > out.log 2>&1 && ./gradlew test", {"maven", "gradle"}),
        # not valid shell: detection must not switch off
        ("python -m pytest -q '{test_file}", {"pytest"}),
        ("npm test", set()),
    ],
)
def test_runner_detection_reads_the_executable(command, runners):
    assert C.command_runners(command) == runners


def test_a_pytest_path_containing_prove_is_not_told_to_use_prove():
    """Regression: `approve` contains `prove`, and the pytest command got prove's advice."""
    problems = C.environment_spec_violations(
        _spec("python -m pytest -q -s -o addopts= tests/test_approve.py"))
    assert problems and not any("prove" in p for p in problems), problems
    assert any(C.PYTEST_TEST_COMMAND in p for p in problems), problems
    for clean in ("python -m pytest -q -s -o addopts= {test_file} --deselect tests/test_approve.py",
                  "python -m pytest -q -s -o addopts= {test_file} -k improve"):
        assert C.environment_spec_violations(_spec(clean)) == [], clean


@pytest.mark.parametrize("tail", ["--basetemp /tmp/mvn", "-k gradle", "-k mvnw"])
def test_a_pytest_command_mentioning_a_jvm_runner_keeps_its_pytest_checks(tail):
    """Regression: a bare `mvn`/`gradle` word routed pytest down the JVM branch.

    That branch asked for a class selector and returned before the pytest checks, so a pytest
    command that captured its output was accepted.
    """
    clean = f"python -m pytest -q -s -o addopts= {{test_file}} {tail}"
    assert C.environment_spec_violations(_spec(clean)) == []
    captured = f"python -m pytest -q -o addopts= {{test_file}} {tail}"
    problems = C.environment_spec_violations(_spec(captured))
    assert any("-s" in p and "capture" in p for p in problems), problems
    assert not any("test class" in p for p in problems), problems


def test_a_path_containing_jest_or_vitest_does_not_pick_the_node_runner():
    """Regression: the first bare `jest`/`vitest` word was taken as the runner."""
    assert C.environment_spec_violations(_spec(
        "python -m pytest -q -s -o addopts= {test_file} --rootdir tests/jest")) == []
    jest_in_vitest_dir = "cd vitest && npx jest --silent=false --runTestsByPath {test_file}"
    assert C.environment_spec_violations(_spec(jest_in_vitest_dir, "node:22-slim")) == []
    assert C.js_runner_choice_violations(jest_in_vitest_dir, ["jest"]) == []


def test_a_class_selector_next_to_a_path_runner_does_not_exempt_it():
    """`-Dtest=` used to route any command down the JVM branch, skipping the pytest checks."""
    problems = C.environment_spec_violations(_spec("pytest -q {test_file} -Dtest=Foo"))
    assert any("capture" in p for p in problems), problems
    assert any("addopts" in p for p in problems), problems


def test_an_install_that_only_mentions_a_tool_is_not_held_to_its_rules():
    """`mvn` in a requirements file name, `cpanm` in a URL: neither invokes the tool."""
    spec = EnvironmentSpec(
        base_image="python:3.12-slim", test_command=C.PYTEST_TEST_COMMAND,
        install_commands=["python -m pip install --user -r requirements-mvn.txt",
                          "curl -fsSL -o /tmp/cpanm-bootstrap https://cpanmin.us"])
    assert C.install_path_violations(spec) == []


@pytest.mark.parametrize(
    "spec,expected",
    [
        (_spec("bash -c 'mvn -B test'", MAVEN_IMAGE), "test class"),
        (_spec("sh ./gradlew test", "gradle:8-jdk17"), "test class"),
        (_spec("cd app && python -m pytest -q -o addopts= {test_file}"), "capture"),
        (_spec("FOO=1 timeout 60 pytest -s {test_file}"), "addopts"),
        (_spec("npx --no-install jest@29 --runTestsByPath {test_file}", "node:22-slim"),
         "--silent=false"),
        (_spec("perl -S prove {test_file}", "perl:5.38-slim"), "verbose"),
        (_spec("python -m pytest -q -o addopts= '{test_file}"), "capture"),
        (EnvironmentSpec(base_image=MAVEN_IMAGE, test_command=C.MAVEN_TEST_COMMAND,
                         install_commands=["sh -c 'mvn -B -DskipTests test-compile'"]),
         "-Dmaven.repo.local"),
        (EnvironmentSpec(base_image="perl:5.38-slim", test_command=C.PROVE_TEST_COMMAND,
                         install_commands=["cd /opt/repo && cpanm --notest --installdeps ."]),
         "--local-lib"),
    ],
)
def test_detection_still_sees_through_shells_and_wrappers(spec, expected):
    """Fail-closed: tokenising must not lose a runner that substring matching used to catch."""
    problems = C.environment_spec_violations(spec) + C.install_path_violations(spec)
    assert any(expected in p for p in problems), problems


# --- the stub plans are built from the same constants ----------------------------------------


def _stub_spec(languages, manifests=(), frameworks=()) -> EnvironmentSpec:
    stack = StackFingerprint(languages=languages, manifests=list(manifests),
                             test_frameworks=list(frameworks))
    return EnvironmentSpec.model_validate(_env_plan(stack.model_dump(mode="json")))


@pytest.mark.parametrize("framework", sorted(C.MAVEN_WARMUP_COMMANDS))
def test_the_java_stub_plan_is_the_contracts_exemplar(framework):
    spec = _stub_spec({"java": 1}, ["pom.xml"], [framework])
    assert spec.test_command == C.MAVEN_TEST_COMMAND
    assert spec.install_commands == [C.MAVEN_INSTALL_COMMAND, C.MAVEN_WARMUP_COMMANDS[framework]]
    assert all_violations(spec, framework) == []


@pytest.mark.parametrize("runner", sorted(C.JS_TEST_COMMANDS))
def test_the_node_stub_plan_is_the_contracts_exemplar(runner):
    spec = _stub_spec({"javascript": 1}, ["package.json"], [runner])
    assert spec.test_command == C.JS_TEST_COMMANDS[runner]
    assert all_violations(spec, declared=[runner]) == []


def test_the_python_and_perl_stub_plans_are_the_contracts_exemplars():
    python = _stub_spec({"python": 1}, ["requirements.txt"])
    assert python.test_command == C.PYTEST_TEST_COMMAND
    assert python.env["PATH"].startswith(f"{C.RUNTIME_HOME}/.local/bin:")
    assert all_violations(python) == []
    perl = _stub_spec({"perl": 1}, ["cpanfile"])
    assert perl.test_command == C.PROVE_TEST_COMMAND
    assert perl.install_commands == [C.CPANM_INSTALL_COMMAND]
    assert perl.env == {"PERL5LIB": C.PERL5LIB_PATH}
    assert all_violations(perl) == []


def test_the_home_paths_are_the_sandboxs_own():
    """The contract and the stubs read the image layout from the module that builds it."""

    assert (C.BUILD_HOME, C.RUNTIME_HOME) == (HOME_STAGE, WORK_HOME)


def test_the_binding_java_release_is_the_oldest_any_candidate_declares():
    pom = "<maven.compiler.source>{}</maven.compiler.source>"
    assert java_release([]) is None
    assert java_release(["<project/>"]) is None
    assert java_release([pom.format("11"), pom.format("1.7"), "<project/>"]) == 7


def test_the_repo_release_reads_the_root_and_its_modules(tmp_path):
    """A multi-module repository whose root declares nothing still binds the JDK."""
    (tmp_path / "pom.xml").write_text("<project><modules/></project>")
    (tmp_path / "core").mkdir()
    (tmp_path / "core" / "pom.xml").write_text(
        "<maven.compiler.source>1.6</maven.compiler.source>")
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "build.gradle").write_text("sourceCompatibility = '1.8'")
    assert C.repo_java_release(str(tmp_path)) == 6
    # The fingerprint binds the same level, so the recipe key and the JDK check agree.
    assert detect_stack(str(tmp_path)).java_release == 6
    assert C.repo_java_release(str(tmp_path / "missing")) is None
    assert C.repo_java_release(None) is None
