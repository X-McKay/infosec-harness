"""Versioned environment adapter contract for the initial unit-probe ecosystems.

This module holds deterministic validation shared by planning, repair, fixtures, and evals.
It describes the existing Python, JVM, JavaScript, and Perl unit-probe slices; detection alone
does not promote a component to tested support.
"""

from __future__ import annotations

import contextlib
import re
import shlex
from collections.abc import Iterable
from pathlib import Path

from infosec_harness.domain.models import EnvironmentSpec
from infosec_harness.repo.detect import declared_java_release, js_test_runners, jvm_test_framework

# The sandbox builds the image with HOME under /opt and copies it to a /work tmpfs for the
# probe: installs write under BUILD_HOME, anything resolved at probe time reads RUNTIME_HOME.
from infosec_harness.sandbox.docker import HOME_STAGE as BUILD_HOME
from infosec_harness.sandbox.docker import WORK_HOME as RUNTIME_HOME

# v2: runner detection reads the executable instead of searching the command text, and every
# retry message cites a canonical command that passes every check here. Both change which specs
# are accepted and the bytes the models are shown on retry.
ADAPTER_CONTRACT_VERSION = "unit-probe-adapters/v2"

# Where Maven's local repository lives in each phase, and where cpanm's local lib is found.
MAVEN_BUILD_REPOSITORY = f"{BUILD_HOME}/.m2/repository"
MAVEN_RUNTIME_REPOSITORY = f"{RUNTIME_HOME}/.m2/repository"
CPANM_LOCAL_LIB = f"{BUILD_HOME}/perl5"
# /opt rather than the /work copy: /work is a noexec tmpfs, so an XS module's shared object
# cannot be mapped from there.
PERL5LIB_PATH = f"{CPANM_LOCAL_LIB}/lib/perl5"

# pytest buffers stdout unless told not to, and the oracle markers are stdout. Either of
# these disables that capture.
PYTEST_TEST_COMMAND = "python -m pytest -q -s -o addopts= {test_file}"
# prove must be verbose (see below), and -Ilib is load-bearing too: measured on fixtures whose
# modules live in lib/, a probe with no `use lib` under a prove with no -I dies on
# `Can't locate Runner.pm`.
PROVE_TEST_COMMAND = "prove -v -Ilib {test_file}"
# cpanm as the non-root sandbox user cannot write perl's site dir, so it installs into a local
# lib that PERL5LIB then points at.
CPANM_INSTALL_COMMAND = f"cpanm --notest --local-lib={CPANM_LOCAL_LIB} --installdeps ."
# The build-time compile that populates the local repository for the offline probe.
MAVEN_INSTALL_COMMAND = (
    f"mvn -B -Dmaven.repo.local={MAVEN_BUILD_REPOSITORY} -DskipTests test-compile"
)
_PYTEST_UNBUFFERED = ("-s", "--capture=no", "--capture no")
# A project's own `addopts` are prepended to our invocation; `addopts = --collect-only` exits 0
# with no markers and no "collected 0 items" text. `-o addopts=` neutralises it (ini and
# pyproject forms both verified).
_PYTEST_ADDOPTS_NEUTRALISED = (
    "-o addopts=",
    "-o addopts =",
    "--override-ini addopts=",
    "--override-ini=addopts=",
)
# prove parses its child's TAP stream and throws away everything that is not TAP unless it is
# verbose, so a non-verbose `prove` swallows every marker exactly as an un-`-s`ed pytest does.
# JVM runners select a test by class name rather than by file path.
_CLASS_SELECTORS = ("-Dtest=", "--tests")
# Maven relays the forked test JVM's stdout through its own logger at INFO level, so -q raises
# the threshold above the markers and they never reach the runner's stdout.
_MAVEN_REDIRECT_OFF = (
    "-Dmaven.test.redirectTestOutputToFile=false",
    "-DredirectTestOutputToFile=false",
)
# Maven 3.x binds Surefire 2.12.4 (no JUnit Platform provider) to the `test` phase, and a
# phase-bound version cannot be overridden from the command line, so a spec compiles with
# `test-compile` and invokes a pinned Surefire goal directly.
_SUREFIRE_PIN = re.compile(r"maven-surefire-plugin:(\d+)[.:]")
# Lifecycle phases that run the pom's own (2.12.4) surefire execution on the way past.
_PHASES_RUNNING_SUREFIRE = frozenset(
    {"test", "integration-test", "verify", "package", "install", "deploy"}
)
_COMPILES_TESTS = "test-compile"
# Every Maven retry message cites this command, so it must itself pass every check here
# (see MESSAGE_EXEMPLARS).
MAVEN_TEST_COMMAND = (
    "mvn -B -o test-compile "
    "org.apache.maven.plugins:maven-surefire-plugin:3.2.5:test "
    f"-Dtest=HarnessProbeTest -Dmaven.repo.local={MAVEN_RUNTIME_REPOSITORY} "
    "-Dmaven.test.redirectTestOutputToFile=false"
)
# Gradle's `test` task is incremental: a repeated run is UP-TO-DATE, executes nothing and exits 0.
# `--rerun-tasks` (or `cleanTest test`) forces it.
_GRADLE_UNCONDITIONAL = ("--rerun-tasks", "--rerun")
GRADLE_TEST_COMMAND = (
    "./gradlew --no-daemon --offline --rerun-tasks -i test --tests '*HarnessProbeTest'"
)
# jest and vitest honour a repository config's `silent: true`, which hides every marker while the
# run exits 0; `--silent=false` overrides it. mocha and node:test never capture stdout.
JEST_TEST_COMMAND = "npx jest --silent=false --runTestsByPath {test_file}"
VITEST_TEST_COMMAND = "npx vitest run --silent=false {test_file}"
MOCHA_TEST_COMMAND = "npx mocha {test_file}"
NODE_TEST_COMMAND = "node --test {test_file}"
JASMINE_TEST_COMMAND = "npx jasmine {test_file}"
_JS_CAPTURING_RUNNERS = {"jest": JEST_TEST_COMMAND, "vitest": VITEST_TEST_COMMAND}
# One command per Node runner, because the runner is not interchangeable with its selector.
JS_TEST_COMMANDS: dict[str, str] = {
    "jest": JEST_TEST_COMMAND,
    "vitest": VITEST_TEST_COMMAND,
    "mocha": MOCHA_TEST_COMMAND,
    "node:test": NODE_TEST_COMMAND,
    "jasmine": JASMINE_TEST_COMMAND,
}
_JS_SILENT_OFF = "--silent=false"
# `--runTestsByPath` is jest's; vitest rejects it before loading any test file.
_JEST_ONLY_SELECTOR = "--runTestsByPath"
# `cmd || true` makes a failed dependency install invisible: the image builds, the smoke test
# passes, and the absence surfaces at probe time as a compile error inside the probe — past
# build repair, the only stage that could have installed anything.
_SWALLOWED_FAILURE = re.compile(r"\|\|\s*(?:true|:)\s*(?=$|[;&|])|;\s*true\s*$")
# cpanm into a local lib puts the modules somewhere perl does not look by default.
_CPANM_LOCAL_LIB = re.compile(r"cpanm\b.*?(?:\s-[lL]\s|--local-lib(?:-contained)?)")


# --- Which runner a command invokes ----------------------------------------------------------
#
# The runner is the *executable* of a simple command, never a word that merely contains its name
# (`tests/test_approve.py` is not `prove`; `--basetemp /tmp/mvn` is not Maven). The tokeniser
# splits on shell operators, skips redirection targets and `VAR=value` prefixes, sees through the
# usual wrappers (`env`, `timeout`, `sh -c`, `python -m`, `npx`, `uv run`, ...), and falls back to
# a plain split on invalid shell so detection never silently turns off.

_EXECUTABLE_RUNNERS = {
    "mvn": "maven",
    "mvnw": "maven",
    "mvnd": "maven",
    "gradle": "gradle",
    "gradlew": "gradle",
    "pytest": "pytest",
    "py.test": "pytest",
    "prove": "prove",
    "jest": "jest",
    "vitest": "vitest",
    "mocha": "mocha",
    "jasmine": "jasmine",
    "cpanm": "cpanm",
}
_JVM_RUNNERS = frozenset({"maven", "gradle"})
# Runners that take the probe's *path*; a `-Dtest=` next to one of these is not a JVM selector.
_PATH_RUNNERS = frozenset({"pytest", "prove", "jest", "vitest", "mocha", "jasmine", "node:test"})
_JS_RUNNERS = ("vitest", "jest", "mocha", "jasmine")
_SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ash", "ksh"})
_PYTHONS = re.compile(r"^(?:python(?:\d+(?:\.\d+)?)?|py|pypy3?)$")
# Wrappers whose own flags precede the real command; the int is how many positional arguments
# they take before it (`timeout 60 mvn ...`).
_WRAPPERS = {"env": 0, "exec": 0, "time": 0, "nohup": 0, "nice": 0,
             "stdbuf": 0, "xvfb-run": 0, "sudo": 0, "timeout": 1}
_RUN_WRAPPERS = frozenset({"uv", "poetry", "pipenv", "pdm", "hatch", "rye"})
_NPX = frozenset({"npx", "bunx", "pnpx"})
_PACKAGE_MANAGERS = frozenset({"npm", "pnpm", "yarn", "bun"})
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_OPERATOR = re.compile(r"^[();<>|&]+$")
_MAX_SHELL_DEPTH = 4


def _words(command: str) -> list[str]:
    """Shell words and operators. Never raises: invalid shell still yields words."""
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        lexer.commenters = ""  # `-Dx=#y` is a property, not a comment; keep every word
        return list(lexer)
    except ValueError:
        return re.findall(r"[();<>|&]+|[^\s();<>|&]+", command)


def _simple_commands(words: list[str]) -> list[list[str]]:
    segments: list[list[str]] = [[]]
    skip_target = False
    for word in words:
        if skip_target:
            skip_target = False
            continue
        if _OPERATOR.match(word):
            if "<" in word or ">" in word:
                skip_target = not word.endswith("&")  # `2>&1` names no file
                continue
            segments.append([])
            continue
        segments[-1].append(word)
    return [segment for segment in segments if segment]


def _program(word: str) -> str:
    """The program a word names: basename, no Windows or JS suffix, no `@version`."""
    name = word.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if "@" in name[1:]:
        name = name[: name.index("@", 1)]
    for suffix in (".cmd", ".bat", ".exe", ".js", ".cjs", ".mjs"):
        name = name.removesuffix(suffix)
    return name


def _skip_flags(words: list[str], valued: tuple[str, ...] = ()) -> list[str]:
    i = 0
    while i < len(words) and (words[i].startswith("-") or _ASSIGNMENT.match(words[i])):
        i += 2 if words[i] in valued else 1
        if i <= len(words) and words[i - 1] == "--":
            break
    return words[i:]


def _python_target(args: list[str]) -> list[str]:
    """What `python [opts] -m mod args` / `python [opts] script args` runs, as a new argv."""
    i = 0
    while i < len(args):
        word = args[i]
        if word == "-m":
            return args[i + 1 :]
        if word.startswith("-m") and len(word) > 2 and not word.startswith("--"):
            return [word[2:], *args[i + 1 :]]
        if word in ("-c",) or (word.startswith("-") and not word.startswith("--")
                               and word.endswith("c") and len(word) > 2):
            return []  # inline code: nothing to resolve
        if word in ("-W", "-X"):
            i += 2
            continue
        if word.startswith("-"):
            i += 1
            continue
        return args[i:]
    return []


def _resolve(argv: list[str], depth: int) -> list[tuple[str, list[str]]]:
    while argv:
        head, rest = argv[0], argv[1:]
        if _ASSIGNMENT.match(head):
            argv = rest
            continue
        program = _program(head)
        if program in _WRAPPERS:
            rest = _skip_flags(rest, ("-u", "-n", "-s", "-k", "--signal", "--kill-after"))
            argv = rest[_WRAPPERS[program] :]
            continue
        if program in _SHELLS:
            i = 0
            while i < len(rest) and rest[i].startswith(("-", "+")):
                word = rest[i]
                if word in ("-o", "+o", "-O", "+O"):
                    i += 2
                    continue
                if "c" in word[1:] and not word.startswith("--"):
                    if depth >= _MAX_SHELL_DEPTH or i + 1 >= len(rest):
                        return []
                    return _invocations(rest[i + 1], depth + 1)
                i += 1
            argv = rest[i:]  # `sh ./gradlew test`: the script is the command
            continue
        if _PYTHONS.match(program):
            argv = _python_target(rest)
            continue
        if program == "coverage":
            argv = _python_target(rest[1:]) if rest[:1] == ["run"] else []
            continue
        if program in ("perl", "node", "tsx"):
            if program != "perl" and "--test" in rest:
                return [("node:test", rest)]
            if program == "perl" and any(w in ("-e", "-E") for w in rest):
                return []
            argv = _skip_flags(rest, ("-I", "-M", "-r", "--require", "--import", "--loader"))
            continue
        if program in _RUN_WRAPPERS:
            argv = _skip_flags(rest[1:]) if rest[:1] == ["run"] else []
            continue
        if program in _NPX:
            argv = _skip_flags(rest, ("-p", "--package", "-c", "--call"))
            continue
        if program in _PACKAGE_MANAGERS:
            if rest[:1] and rest[0] in ("exec", "x", "dlx", "run"):
                rest = rest[1:]
            elif program == "npm":
                return []  # `npm test` runs a script this contract cannot see into
            argv = _skip_flags(rest)
            continue
        runner = _EXECUTABLE_RUNNERS.get(program)
        return [(runner, rest)] if runner else []
    return []


def _invocations(command: str, depth: int = 0) -> list[tuple[str, list[str]]]:
    """Every (runner, arguments) the command invokes, in order."""
    found: list[tuple[str, list[str]]] = []
    for argv in _simple_commands(_words(command)):
        found += _resolve(argv, depth)
    return found


def command_runners(command: str) -> frozenset[str]:
    """The test runners and installers a shell command invokes, read from its executables."""
    return frozenset(runner for runner, _ in _invocations(command))


def _invokes(commands: str | list[str] | tuple[str, ...], runner: str) -> bool:
    if isinstance(commands, str):
        commands = [commands]
    return any(runner in command_runners(command) for command in commands)


def _js_runner(command: str) -> str | None:
    """Which Node test runner a command invokes, or None: the first one run as an executable.

    A command may legitimately mention two (`npx vitest run` in a repo whose config file is
    named jest.*, or a `cd jest-compat && npx vitest ...`); only the executable counts.
    """
    return next((runner for runner, _ in _invocations(command) if runner in _JS_RUNNERS), None)


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


def _path_runner_exemplar(runners: frozenset[str]) -> str:
    """The canonical command for the path-taking runner a command invokes; pytest otherwise."""
    if "prove" in runners:
        return PROVE_TEST_COMMAND
    js = next((runner for runner in (*_JS_RUNNERS, "node:test") if runner in runners), None)
    return JS_TEST_COMMANDS[js] if js else PYTEST_TEST_COMMAND


def _selects_by_class_name(command: str) -> bool:
    """A JVM class selector as a word of its own, not as part of some other flag or path."""
    return any(
        word.startswith("-Dtest=") or word == "--tests" or word.startswith("--tests=")
        for word in _words(command)
    )


def _is_jvm_runner(command: str) -> bool:
    """A Maven or Gradle command, selector or not, read from its executables."""
    return bool(command_runners(command) & _JVM_RUNNERS)


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
    """The phases and goals the `mvn` invocations ask for, with flags and properties removed."""
    return [
        word
        for runner, args in _invocations(command)
        if runner == "maven"
        for word in args
        if not word.startswith("-")
    ]


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
            "PERL5LIB" in spec.env
            or "PERL5LIB" in (spec.test_command or "")
            or _short_flag(spec.test_command or "", "I")
        ):
            problems.append(
                "This install puts the modules in a local lib, so set "
                f"env.PERL5LIB={PERL5LIB_PATH} (matching the -l/-L path) or drop the "
                "local lib entirely. Without it prove runs with the stock @INC and the probe "
                "dies on the modules that were just installed."
            )
    return problems


def _jvm_violations(command: str) -> list[str]:
    """Maven and Gradle: the ways a JVM probe runs and reports nothing anyway."""
    problems: list[str] = []
    runners = command_runners(command)
    if "maven" in runners:
        if _short_flag(command, "q") or _long_flag(command, "--quiet"):
            problems.append(
                f"Drop -q and use -B instead: {MAVEN_TEST_COMMAND}. Maven relays the forked "
                "test JVM's stdout through its own logger at INFO level, so -q raises the "
                "threshold above the probe's HARNESS_ markers and a correct probe is recorded "
                "as having reached nothing."
            )
        if not any(flag in command for flag in _MAVEN_REDIRECT_OFF):
            problems.append(
                f"Add -Dmaven.test.redirectTestOutputToFile=false: {MAVEN_TEST_COMMAND}. A pom "
                "that turns the "
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
    if "gradle" in runners:
        if not (
            _short_flag(command, "i")
            or _short_flag(command, "d")
            or _long_flag(command, "--info", "--debug")
        ):
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


# Surefire and Gradle select by *class*, so a selector given a file path (or `{test_file}`)
# matches nothing and the run executes zero tests.
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
    hint = f"-Dtest={named}" if "-Dtest=" in command else f"--tests '*{named}'"
    return (
        f"the test selector was given {value!r}, which is a file path, not a class name. Write "
        f"{hint} instead. Surefire and Gradle match selectors against class names, so a path "
        f"matches nothing and the run executes zero tests -- Surefire reports "
        f'`No tests matching pattern "{value}" were executed!`. Do not use {{test_file}} in a '
        f"JVM selector: the harness substitutes the probe's path there, which is exactly the "
        f"value that matches nothing. The coupling is by name -- the probe's test class must be "
        f"the one the selector names."
    )


# --- JDK / language-level compatibility -----------------------------------------------------
#
# A JDK too old fails with "invalid target release"; one too new no longer accepts old -source
# levels. Both are caught at plan time. An unknown JDK gets no floor rather than a guessed one.
_JAVAC_SOURCE_FLOOR = (
    (20, 8),  # JDK 20 removed -source/-target 7: "Source option 7 is no longer supported."
    (12, 7),  # JDK 12 removed 6 (deprecated in 11).
    (11, 6),  # JDK 11 removed 5: "Source option 5 is no longer supported. Use 6 or later."
)
# Each floor was executed (javac from JDK 8/11/17/21 against -source 1.5-1.8 under Maven 3.9.16).
# The LTS JDKs the `maven:3.9-eclipse-temurin-*` line publishes, checked against the tag list.
_MAVEN_IMAGE_JDKS = (8, 11, 17, 21)


def _javac_floor(jdk: int) -> int | None:
    """The oldest -source level ``jdk``'s javac still accepts, or None when it accepts any."""
    return next((floor for threshold, floor in _JAVAC_SOURCE_FLOOR if jdk >= threshold), None)


# The ceiling on what is recommended for old code, matching the skills/build-maven table. Not a
# compatibility floor: a project that declares 21 still gets 21.
_PREFERRED_IMAGE_JDK = 17


def maven_image_for_release(declared_release: int) -> str:
    """An allowlisted Maven image whose JDK still compiles ``declared_release``."""
    usable = [
        jdk
        for jdk in _MAVEN_IMAGE_JDKS
        if jdk >= declared_release and (_javac_floor(jdk) or 0) <= declared_release
    ]
    if not usable:
        return f"maven:3.9-eclipse-temurin-{max(_MAVEN_IMAGE_JDKS)}"
    capped = [jdk for jdk in usable if jdk <= _PREFERRED_IMAGE_JDK]
    return f"maven:3.9-eclipse-temurin-{max(capped) if capped else min(usable)}"


_IMAGE_JDK_PATTERNS = (
    re.compile(r"-jdk[-]?(\d+)"),  # gradle:8-jdk21, eclipse-temurin:17-jdk
    re.compile(r"eclipse-temurin[:-](\d+)"),  # maven:3.9-eclipse-temurin-17
    re.compile(r"\bopenjdk[:-](\d+)"),  # openjdk:11
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
    """Deterministic requirements on a test command: each catches a run that exits cleanly and
    reports nothing. Pure, so evals and tests can check it."""
    problems: list[str] = _install_violations(spec)
    command = spec.test_command or ""
    runners = command_runners(command)
    # A class selector with no runner this contract can read is still routed as JVM, as it always
    # was; next to a runner that takes a path, it is not a JVM selector and must not exempt the
    # command from that runner's checks.
    if runners & _JVM_RUNNERS or (_selects_by_class_name(command) and not runners & _PATH_RUNNERS):
        # Maven and Gradle select by *class*, so these commands carry no {test_file}; the probe's
        # class must be the one the selector names.
        if not _has_class_selector_value(command):
            exemplars = [
                exemplar
                for runner, exemplar in (("maven", MAVEN_TEST_COMMAND),
                                         ("gradle", GRADLE_TEST_COMMAND))
                if runner in runners
            ] or [MAVEN_TEST_COMMAND, GRADLE_TEST_COMMAND]
            problems.append(
                "a JVM test command must name the probe's test class in its selector, e.g. "
                + " or ".join(repr(exemplar) for exemplar in exemplars)
                + "."
            )
        elif pathish := _pathish_selector_violation(command):
            problems.append(pathish)
        return problems + _jvm_violations(command)
    if "{test_file}" not in command:
        # The harness writes the probe to the path the author chose and substitutes it here.
        # A hardcoded path means the probe file that was actually written is never run: pytest
        # reports "file or directory not found" and exits 4, having executed no test.
        problems.append(
            "test_command must contain the literal placeholder {test_file}; the harness "
            "substitutes the probe's real path into it. Replace the hardcoded test path with "
            f"{{test_file}}, e.g. {_path_runner_exemplar(runners)!r}."
        )
    if "pytest" in runners and not any(f in command for f in _PYTEST_ADDOPTS_NEUTRALISED):
        problems.append(
            f"Add `-o addopts=` to the pytest command: {PYTEST_TEST_COMMAND}. A project's own "
            "`addopts` are "
            "prepended to our invocation, and `addopts = --collect-only` makes pytest exit 0 "
            "having printed neither the markers nor the words 'collected 0 items' -- the probe "
            "silently never runs and nothing downstream can tell. `-x` and `-p no:...` do the "
            "same. Overriding costs nothing when a project sets no addopts, and if a project "
            "genuinely needs one the prepare-phase canary fails loudly instead of silently."
        )
    if "pytest" in runners and not any(flag in command for flag in _PYTEST_UNBUFFERED):
        # Without this the probe runs, passes, and prints its markers into pytest's capture
        # buffer, so the harness sees precondition_reached=false on a probe that was correct.
        problems.append(
            "a pytest test_command must disable output capture with -s (or --capture=no), "
            f"as in {PYTEST_TEST_COMMAND}, otherwise the probe's HARNESS_ markers never reach "
            "the runner and a correct probe is recorded as having reached nothing."
        )
    problems += _js_runner_violations(command)
    if "prove" in runners and not (_short_flag(command, "v") or _long_flag(command, "--verbose")):
        # prove is a TAP consumer: it parses the child's stream and reports the plan, and
        # everything that is not TAP — which is every HARNESS_ marker — is discarded unless it
        # is verbose. Same failure as an un-`-s`ed pytest, and just as invisible downstream.
        problems.append(
            f"a prove test_command must be verbose: {PROVE_TEST_COMMAND!r}. prove discards "
            "non-TAP output from the test it runs, so without -v the probe's HARNESS_ markers "
            "never reach the runner and a correct probe is recorded as having reached nothing."
        )
    return problems


def install_path_violations(spec: EnvironmentSpec) -> list[str]:
    """Install commands must write where they can, and env must point where things end up."""
    problems: list[str] = []
    installs = " ".join(spec.install_commands or [])
    if RUNTIME_HOME in installs or "/work/" in installs:
        problems.append(
            f"an install command writes under /work, which does not exist at build time: the "
            f"probe tmpfs is mounted later. Install under {BUILD_HOME}. Keep runtime references "
            "on executable artifacts: Perl XS libraries remain under /opt, while ecosystems "
            "that only read data may use the /work copy."
        )
    # cpanm as the non-root sandbox user cannot write perl's site dir. It warns, "succeeds",
    # and installs nowhere on @INC -- so the build exits 0 with the dependency absent and the
    # failure only appears inside the probe as "Can't locate X.pm". Verified against the corpus.
    installs_cpanm = _invokes(spec.install_commands or [], "cpanm")
    if installs_cpanm and not any(f in installs for f in ("--local-lib", " -l ", " -L ")):
        problems.append(
            f"a cpanm install must use --local-lib, e.g. {CPANM_INSTALL_COMMAND!r} with "
            f"env PERL5LIB={PERL5LIB_PATH}. Without it cpanm cannot write perl's "
            "site directory as the non-root sandbox user: it reports success, installs nothing "
            "importable, and the build goes green with the dependency missing."
        )
    # Maven resolves its local repository from the JVM's user.home. The sandbox user has no
    # passwd entry, so that is /root, and the build dies with
    # "mkdir: cannot create directory '/root': Permission denied". Verified against the corpus.
    if _invokes(spec.install_commands or [], "maven") and "-Dmaven.repo.local=" not in installs:
        problems.append(
            f"a Maven install must set -Dmaven.repo.local={MAVEN_BUILD_REPOSITORY}, as in "
            f"{MAVEN_INSTALL_COMMAND!r}. Maven "
            "takes its local repository from the JVM's user.home, which is /root for the "
            "sandbox user's unmapped uid, so the build fails with \"cannot create directory "
            "'/root'\" before it resolves anything."
        )
    command = spec.test_command or ""
    if _invokes(command, "maven") and "-Dmaven.repo.local=" not in command:
        problems.append(
            f"a Maven test command must set -Dmaven.repo.local={MAVEN_RUNTIME_REPOSITORY}, as "
            f"in {MAVEN_TEST_COMMAND} — the repository populated under {BUILD_HOME} at build "
            "time is copied there for the probe, and without the flag Maven looks in /root and "
            "cannot write it."
        )
    if "--local-lib" in installs or installs_cpanm:
        perl5lib = (spec.env or {}).get("PERL5LIB", "")
        if not perl5lib:
            problems.append(
                f"a cpanm install needs env PERL5LIB={PERL5LIB_PATH} so the probe "
                "can find what was installed; without it prove fails with 'Can't locate X.pm'."
            )
        elif not perl5lib.startswith((BUILD_HOME, RUNTIME_HOME)):
            problems.append(
                f"env PERL5LIB is {perl5lib!r}; point it at {PERL5LIB_PATH}. "
                f"Legacy histories using {RUNTIME_HOME}/perl5/lib/perl5 remain schema-admissible "
                "for replay, but that noexec copy cannot load XS modules and will fail the "
                "execution-backed build-repair check."
            )
    return problems


# Flags that turn "no test ran" into success, which makes a warm-up a silent no-op: Surefire
# resolves its provider only when a test executes.
_WARMUP_NO_OPS = (
    "-DfailIfNoTests=false",
    "-Dsurefire.failIfNoTests=false",
    "-DfailIfNoSpecifiedTests=false",
    "-Dsurefire.failIfNoSpecifiedTests=false",
)


# A throwaway test, written, run and removed inside one install step, so the warm-up has
# something to execute in an empty test tree. One line of Java: render_dockerfile emits each
# install command as a single `RUN`. It must be written in the project's own framework, or its
# `test-compile` fails ("cannot find symbol: class Test") and the image never builds.
def _warmup(import_line: str, declaration: str) -> str:
    return (
        f"mkdir -p src/test/java && echo '{import_line} {declaration}' > "
        "src/test/java/HarnessWarmupTest.java && "
        f"mvn -B -Dmaven.repo.local={MAVEN_BUILD_REPOSITORY} test-compile "
        "org.apache.maven.plugins:maven-surefire-plugin:3.2.5:test -Dtest=HarnessWarmupTest && "
        "rm -f src/test/java/HarnessWarmupTest.java target/test-classes/HarnessWarmupTest.class"
    )


MAVEN_WARMUP_COMMANDS: dict[str, str] = {
    # JUnit 4 wants a *public* class and a *public* method: with either left package-private the
    # JUnit4Provider reports `initializationError` and prints no markers (measured).
    "junit4": _warmup(
        "import org.junit.Test;", "public class HarnessWarmupTest { @Test public void warm() {} }"
    ),
    "junit5": _warmup(
        "import org.junit.jupiter.api.Test;", "class HarnessWarmupTest { @Test void warm() {} }"
    ),
    "testng": _warmup(
        "import org.testng.annotations.Test;",
        "public class HarnessWarmupTest { @Test public void warm() {} }",
    ),
}
# The warm-up cited when the project's test framework cannot be read.
MAVEN_WARMUP_COMMAND = MAVEN_WARMUP_COMMANDS["junit5"]

# Every whole command a retry message may tell an agent to write. Each must pass every check, or
# an agent copying it verbatim is sent into a different violation and the retries cycle;
# tests/agents/test_ecosystem_contract.py holds that.
MESSAGE_EXEMPLARS: dict[str, str] = {
    "PYTEST_TEST_COMMAND": PYTEST_TEST_COMMAND,
    "PROVE_TEST_COMMAND": PROVE_TEST_COMMAND,
    "MAVEN_TEST_COMMAND": MAVEN_TEST_COMMAND,
    "GRADLE_TEST_COMMAND": GRADLE_TEST_COMMAND,
    "JEST_TEST_COMMAND": JEST_TEST_COMMAND,
    "VITEST_TEST_COMMAND": VITEST_TEST_COMMAND,
    "MOCHA_TEST_COMMAND": MOCHA_TEST_COMMAND,
    "NODE_TEST_COMMAND": NODE_TEST_COMMAND,
    "JASMINE_TEST_COMMAND": JASMINE_TEST_COMMAND,
    "MAVEN_INSTALL_COMMAND": MAVEN_INSTALL_COMMAND,
    "CPANM_INSTALL_COMMAND": CPANM_INSTALL_COMMAND,
    **{f"MAVEN_WARMUP_COMMANDS[{name}]": command for name, command in MAVEN_WARMUP_COMMANDS.items()},
}
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

    Surefire resolves its provider lazily, at test-execution time, from the framework on the
    test classpath: a warm-up that runs no test (an empty test tree, or `-DfailIfNoTests=false`)
    fetches the plugin and never the provider, and the offline probe dies on
    `surefire-junit-platform:jar:3.2.5 ... has not been downloaded from it before`.

    ``framework`` is the repository's own test framework, when it is known. The warm-up's
    throwaway test is compiled against the project's test classpath, so a warm-up written in the
    wrong framework does not compile and the image never builds.
    """
    problems: list[str] = []
    command = spec.test_command or ""
    if not _invokes(command, "maven"):
        return problems
    wanted = MAVEN_WARMUP_COMMANDS.get(framework or "", MAVEN_WARMUP_COMMAND)
    if not _warms_the_surefire_provider(spec.install_commands):
        problems.append(
            "install_commands must include a build-time test that warms the declared "
            "Surefire provider. Keep prerequisite install commands and append this "
            f"framework-specific warm-up command: {wanted!r}. "
            "An empty test directory still requires creating, running, and removing "
            "the temporary test; an empty install_commands list cannot warm the provider."
        )
    elif framework in _FRAMEWORK_IMPORTS:
        # The warm-up runs a test; it must be written in the project's own framework.
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
                    f'"cannot find symbol: class Test" and the image never builds, which is a '
                    f"build failure in the *harness's* command rather than in the repository."
                )
                break
    return problems


# Build files whose declared language level binds the choice of JDK, read from the repository
# root and one level down.
_JAVA_BUILD_FILES = ("pom.xml", "build.gradle", "build.gradle.kts")


def js_runner_choice_violations(test_command: str, declared: list[str]) -> list[str]:
    """Reject a Node runner the repository does not have. Pure, so tests can check it.

    The offline probe container cannot fetch a missing runner (`npx canceled due to missing
    packages`, no test output). The first declared runner is the one the repository's own `test`
    script invokes, so it is the one to name.
    """
    runner = _js_runner(test_command)
    if runner is None or not declared or runner in declared:
        return []
    wanted = declared[0]
    exemplar = JS_TEST_COMMANDS.get(wanted)
    hint = (
        f" Use {exemplar}" if exemplar else f" Invoke {wanted} instead"
    ) + ", and match the selector to it."
    return [
        f"test_command invokes {runner}, which this repository does not declare; its package.json "
        f"declares {', '.join(declared)} and its own `test` script runs {wanted}.{hint} "
        f"`npx` cannot install a missing {runner} in an offline probe container — it exits "
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


def java_release(build_texts: Iterable[str]) -> int | None:
    """The oldest Java language level any of these build files declares, or None.

    The oldest binds: a JDK must still accept every level the build compiles at. This is the
    single rule for the JDK check; the stack fingerprint's ``java_release`` is meant to apply it
    to the same candidate texts so the two cannot disagree on a multi-module repository.
    """
    declared = [level for text in build_texts
                if (level := declared_java_release(text)) is not None]
    return min(declared) if declared else None


def repo_java_release(repo_path: str | None) -> int | None:
    """The repository's binding Java level; None (the JDK check stays silent) when unknown."""
    return java_release(_java_build_texts(repo_path))


def _java_build_texts(repo_path: str | None) -> list[str]:
    """The repository's own build files, root and one level down."""
    if not repo_path:
        return []
    root = Path(repo_path)
    if not root.is_dir():
        return []
    candidates = [root / name for name in _JAVA_BUILD_FILES]
    with contextlib.suppress(OSError):
        candidates += [
            child / name
            for child in sorted(root.iterdir())[:40]
            if child.is_dir()
            for name in _JAVA_BUILD_FILES
        ]
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

    The warm-up command and the probe's shape both depend on it, so it is read, never assumed.
    """
    for text in _java_build_texts(repo_path):
        framework = jvm_test_framework(text)
        if framework:
            return framework
    return None
