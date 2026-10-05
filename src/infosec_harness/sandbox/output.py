"""Deterministic readings of untrusted runner output: markers, zero-test runs, runner checks.

Everything here is pure. Marker text is self-reported by the probe, so these functions classify
what the output says; they never upgrade it into controller evidence (see ``evidence``).
"""

from __future__ import annotations

import re

from infosec_harness.sandbox.markers import (
    CANARY_PREFIX,
    ORACLE_PREFIX,
    PRECONDITION_PREFIX,
    SINK_RETURNED_PREFIX,
)


def _oracle_fired(output: str, nonce: str) -> bool:
    return f"{ORACLE_PREFIX}{nonce}" in output or f"{CANARY_PREFIX}{nonce}" in output


def oracle_signals(output: str, nonce: str) -> tuple[bool, bool]:
    """Deterministic oracle detection: (oracle_fired, precondition_reached)."""
    fired = _oracle_fired(output, nonce)
    return fired, fired or f"{PRECONDITION_PREFIX}{nonce}" in output


def sink_returned(output: str, nonce: str) -> bool:
    """Whether the sink call completed, as distinct from the probe having reached it.

    A fired oracle implies it: the exploit condition cannot be observed without the call
    having produced something to observe.
    """
    return f"{SINK_RETURNED_PREFIX}{nonce}" in output or _oracle_fired(output, nonce)


# How to ask each known test runner whether it is actually installed. Keyed on the token that
# identifies the runner inside a test command. A runner absent from this table falls back to the
# trivial shell check, so an unfamiliar command can never fail preparation spuriously.
_RUNNER_VERSION_CHECKS: tuple[tuple[str, str], ...] = (
    ("python -m pytest", "python -m pytest --version"),
    ("pytest", "pytest --version"),
    ("npx jest", "npx --no-install jest --version"),
    ("jest", "jest --version"),
    ("npx vitest", "npx --no-install vitest --version"),
    # mocha, tsx and node's own runner were missing, so a spec naming any of them got the trivial
    # shell check and an absent runner surfaced at probe time as `npx canceled due to missing
    # packages` — exit 1, no test output, routed to probe repair, which cannot install anything.
    ("npx mocha", "npx --no-install mocha --version"),
    ("mocha", "mocha --version"),
    ("npx tsx", "npx --no-install tsx --version"),
    ("node --test", "node --version"),
    ("prove", "prove --version"),
    ("mvn", "mvn -v"),
    ("gradlew", "./gradlew --offline --version"),
    ("gradle", "gradle --version"),
)


def runner_check_command(test_command: str) -> str | None:
    """A command that proves the test runner in ``test_command`` is installed and invocable.

    The smoke test previously ran `echo`, which proves only that the image starts a shell. A
    missing runner therefore surfaced at *probe* time as exit 127, where the graph routes to
    probe repair — powerless, because the fault is in the environment. Checking it during
    preparation puts the failure where build repair can act on it.

    Returns None for a runner we do not recognise, so preparation is never failed by a command
    this table simply has not learned.
    """
    command = (test_command or "").strip()
    for token, check in _RUNNER_VERSION_CHECKS:
        if token in command:
            return check
    return None


# A runner that executed *no test at all* is categorically different from one that ran the
# probe and saw the oracle stay silent -- the first is a probe defect, the second is evidence.
# Both leave the three markers unprinted, so without naming the difference the diagnosis agent
# has to guess from a bare exit code. Measured: perl-cmdi-vulnerable produced
# `t/...t .. skipped: (no reason given)` with exit 255 and an EMPTY stderr; the agent guessed
# "file not written correctly", repaired the wrong thing, and burned its whole repair budget to
# `inconclusive` on a case that is genuinely exploitable. Each signature below is a phrase the
# runner itself prints when it ran zero tests; they are quoted verbatim from real output.
_NO_TESTS_SIGNATURES: tuple[tuple[str, str], ...] = (
    # prove / TAP::Harness. "skipped: (no reason given)" is a `1..0` plan with no SKIP
    # directive; "Result: NOTESTS" is prove's own summary for the same thing.
    ("skipped: (no reason given)", "prove: the test file emitted a zero-test plan (1..0)"),
    ("Result: NOTESTS", "prove: no tests were run"),
    ("you planned 1 tests but ran 0", "prove: the plan promised tests that never ran"),
    # pytest
    ("no tests ran", "pytest: no tests ran"),
    ("collected 0 items", "pytest: collected 0 items"),
    # Maven Surefire. The "matching pattern" wording is the one that actually showed up, on
    # java-sqli-fixed: a selector handed a file path instead of a class name matches nothing.
    ("Tests run: 0", "surefire: ran 0 tests"),
    ("No tests to run", "surefire: found no tests to run"),
    ("No tests matching pattern", "surefire: the -Dtest selector matched no test class"),
    ("No tests were executed", "surefire: no tests were executed"),
    # A pom that configures maven-surefire-plugin with <skipTests>true</skipTests> at plugin
    # level. `-DskipTests=false` does not override an explicit plugin configuration (measured),
    # so the probe run exits 0 having executed nothing and written no reports at all. Named here
    # because the cause is the repository's build, not the probe: without this the diagnosis has
    # only a clean exit and no markers to go on, and repair rewrites a correct probe.
    ("Tests are skipped.", "surefire: the build itself skipped the tests -- the pom configures "
                           "maven-surefire-plugin with <skipTests>true</skipTests>, which "
                           "-DskipTests=false cannot override"),
    # Jest
    ("No tests found", "jest: found no test files"),
    ("Tests:       0 total", "jest: ran 0 tests"),
    # Vitest. Measured on real fixtures: a file with no `test()` in it is a *failed suite*, not
    # an empty one, and a path vitest cannot match is a different message again. Neither says
    # "no tests found", which is why jest's wording caught nothing here.
    ("No test suite found in file", "vitest: the file declared no test suite"),
    ("No test files found", "vitest: matched no test file"),
)
# Signatures that need a boundary a substring cannot express. mocha's summary is "  0 passing",
# and `"0 passing" in output` is TRUE for a ten-test run ("10 passing") -- measured -- which would
# report a healthy run as having executed nothing. node:test prints its own counters as TAP
# comments; `# pass 0` with `# fail 0` is a run in which every test was skipped or filtered out,
# which is exactly the zero-test shape (`node --test` has no "no tests" message of its own).
_NO_TESTS_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?<!\d)0 passing"), "mocha: 0 passing"),
    (re.compile(r"^# pass 0$", re.M), "node:test: every test was skipped or filtered out"),
)


def no_tests_executed(output: str) -> str | None:
    """Name the runner's own evidence that it executed zero tests, or None.

    Pure and deterministic, so the diagnosis agent is told *what happened* instead of inferring
    it from an exit code. A zero-test run is never a negative result: nothing exercised the
    sink, so it says nothing about exploitability. Callers put the returned phrase on
    `ProbeExecution.runner_reported_no_tests`, which is serialised into the diagnosis, repair,
    and verdict prompts.
    """
    matched: tuple[str, str] | None = None
    for signature, reason in _NO_TESTS_SIGNATURES:
        if signature in output:
            matched = (reason, signature)
            break
    else:
        for pattern, reason in _NO_TESTS_PATTERNS:
            if match := pattern.search(output):
                matched = (reason, match.group(0))
                break
    if matched is None:
        return None
    reason, evidence = matched
    return f"{reason} (matched {evidence!r}). Zero tests ran, so this is not a negative result."


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def tail(text: str, limit: int = 4000) -> str:
    """The last ``limit`` characters of ``text`` with terminal escape sequences removed."""
    return _ANSI.sub("", text)[-limit:]
