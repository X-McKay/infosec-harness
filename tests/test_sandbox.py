from infosec_harness.domain.models import EnvironmentSpec
from infosec_harness.sandbox import docker


def _spec(**kw):
    return EnvironmentSpec(base_image="python:3.12-slim", install_commands=["pip install -e ."],
                           test_command="python -m pytest -q -s {test_file}", **kw)


def test_dockerfile_is_deterministic_and_nonroot():
    df = docker.render_dockerfile(_spec(system_packages=["gcc"]))
    assert df == docker.render_dockerfile(_spec(system_packages=["gcc"]))
    assert f"USER {docker.SANDBOX_USER}" in df
    assert "COPY --chown" in df


def test_partial_scope_sets_module_workdir():
    df = docker.render_dockerfile(_spec(scope="partial", module_path="services/api"))
    assert "WORKDIR /opt/repo/services/api" in df


def test_oracle_signals_match_nonce():
    n = "abc123"
    assert docker.oracle_signals(f"{docker.ORACLE_PREFIX}{n}", n) == (True, True)
    assert docker.oracle_signals(f"{docker.PRECONDITION_PREFIX}{n}", n) == (False, True)
    assert docker.oracle_signals("nothing", n) == (False, False)
    assert docker.oracle_signals(f"{docker.ORACLE_PREFIX}other", n) == (False, False)


def test_image_tag_changes_with_spec():
    t1 = docker.image_tag_for("repohash", _spec())
    t2 = docker.image_tag_for("repohash", _spec(system_packages=["gcc"]))
    assert t1 != t2


# --- The smoke test must smoke-test the thing that matters --------------------------------

def test_a_known_runner_gets_a_real_installation_check():
    """`echo` proves a shell starts, not that the test runner exists.

    Observed live: a build that omitted pytest passed the smoke test, and the absence surfaced
    at probe time as exit 127 "pytest: not found". probe_diagnosis correctly called it an
    environment issue, but by then the graph is past build repair — the only stage that could
    have fixed it.
    """
    from infosec_harness.sandbox.docker import runner_check_command

    assert runner_check_command("python -m pytest -q -s {test_file}") == "python -m pytest --version"
    assert runner_check_command("prove -v {test_file}") == "prove --version"
    assert runner_check_command("mvn -q -B test -Dtest=HarnessProbeTest") == "mvn -v"
    assert "jest" in (runner_check_command("npx jest --runTestsByPath {test_file}") or "")


def test_an_unrecognised_runner_does_not_fail_preparation():
    """A command this table has not learned must not be treated as a broken environment."""
    from infosec_harness.sandbox.docker import runner_check_command

    for command in ("sh {test_file}", "./run-my-tests {test_file}", ""):
        assert runner_check_command(command) is None


async def test_smoke_test_fails_when_the_runner_is_missing(monkeypatch):
    from infosec_harness.sandbox import docker
    from infosec_harness.workflows.activities import smoke_test_activity

    calls = []

    async def fake_shell(image, command, *, network, timeout=None):
        calls.append(command)
        if "harness-smoke-ok" in command:
            return docker.ProcResult(exit_code=0, stdout="harness-smoke-ok\n", stderr="",
                                     timed_out=False, duration_s=0.1)
        return docker.ProcResult(exit_code=127, stdout="", stderr="pytest: not found",
                                 timed_out=False, duration_s=0.1)

    monkeypatch.setattr(docker, "run_shell", fake_shell, raising=True)
    result = await smoke_test_activity({"image_tag": "img",
                                        "test_command": "python -m pytest -q -s {test_file}"})
    assert result.ok is False
    assert "test runner is not installed" in result.output_excerpt
    assert any("--version" in c for c in calls), "the runner was never actually invoked"


async def test_smoke_test_passes_when_the_runner_answers(monkeypatch):
    from infosec_harness.sandbox import docker
    from infosec_harness.workflows.activities import smoke_test_activity

    async def fake_shell(image, command, *, network, timeout=None):
        out = "harness-smoke-ok\n" if "harness-smoke-ok" in command else "pytest 9.1.1\n"
        return docker.ProcResult(exit_code=0, stdout=out, stderr="", timed_out=False,
                                 duration_s=0.1)

    monkeypatch.setattr(docker, "run_shell", fake_shell, raising=True)
    result = await smoke_test_activity({"image_tag": "img",
                                        "test_command": "python -m pytest -q -s {test_file}"})
    assert result.ok is True


async def test_a_bare_image_tag_still_works(monkeypatch):
    """Recorded workflow histories pass the tag alone; replay must not break."""
    from infosec_harness.sandbox import docker
    from infosec_harness.workflows.activities import smoke_test_activity

    async def fake_shell(image, command, *, network, timeout=None):
        return docker.ProcResult(exit_code=0, stdout="harness-smoke-ok\n", stderr="",
                                 timed_out=False, duration_s=0.1)

    monkeypatch.setattr(docker, "run_shell", fake_shell, raising=True)
    assert (await smoke_test_activity("img")).ok is True


# Captured from a real `prove -v` run on a probe whose test file emitted a zero-test plan and
# then died: this is verbatim what the harness saw on perl-cmdi-vulnerable, empty stderr and all.
PROVE_ZERO_TESTS = """t/injection_os_command_runner.t .. skipped: (no reason given)

Test Summary Report
-------------------
t/injection_os_command_runner.t (Wstat: 65280 Tests: 0 Failed: 0)
  Non-zero exit status: 255
Files=1, Tests=0,  0 wallclock secs
Result: FAIL
"""


def test_a_zero_test_run_is_named_not_left_to_be_inferred():
    reason = docker.no_tests_executed(PROVE_ZERO_TESTS)
    assert reason is not None, "prove's own zero-plan phrasing must be recognised"
    assert "zero-test plan" in reason
    # The point of the field: say outright that this is not evidence of non-exploitability.
    assert "not a negative result" in reason


def test_a_probe_that_really_ran_reports_no_zero_test_signature():
    nonce = "n0nce"
    ran = (f"t/x.t .. ok\n{docker.PRECONDITION_PREFIX}{nonce}\n"
           f"{docker.SINK_RETURNED_PREFIX}{nonce}\nFiles=1, Tests=2\nResult: PASS\n")
    assert docker.no_tests_executed(ran) is None


def test_every_supported_runner_has_a_zero_test_signature():
    """Each runner the harness can drive must be recognisable when it runs nothing.

    Without this the gap is silent: a new runner's zero-test output falls through and the
    diagnosis agent goes back to guessing from the exit code.
    """
    samples = {
        "prove": "t/x.t .. skipped: (no reason given)\nResult: FAIL\n",
        "pytest": "collected 0 items\n\nno tests ran in 0.01s\n",
        "surefire": "[INFO] Tests run: 0, Failures: 0, Errors: 0, Skipped: 0\n",
        "jest": "No tests found, exiting with code 1\n",
        # Captured verbatim from real runs. None of these contains any phrase the jest/pytest/
        # prove/surefire signatures match, so before they were added a zero-test run under any
        # of the three fell through as "the probe ran and observed nothing".
        "vitest (no suite in file)": (
            " FAIL  empty.test.js [ empty.test.js ]\n"
            "Error: No test suite found in file /work/empty.test.js\n"),
        "vitest (no file matched)": "filter:  missing.test.js\n\nNo test files found, exiting with code 1\n",
        "mocha": "\n\n  0 passing (0ms)\n  1 pending\n",
        "node:test": ("TAP version 13\n# Subtest: harness probe\nok 1 - harness probe # SKIP\n"
                      "1..1\n# tests 1\n# suites 0\n# pass 0\n# fail 0\n# skipped 1\n"),
    }
    for runner, output in samples.items():
        assert docker.no_tests_executed(output) is not None, f"{runner} zero-test run unrecognised"


def test_a_healthy_mocha_run_is_not_read_as_a_zero_test_run():
    """`"0 passing" in output` is TRUE for "10 passing" — measured, and the reason the mocha
    signature is a pattern with a digit boundary rather than a substring. Reporting a ten-test
    run as having executed nothing would turn a real positive into a probe defect."""
    for count in (1, 5, 10, 20, 100, 1000):
        output = f"\n  {count} passing (3ms)\n"
        assert docker.no_tests_executed(output) is None, output


def test_a_healthy_node_test_run_is_not_read_as_a_zero_test_run():
    """`# pass 0` must not match `# pass 10`, and a real pass must stay a real pass."""
    for count in (1, 10, 20, 100):
        output = (f"TAP version 13\nok 1 - harness probe\n1..1\n# tests {count}\n"
                  f"# pass {count}\n# fail 0\n")
        assert docker.no_tests_executed(output) is None, output


def test_the_node_runners_that_were_unsmoke_testable_now_have_checks():
    """mocha, tsx and node's own runner fell through to the trivial shell check, so an absent
    runner surfaced at probe time (exit 1, `npx canceled due to missing packages`, no test
    output) where probe repair is handed a correct probe and build repair never sees a failure.
    """
    from infosec_harness.sandbox.docker import runner_check_command

    assert "mocha" in (runner_check_command("npx mocha {test_file}") or "")
    assert "tsx" in (runner_check_command("npx tsx --test {test_file}") or "")
    assert runner_check_command("node --test {test_file}") == "node --version"
    assert "vitest" in (runner_check_command("npx vitest run --silent=false {test_file}") or "")
