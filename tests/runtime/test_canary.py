"""The prepare-phase canary: a test we wrote must run here and be heard.

The smoke test proves the image starts and the runner answers `--version`. Neither proves that a
file *we* author is discovered by the project's own test command, or that its stdout reaches the
harness. Everything between — discovery rules, the provider selected, the selector syntax, a
project config that re-enables capture — was assumed, and assumed per framework.

That assumption is how a framework discrepancy becomes a false negative rather than an error:
the probe compiles, runs, prints nothing, and the case is recorded as having reached nothing.
"""
import pytest

from infosec_harness.sandbox import canary
from infosec_harness.sandbox.errors import InvalidEnvironmentSpec
from infosec_harness.sandbox.markers import PRECONDITION_PREFIX
from infosec_harness.sandbox.process import ProcessResult


def test_a_canary_exists_for_every_language_the_corpus_covers():
    for language in ("python", "java", "javascript", "perl"):
        written = canary.canary_for(language, "pytest -q -s {test_file}")
        assert written is not None, language
        path, content = written
        assert path and content
        # It must print all three markers unconditionally: it is testing the transport, not code.
        assert canary.missing_markers(content) == [], language


def test_an_unknown_language_is_not_checked_and_not_claimed_as_verified():
    """"Not checked" and "passed" must not be the same answer. A language this module has not
    learned must not fail preparation, and preparation must not report it as verified."""
    assert canary.canary_for("haskell", "cabal test") is None
    assert canary.canary_for("", "") is None


def test_the_java_canary_is_named_what_the_selector_will_look_for():
    """A JVM command selects by class, so a canary written to another name is simply not run --
    which looks exactly like the failure this gate detects, for the wrong reason."""
    path, content = canary.canary_for(
        "java", "mvn -B -o test -Dtest=MyProbeTest -Dmaven.repo.local=/work/home/.m2/repository")
    assert path == "src/test/java/MyProbeTest.java"
    assert "class MyProbeTest" in content
    _, content = canary.canary_for("java", "./gradlew test --tests '*OtherTest'")
    assert "class OtherTest" in content
    # A command that is not a JVM runner selects no class: the name the skills use.
    path, _ = canary.canary_for("java", "pytest -q -s {test_file}")
    assert path.endswith(f"{canary.DEFAULT_JVM_CLASS}.java")
    # A JVM command that selects no class is not a valid spec, so nothing is guessed for it.
    with pytest.raises(InvalidEnvironmentSpec):
        canary.canary_for("java", "mvn -B -o test")


def test_the_java_canary_has_no_package_so_every_provider_discovers_it():
    _, content = canary.canary_for("java", "mvn -B -o test -Dtest=HarnessProbeTest")
    assert "package " not in content, "a package must match its directory; default package is safer"


def test_swallowed_output_is_reported_as_missing_markers():
    """The exact false negative: the test ran and exited 0, and nothing was heard."""
    assert canary.missing_markers("") == ["precondition", "sink_returned", "oracle"]
    partial = f"{PRECONDITION_PREFIX}{canary.CANARY_NONCE}\n"
    assert canary.missing_markers(partial) == ["sink_returned", "oracle"]


def test_a_probes_nonce_is_never_mistaken_for_the_canarys():
    """The canary proves the transport and must never be read as evidence about a vulnerability."""
    other = "HARNESS_PRECONDITION::abc123\nHARNESS_SINK_RETURNED::abc123\nHARNESS_ORACLE::abc123"
    assert canary.missing_markers(other) == ["precondition", "sink_returned", "oracle"]


def test_negative_control_has_no_oracle_and_control_records_are_versioned():
    _, content = canary.canary_for(
        "python", "pytest -q -s {test_file}", nonce=canary.NEGATIVE_CANARY_NONCE,
        oracle=False,
    )
    assert f"HARNESS_PRECONDITION::{canary.NEGATIVE_CANARY_NONCE}" in content
    assert f"HARNESS_SINK_RETURNED::{canary.NEGATIVE_CANARY_NONCE}" in content
    assert "HARNESS_ORACLE::" not in content
    encoded = canary.encode_control_result(canary.ControlResult(positive=True, negative=True))
    decoded = canary.parse_control_result("runner output\n" + encoded)
    assert decoded is not None and decoded.passed
    assert canary.parse_control_result("old workflow output") is None


def test_the_explanation_blames_the_environment_rather_than_a_probe():
    """Build repair can act on this; probe repair cannot, and sending it there wastes the whole
    repair budget on a probe that was never the problem."""
    message = canary.explain("java", "mvn -B -o test -Dtest=X", ["precondition"], "BUILD FAILURE")
    assert "environment spec" in message
    assert "not in any probe" in message
    assert "false negative" in message


async def test_the_smoke_test_fails_when_the_canary_is_not_heard(monkeypatch):
    """End to end through the smoke workload: a runner that answers --version but reports nothing."""
    from infosec_harness.graph.workloads import smoke_test
    from infosec_harness.sandbox import docker

    async def ok_shell(image, command, *, timeout=None, **_ignored):
        return ProcessResult(exit_code=0, stdout="harness-smoke-ok\npytest 8.0.0",
                                 stderr="", timed_out=False, duration_s=0.0)

    async def silent_probe(image, path, content, test_command, nonce, module_path=""):
        # Exit 0, no markers: the shape a framework mismatch actually produces.
        return ProcessResult(exit_code=0, stdout="1 passed", stderr="",
                                 timed_out=False, duration_s=0.1)

    monkeypatch.setattr(docker, "run_shell", ok_shell, raising=True)
    monkeypatch.setattr(docker, "run_probe", silent_probe, raising=True)
    result = await smoke_test("img", "pytest -q -s {test_file}", language="python")
    assert not result.ok, "a runner that reports nothing must fail preparation"
    assert "did not reach stdout" in result.output_excerpt


async def test_the_smoke_test_passes_when_the_canary_is_heard(monkeypatch):
    from infosec_harness.graph.workloads import smoke_test
    from infosec_harness.sandbox import canary as canary_mod
    from infosec_harness.sandbox import docker

    async def ok_shell(image, command, *, timeout=None, **_ignored):
        return ProcessResult(exit_code=0, stdout="harness-smoke-ok\npytest 8.0.0",
                                 stderr="", timed_out=False, duration_s=0.0)

    async def heard_probe(image, path, content, test_command, nonce, module_path=""):
        out = f"HARNESS_PRECONDITION::{nonce}\nHARNESS_SINK_RETURNED::{nonce}\n"
        if nonce == canary_mod.CANARY_NONCE:
            out += f"HARNESS_ORACLE::{nonce}\n"
        return ProcessResult(exit_code=0, stdout=out, stderr="", timed_out=False, duration_s=0.1)

    monkeypatch.setattr(docker, "run_shell", ok_shell, raising=True)
    monkeypatch.setattr(docker, "run_probe", heard_probe, raising=True)
    result = await smoke_test("img", "pytest -q -s {test_file}", language="python")
    assert result.ok
    assert "canary positive and negative controls observed" in result.output_excerpt
    controls = canary_mod.parse_control_result(result.output_excerpt)
    assert controls is not None and controls.passed


@pytest.mark.parametrize("language", ["python", "perl", "javascript", "java"])
def test_each_canary_is_syntactically_plausible_for_its_language(language):
    _, content = canary.canary_for(language, "mvn -B -o test -Dtest=HarnessProbeTest")
    if language == "python":
        compile(content, "canary.py", "exec")  # real parse, not a guess
    elif language == "perl":
        assert "use Test::More" in content and "done_testing" not in content
        assert "tests => 1" in content, "prove needs a plan or it reports a bad plan"
    elif language == "javascript":
        assert content.count("console.log") == 3 and content.strip().endswith("});")
    else:
        assert content.count("System.out.println") == 3 and content.rstrip().endswith("}")
