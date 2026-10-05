import pytest

from infosec_harness.agents.validators import verdict_violations
from infosec_harness.domain.models import (
    CodeRef,
    DiagnosisKind,
    InconclusiveReason,
    Reachability,
    Verdict,
    VerdictFacts,
    VerdictLabel,
)


def v(label, **kw):
    return Verdict(label=label, confidence=0.8, rationale="r", **kw)


@pytest.mark.parametrize("label", [VerdictLabel.potentially_exploitable,
                                   VerdictLabel.likely_not_exploitable])
def test_a_verdict_with_no_recorded_facts_may_only_be_inconclusive(label):
    """Regression: with `deps.facts` absent the validator returned the output unchecked, so a
    positive or negative claim corroborated by nothing was accepted, while the offered output
    tools (`outputs.allowed_verdict_labels`) already reduced that case to inconclusive."""
    from types import SimpleNamespace

    from pydantic_ai import ModelRetry

    from infosec_harness.agents.validators import NO_FACTS_VIOLATION, validate_verdict

    ctx = SimpleNamespace(deps=SimpleNamespace(facts=None))
    with pytest.raises(ModelRetry) as error:
        validate_verdict(ctx, v(label))
    assert NO_FACTS_VIOLATION in error.value.message
    inconclusive = v(VerdictLabel.inconclusive,
                     inconclusive_reason=InconclusiveReason.conflicting_evidence)
    assert validate_verdict(ctx, inconclusive) is inconclusive


def test_the_no_facts_rule_matches_the_offered_tools():
    from infosec_harness.agents.outputs import allowed_verdict_labels

    assert allowed_verdict_labels(None) == {VerdictLabel.inconclusive}


def test_exploitable_requires_oracle():
    facts = VerdictFacts(environment_ready=True, oracle_fired=False)
    assert verdict_violations(v(VerdictLabel.potentially_exploitable), facts)


def test_exploitable_valid_positive_ok():
    facts = VerdictFacts(environment_ready=True, oracle_fired=True, precondition_reached=True,
                         last_diagnosis=DiagnosisKind.valid_positive)
    assert verdict_violations(v(VerdictLabel.potentially_exploitable), facts) == []


def test_not_exploitable_needs_a_complete_valid_negative():
    facts = VerdictFacts(environment_ready=True, oracle_fired=False, precondition_reached=False)
    assert verdict_violations(v(VerdictLabel.likely_not_exploitable), facts)
    facts_ok = VerdictFacts(
        environment_ready=True,
        oracle_fired=False,
        precondition_reached=True,
        sink_returned=True,
        last_diagnosis=DiagnosisKind.valid_negative,
    )
    assert verdict_violations(v(VerdictLabel.likely_not_exploitable), facts_ok) == []

    did_not_return = facts_ok.model_copy(update={"sink_returned": False})
    assert verdict_violations(v(VerdictLabel.likely_not_exploitable), did_not_return)


def test_static_unreachable_is_not_a_negative_execution():
    facts = VerdictFacts(environment_ready=False, reachability=Reachability.unreachable)
    assert verdict_violations(v(VerdictLabel.likely_not_exploitable), facts)  # no evidence
    assert verdict_violations(
        v(VerdictLabel.likely_not_exploitable, evidence=[CodeRef(file_path="a", start_line=1, end_line=2)]),
        facts)


def test_inconclusive_needs_reason_and_env_rule():
    facts = VerdictFacts(environment_ready=False)
    assert verdict_violations(v(VerdictLabel.inconclusive), facts)  # missing reason
    assert verdict_violations(
        v(VerdictLabel.inconclusive, inconclusive_reason=InconclusiveReason.conflicting_evidence),
        facts)  # wrong reason for no-env
    assert verdict_violations(
        v(VerdictLabel.inconclusive, inconclusive_reason=InconclusiveReason.environment_unbuildable),
        facts) == []


# --- Double-encoded nested objects in tool calls (domain/models.py) ---

def test_nested_object_arriving_as_a_json_string_is_decoded():
    """Models often emit a single nested object as a JSON string; accept it."""
    import json

    from infosec_harness.domain.models import FindingContext

    ctx = FindingContext.model_validate({
        "summary": "sqli", "reachability": "reachable", "reachability_rationale": "r",
        "sink": json.dumps({"file_path": "app.py", "start_line": 16, "end_line": 16}),
        "path": [{"file_path": "app.py", "start_line": 13, "end_line": 13}],
    })
    assert ctx.sink is not None and ctx.sink.file_path == "app.py" and ctx.sink.start_line == 16
    assert [p.start_line for p in ctx.path] == [13]


def test_a_string_that_is_not_an_object_is_still_rejected():
    """The coercion widens acceptance; it must not turn bad data into a silent default."""
    import pytest
    from pydantic import ValidationError

    from infosec_harness.domain.models import FindingContext

    for bad in ("not json at all", "[1, 2, 3]", '"just a string"', "42"):
        with pytest.raises(ValidationError):
            FindingContext.model_validate({
                "summary": "s", "reachability": "reachable",
                "reachability_rationale": "r", "sink": bad,
            })


def test_well_formed_nested_objects_are_untouched():
    from infosec_harness.domain.models import FindingContext

    payload = {
        "summary": "s", "reachability": "reachable", "reachability_rationale": "r",
        "sink": {"file_path": "a.py", "start_line": 1, "end_line": 2, "note": "n"},
    }
    ctx = FindingContext.model_validate(payload)
    assert ctx.sink is not None and ctx.sink.note == "n"


def test_coercion_applies_to_every_nested_object_field():
    """Not just `sink` — any singular nested model on an agent output type."""
    import json

    from infosec_harness.domain.models import FindingContext

    ref = {"file_path": "a.py", "start_line": 1, "end_line": 1}
    ctx = FindingContext.model_validate({
        "summary": "s", "reachability": "reachable", "reachability_rationale": "r",
        "source": json.dumps(ref), "sink": json.dumps(ref),
    })
    assert ctx.source is not None and ctx.sink is not None


# --- The environment spec must be able to run a probe at all -----------------------------

def test_a_hardcoded_test_path_is_rejected():
    """The harness substitutes {test_file}; a hardcoded path runs a file that does not exist.

    Observed live: env-planner emitted `python -m pytest -q -s tests/test_app.py`, pytest
    exited 4 with "file or directory not found", no test executed, and the finding was scored
    inconclusive. Nothing downstream can diagnose this — the probe itself is fine.
    """
    from infosec_harness.agents.ecosystem_contract import environment_spec_violations
    from infosec_harness.domain.models import EnvironmentSpec

    spec = EnvironmentSpec(base_image="python:3.12-slim",
                           test_command="python -m pytest -q -s tests/test_app.py")
    problems = environment_spec_violations(spec)
    assert any("{test_file}" in p for p in problems)


def test_a_pytest_command_that_captures_output_is_rejected():
    """Without -s the markers land in pytest's capture buffer, never in the runner's stdout.

    The probe then passes, exits 0, and is recorded as having reached nothing — which
    probe_diagnosis correctly calls a defect and probe_repair cannot fix, because the fault
    is in the test command.
    """
    from infosec_harness.agents.ecosystem_contract import environment_spec_violations
    from infosec_harness.domain.models import EnvironmentSpec

    captured = EnvironmentSpec(base_image="python:3.12-slim",
                              test_command="python -m pytest -q {test_file}")
    assert any("-s" in p for p in environment_spec_violations(captured))
    # A clean pytest command also has to neutralise the project's own addopts, which can make
    # pytest exit 0 without running the probe; see the addopts test below.
    for ok in ("python -m pytest -q -s -o addopts= {test_file}",
               "python -m pytest --capture=no -o addopts= {test_file}"):
        spec = EnvironmentSpec(base_image="python:3.12-slim", test_command=ok)
        assert environment_spec_violations(spec) == [], ok


def test_non_pytest_runners_are_not_held_to_pytests_flag():
    """Only invent a requirement where it is real.

    This test used to assert that no Node runner needed a flag of its own, on the stated grounds
    that "jest does not capture as pytest does". Measured on real fixtures under node 18/20/22,
    that is only true of mocha and node's own runner. jest and vitest both replace the test's
    console when the *project's* config says `silent: true`, and the run then exits 0 having
    printed none of the three markers — so the two halves are asserted separately now.
    """
    from infosec_harness.agents.ecosystem_contract import environment_spec_violations
    from infosec_harness.domain.models import EnvironmentSpec

    for command in ("npx mocha {test_file}", "node --test {test_file}",
                    "npx tsx --test {test_file}"):
        spec = EnvironmentSpec(base_image="node:22-slim", test_command=command)
        assert environment_spec_violations(spec) == [], command


def test_a_jest_or_vitest_command_a_project_config_can_mute_is_rejected():
    """The Node equivalent of an un-`-s`ed pytest, and the costliest shape there is.

    Measured: a fixture whose `jest.config.js` carries `silent: true` ran the probe, exited 0,
    and printed none of HARNESS_PRECONDITION / HARNESS_SINK_RETURNED / HARNESS_ORACLE; the same
    holds for `vitest.config.js`. `--silent=false` restored all three, and is a no-op when the
    project silences nothing, so the rejection names it as the correction.
    """
    from infosec_harness.agents.ecosystem_contract import (
        JEST_TEST_COMMAND,
        VITEST_TEST_COMMAND,
        environment_spec_violations,
    )
    from infosec_harness.domain.models import EnvironmentSpec

    for muted in ("npx jest --runTestsByPath {test_file}", "npx vitest run {test_file}",
                  "npx jest --silent --runTestsByPath {test_file}"):
        spec = EnvironmentSpec(base_image="node:22-slim", test_command=muted)
        problems = environment_spec_violations(spec)
        assert any("--silent=false" in p for p in problems), muted
    for ok in (JEST_TEST_COMMAND, VITEST_TEST_COMMAND):
        spec = EnvironmentSpec(base_image="node:22-slim", test_command=ok)
        assert environment_spec_violations(spec) == [], ok


def test_vitest_given_jests_selector_is_rejected_with_the_command_that_works():
    """`npx vitest run --runTestsByPath <path>` dies in vitest's own argument parser.

    Measured: it exits 1 with a CAC stack trace, before loading a single test file, so there is
    no test output at all to diagnose from — a run that looks like a probe defect and is not one.
    """
    from infosec_harness.agents.ecosystem_contract import (
        VITEST_TEST_COMMAND,
        environment_spec_violations,
    )
    from infosec_harness.domain.models import EnvironmentSpec

    spec = EnvironmentSpec(base_image="node:22-slim",
                          test_command="npx vitest run --silent=false --runTestsByPath {test_file}")
    problems = environment_spec_violations(spec)
    assert any(VITEST_TEST_COMMAND in p for p in problems), problems
    # jest is the runner the flag belongs to, so it must not be rejected for carrying it.
    ok = EnvironmentSpec(base_image="node:22-slim",
                        test_command="npx jest --silent=false --runTestsByPath {test_file}")
    assert environment_spec_violations(ok) == []


def test_a_runner_the_repository_does_not_declare_is_rejected(tmp_path):
    """`npx jest` in a vitest-only project cannot fall back to anything in an offline container.

    Measured: `npx --no-install jest --runTestsByPath probe.test.js` in a vitest-only fixture
    exits 1 with `npx canceled due to missing packages` and no test output whatsoever, which
    reads as a probe defect and routes repair to the one stage that cannot install a runner.
    """
    from infosec_harness.agents.ecosystem_contract import (
        js_runner_choice_violations,
        repo_js_runners,
    )

    (tmp_path / "package.json").write_text(
        '{"name":"v","scripts":{"test":"vitest run"},"devDependencies":{"vitest":"^2"}}')
    declared = repo_js_runners(str(tmp_path))
    assert declared == ["vitest"], declared

    problems = js_runner_choice_violations("npx jest --silent=false --runTestsByPath {test_file}",
                                           declared)
    assert problems and "vitest" in problems[0] and "npx canceled" in problems[0]
    assert js_runner_choice_violations("npx vitest run --silent=false {test_file}", declared) == []
    # No package.json, or a runner the repo does declare: the check stays silent rather than guess.
    assert js_runner_choice_violations("npx jest --runTestsByPath {test_file}", []) == []


def test_a_migration_that_carries_both_runners_names_the_one_its_test_script_invokes(tmp_path):
    """jest and vitest side by side in devDependencies is the case the skill warns about.

    `test_frameworks[0]` is what recon reports and what the env plan builds its command from, so
    the ordering is load-bearing: alphabetical order would answer "jest" for a project that has
    already migrated to vitest.
    """
    from infosec_harness.agents.ecosystem_contract import (
        js_runner_choice_violations,
        repo_js_runners,
    )

    (tmp_path / "package.json").write_text(
        '{"name":"m","scripts":{"test":"vitest run"},'
        '"devDependencies":{"jest":"^29","vitest":"^2"}}')
    declared = repo_js_runners(str(tmp_path))
    assert declared[0] == "vitest", declared
    # Both are installed, so neither invocation is *missing* a runner: this check must not fire.
    assert js_runner_choice_violations("npx jest --silent=false --runTestsByPath {test_file}",
                                       declared) == []


def test_the_environment_agents_all_carry_the_contract():
    """A spec from any of the three build agents reaches run_probe, so all three are bound."""
    from infosec_harness.agents.registry import BINDINGS
    from infosec_harness.agents.validators import validate_environment_spec

    for agent in ("env-planner", "build-repair", "partial-build"):
        assert validate_environment_spec in BINDINGS[agent].validators, agent


def test_partial_build_adds_its_scope_contract_without_changing_other_agents():
    from infosec_harness.agents.registry import BINDINGS
    from infosec_harness.agents.validators import (
        validate_environment_spec,
        validate_partial_build_scope,
    )

    assert BINDINGS["env-planner"].validators == (validate_environment_spec,)
    assert BINDINGS["build-repair"].validators == (validate_environment_spec,)
    assert BINDINGS["partial-build"].validators == (
        validate_environment_spec,
        validate_partial_build_scope,
    )


def test_partial_build_rejects_the_shared_full_scope_default():
    from pydantic_ai import ModelRetry

    from infosec_harness.agents.validators import validate_partial_build_scope
    from infosec_harness.domain.models import EnvironmentSpec

    spec = EnvironmentSpec(
        base_image="python:3.12-slim",
        test_command="python -m pytest -q -s -o addopts= {test_file}",
    )
    with pytest.raises(ModelRetry, match="scope.*partial"):
        validate_partial_build_scope(None, spec)


@pytest.mark.parametrize("module_path", [None, "", "   "])
def test_partial_build_rejects_missing_or_blank_module_path(module_path):
    from pydantic_ai import ModelRetry

    from infosec_harness.agents.validators import validate_partial_build_scope
    from infosec_harness.domain.models import EnvironmentSpec

    spec = EnvironmentSpec(
        base_image="python:3.12-slim",
        test_command="python -m pytest -q -s -o addopts= {test_file}",
        scope="partial",
        module_path=module_path,
    )
    with pytest.raises(ModelRetry, match="module_path"):
        validate_partial_build_scope(None, spec)


@pytest.mark.parametrize("module_path", [".", "services/api"])
def test_partial_build_accepts_root_or_named_module(module_path):
    from infosec_harness.agents.validators import validate_partial_build_scope
    from infosec_harness.domain.models import EnvironmentSpec

    spec = EnvironmentSpec(
        base_image="python:3.12-slim",
        test_command="python -m pytest -q -s -o addopts= {test_file}",
        scope="partial",
        module_path=module_path,
    )
    assert validate_partial_build_scope(None, spec) is spec


def test_the_retry_message_names_the_fix_rather_than_the_violation():
    """A retry the model cannot act on just burns the budget (cf. verdict's inconclusive_reason)."""
    from infosec_harness.agents.ecosystem_contract import (
        PYTEST_TEST_COMMAND,
        environment_spec_violations,
    )
    from infosec_harness.domain.models import EnvironmentSpec

    spec = EnvironmentSpec(base_image="python:3.12-slim", test_command="python -m pytest tests/t.py")
    joined = " ".join(environment_spec_violations(spec))
    assert "{test_file}" in joined and "-s" in joined
    # Shows the corrected command, and that exemplar itself passes every check.
    assert PYTEST_TEST_COMMAND in joined


def test_jvm_runners_select_by_class_and_are_not_required_to_carry_the_placeholder():
    """Maven and Gradle take a test *class*, not a path — the skills had this right.

    A blanket {test_file} requirement rejected every valid Java spec, including the one the
    stub model produces, which would have broken the Java corpus runs outright. The coupling
    for these runners is that the probe's class name matches the selector.
    """
    from infosec_harness.agents.ecosystem_contract import (
        GRADLE_TEST_COMMAND,
        MAVEN_TEST_COMMAND,
        environment_spec_violations,
    )
    from infosec_harness.domain.models import EnvironmentSpec

    for command in (MAVEN_TEST_COMMAND, GRADLE_TEST_COMMAND):
        spec = EnvironmentSpec(base_image="maven:3.9-eclipse-temurin-21", test_command=command)
        assert "{test_file}" not in command
        assert environment_spec_violations(spec) == [], command


def test_an_empty_class_selector_is_still_rejected():
    """`-Dtest=` with nothing after it selects no test at all."""
    from infosec_harness.agents.ecosystem_contract import environment_spec_violations
    from infosec_harness.domain.models import EnvironmentSpec

    spec = EnvironmentSpec(base_image="maven:3.9", test_command="mvn -q -B test -Dtest=")
    assert any("test class" in p for p in environment_spec_violations(spec))


def test_a_non_verbose_prove_command_is_rejected():
    """prove is a TAP consumer: without -v it throws away every non-TAP line, markers included.

    Exactly the pytest `-s` failure in another ecosystem — the probe runs, exits 0, and the
    harness records `precondition_reached=false`, which probe repair cannot fix.
    """
    from infosec_harness.agents.ecosystem_contract import environment_spec_violations
    from infosec_harness.domain.models import EnvironmentSpec

    quiet = EnvironmentSpec(base_image="perl:5.40", test_command="prove {test_file}")
    assert any("prove -v" in p for p in environment_spec_violations(quiet))
    for ok in ("prove -v {test_file}", "prove --verbose {test_file}", "prove -lv {test_file}"):
        spec = EnvironmentSpec(base_image="perl:5.40", test_command=ok)
        assert environment_spec_violations(spec) == [], ok


def test_an_install_command_that_swallows_its_failure_is_rejected():
    """`cpanm --installdeps . || true` is why both perl SQLi cases scored inconclusive.

    The image builds, the smoke test (`prove --version`) passes, and the missing module first
    appears at probe time as `Can't locate DBI.pm in @INC` — past build repair, the only stage
    that could install it, and unfixable by probe repair, whose probe is correct.
    """
    from infosec_harness.agents.ecosystem_contract import environment_spec_violations
    from infosec_harness.domain.models import EnvironmentSpec

    # The house pattern: each message names the corrected command, not the violation.
    for swallowed, corrected in (
        ("cpanm --notest --installdeps . || true", "cpanm --notest --installdeps ."),
        ("cpanm --installdeps . || :", "cpanm --installdeps ."),
        ("npm install || true && npm run build", "npm install && npm run build"),
        ("pip install -r requirements.txt ; true", "pip install -r requirements.txt"),
    ):
        spec = EnvironmentSpec(base_image="perl:5.40", test_command="prove -v {test_file}",
                              install_commands=[swallowed])
        problems = environment_spec_violations(spec)
        assert any(repr(corrected) in p for p in problems), (swallowed, problems)
    ok = EnvironmentSpec(base_image="perl:5.40", test_command="prove -v {test_file}",
                         install_commands=["cpanm --notest --installdeps ."])
    assert environment_spec_violations(ok) == []


def test_a_local_lib_install_must_be_on_perls_search_path():
    """Installing the deps is only half of it: prove still runs with the stock @INC."""
    from infosec_harness.agents.ecosystem_contract import environment_spec_violations
    from infosec_harness.domain.models import EnvironmentSpec

    unreachable = EnvironmentSpec(
        base_image="perl:5.40", test_command="prove -v {test_file}",
        install_commands=["cpanm --notest -l /opt/home/perl5 --installdeps ."])
    assert any("PERL5LIB" in p for p in environment_spec_violations(unreachable))
    reachable = unreachable.model_copy(
        update={"env": {"PERL5LIB": "/opt/home/perl5/lib/perl5"}})
    assert environment_spec_violations(reachable) == []


def test_a_maven_command_that_cannot_discover_a_junit5_probe_is_rejected():
    """Maven 3.x binds surefire 2.12.4, which has no JUnit Platform provider.

    A JUnit 5 probe is then never discovered: `-Dtest=HarnessProbeTest` matches no runnable
    test, the build fails with "No tests were executed", and the harness sees a nonzero exit
    with no markers — probe_defect, forever, on a probe that is correct. The plugin version
    bound to a phase cannot be overridden from the command line, so the spec must compile with
    `test-compile` and then invoke a pinned surefire goal directly.
    """
    from infosec_harness.agents.ecosystem_contract import (
        MAVEN_TEST_COMMAND,
        environment_spec_violations,
    )
    from infosec_harness.domain.models import EnvironmentSpec

    def problems(command):
        return environment_spec_violations(
            EnvironmentSpec(base_image="maven:3.9-eclipse-temurin-21", test_command=command))

    unpinned = problems("mvn -B -o test -Dtest=HarnessProbeTest "
                        "-Dmaven.test.redirectTestOutputToFile=false")
    assert any("2.12.4" in p for p in unpinned)
    assert any(MAVEN_TEST_COMMAND in p for p in unpinned)  # names the corrected command

    # Pinning the goal but still reaching the `test` phase runs 2.12.4 on the way past.
    both = problems("mvn -B -o test org.apache.maven.plugins:maven-surefire-plugin:3.2.5:test "
                    "-Dtest=HarnessProbeTest -Dmaven.test.redirectTestOutputToFile=false")
    assert any("`test` phase" in p for p in both)

    # The probe is written into the container at probe time, so it has to be compiled there.
    uncompiled = problems("mvn -B -o org.apache.maven.plugins:maven-surefire-plugin:3.2.5:test "
                          "-Dtest=HarnessProbeTest "
                          "-Dmaven.test.redirectTestOutputToFile=false")
    assert any("test-compile" in p for p in uncompiled)

    assert problems(MAVEN_TEST_COMMAND) == []


def test_a_quiet_maven_command_is_rejected_for_the_same_reason_pytest_needs_s():
    """-q raises Maven's log threshold above the INFO relay that carries test stdout."""
    from infosec_harness.agents.ecosystem_contract import (
        MAVEN_TEST_COMMAND,
        environment_spec_violations,
    )
    from infosec_harness.domain.models import EnvironmentSpec

    quiet = MAVEN_TEST_COMMAND.replace("mvn -B", "mvn -q -B")
    problems = environment_spec_violations(
        EnvironmentSpec(base_image="maven:3.9", test_command=quiet))
    assert any("-q" in p and "-B" in p for p in problems)


def test_a_maven_command_must_keep_surefire_output_on_stdout():
    """A pom that redirects test output writes the markers to a file the harness never reads."""
    from infosec_harness.agents.ecosystem_contract import (
        MAVEN_TEST_COMMAND,
        environment_spec_violations,
    )
    from infosec_harness.domain.models import EnvironmentSpec

    without = MAVEN_TEST_COMMAND.replace(" -Dmaven.test.redirectTestOutputToFile=false", "")
    problems = environment_spec_violations(
        EnvironmentSpec(base_image="maven:3.9", test_command=without))
    assert any("redirectTestOutputToFile=false" in p for p in problems)


def test_a_gradle_command_below_the_info_log_level_is_rejected():
    """Gradle's Test task forwards a test's standard streams only from INFO up."""
    from infosec_harness.agents.ecosystem_contract import (
        GRADLE_TEST_COMMAND,
        environment_spec_violations,
    )
    from infosec_harness.domain.models import EnvironmentSpec

    default = "./gradlew --no-daemon --offline test --tests '*HarnessProbeTest'"
    problems = environment_spec_violations(
        EnvironmentSpec(base_image="gradle:8-jdk21", test_command=default))
    assert any("-i" in p for p in problems)
    assert environment_spec_violations(
        EnvironmentSpec(base_image="gradle:8-jdk21", test_command=GRADLE_TEST_COMMAND)) == []


def test_a_d_property_is_not_mistaken_for_a_short_flag():
    """`-Dmaven.test.redirectTestOutputToFile=false` contains an 'i' and a 'q'; neither counts."""
    from infosec_harness.agents.ecosystem_contract import _short_flag

    prop = "-Dmaven.test.redirectTestOutputToFile=false -Dtest=HarnessRequestTest"
    assert not _short_flag(prop, "i")
    assert not _short_flag(prop, "q")
    assert _short_flag("mvn -q -B test", "q")


# --- A probe that declines to run reports nothing, forever -------------------------------

def _perl_probe(body: str):
    from infosec_harness.domain.models import ProbeSource

    return ProbeSource(test_file_path="t/harness_probe.t", content=body)


PERL_PROBE_BODY = (
    "use Test::More;\n"
    "print \"HARNESS_PRECONDITION::x\\n\";\n"
    "my $r = Runner::run('x');\n"
    "print \"HARNESS_SINK_RETURNED::x\\n\";\n"
    "print \"HARNESS_ORACLE::x\\n\" if $r;\n"
    "done_testing();\n"
)


def test_a_test_more_probe_that_skips_itself_is_rejected():
    """`perl-cmdi-fixed` burned its whole repair budget on `skipped: (no reason given)`.

    A skipped script prints no markers at all, so the harness cannot tell it from a broken
    probe, and probe_repair is asked to fix something that is not wrong. Guarding a missing
    module with skip_all is ordinary Perl practice, which is exactly why a model reaches for it.
    """
    from infosec_harness.agents.validators import _skipping_probe_violations

    skipping = PERL_PROBE_BODY.replace(
        "use Test::More;\n",
        "use Test::More;\neval { require DBI; 1 } or plan skip_all => 'no DBI';\n")
    problems = _skipping_probe_violations(_perl_probe(skipping))
    assert any("skip_all" in p for p in problems)
    assert _skipping_probe_violations(_perl_probe(PERL_PROBE_BODY)) == []


def test_a_test_more_probe_with_no_plan_is_rejected():
    """No plan means prove exits nonzero however well the probe behaved."""
    from infosec_harness.agents.validators import _skipping_probe_violations

    planless = PERL_PROBE_BODY.replace("done_testing();\n", "")
    problems = _skipping_probe_violations(_perl_probe(planless))
    assert any("done_testing" in p for p in problems)
    counted = planless.replace("use Test::More;", "use Test::More tests => 1;") + "ok(1);\n"
    assert _skipping_probe_violations(_perl_probe(counted)) == []


def test_the_plan_forms_the_other_perl_dialects_use_are_accepted():
    """Executed against perl 5.34 + prove 3.43: each of these exits 0 with all three markers.

    The rule used to look only for `done_testing`, `tests =>` or `no_plan`, which rejects both
    forms below — a correct probe sent into output retries until the author's budget is gone.
    `Test2::V0` has no `tests =>` spelling at all (`plan 1;` is the whole of it), and a
    prove-run script that loads no Test:: module declares its plan by printing `1..N` itself.
    """
    from infosec_harness.agents.validators import _skipping_probe_violations

    test2 = (
        "use strict; use warnings;\nuse lib 'lib';\nuse Test2::V0;\nplan 1;\nuse Runner;\n"
        "print \"HARNESS_PRECONDITION::n\\n\";\n"
        "my $r = Runner::render('x');\n"
        "print \"HARNESS_SINK_RETURNED::n\\n\";\n"
        "print \"HARNESS_ORACLE::n\\n\" if index($r, 'x') >= 0;\n"
        "ok(1);\n"
    )
    bare_tap = (
        "use strict; use warnings;\nuse lib 'lib';\nuse Runner;\n"
        "print \"HARNESS_PRECONDITION::n\\n\";\n"
        "my $r = Runner::render('x');\n"
        "print \"HARNESS_SINK_RETURNED::n\\n\";\n"
        "print \"HARNESS_ORACLE::n\\n\" if index($r, 'x') >= 0;\n"
        "print \"1..1\\nok 1\\n\";\n"
    )
    for content in (test2, bare_tap):
        assert _skipping_probe_violations(_perl_probe(content)) == [], content
    # `plan skip_all => '...'` is a plan keyword but not a plan: it must still be rejected, and
    # for the skip, not for a missing plan.
    skipping = test2.replace("plan 1;", "skip_all 'needs DBI';")
    problems = _skipping_probe_violations(_perl_probe(skipping))
    assert any("skip_all" in p for p in problems), problems


def test_the_no_plan_rejection_names_every_dialects_spelling():
    """A retry that names only Test::More's spelling is unactionable in a Test2 distribution."""
    from infosec_harness.agents.validators import _skipping_probe_violations

    planless = PERL_PROBE_BODY.replace("done_testing();\n", "")
    joined = " ".join(_skipping_probe_violations(_perl_probe(planless)))
    for spelling in ("done_testing();", "tests => 1", "plan 1;", "1..1"):
        assert spelling in joined, spelling


def test_a_junit_probe_that_disables_or_aborts_itself_is_rejected():
    """Same failure, different ecosystem: Surefire reports it skipped and no markers appear."""
    from infosec_harness.agents.validators import _skipping_probe_violations
    from infosec_harness.domain.models import ProbeSource

    good = ("import org.junit.jupiter.api.Test;\n"
            "class HarnessProbeTest {\n"
            "  @Test void probe() {\n"
            "    System.out.println(\"HARNESS_PRECONDITION::x\");\n"
            "    var r = Target.run(\"x\");\n"
            "    System.out.println(\"HARNESS_SINK_RETURNED::x\");\n"
            "    if (r.contains(\"x\")) System.out.println(\"HARNESS_ORACLE::x\");\n"
            "  }\n}\n")
    path = "src/test/java/com/example/HarnessProbeTest.java"
    assert _skipping_probe_violations(ProbeSource(test_file_path=path, content=good)) == []
    for skip in ("@Disabled\n", "    org.junit.jupiter.api.Assumptions.assumeTrue(ok);\n"):
        bad = good.replace("  @Test", skip + "  @Test")
        assert _skipping_probe_violations(ProbeSource(test_file_path=path, content=bad))


def test_a_python_probe_is_not_held_to_perls_plan_rule():
    """Do not hold a runner to another runner's rule: pytest needs no plan declaration."""
    from infosec_harness.agents.validators import _skipping_probe_violations
    from infosec_harness.domain.models import ProbeSource

    probe = ProbeSource(test_file_path="tests/test_harness_probe.py",
                        content="print('HARNESS_PRECONDITION::x')\n"
                                "print('HARNESS_SINK_RETURNED::x')\n"
                                "print('HARNESS_ORACLE::x')\n")
    assert _skipping_probe_violations(probe) == []


def test_the_probe_guard_carries_the_skip_rule():
    """The pure function is only useful if the agents' validator actually calls it."""
    from types import SimpleNamespace

    import pytest
    from pydantic_ai import ModelRetry

    from infosec_harness.agents.deps import AgentDeps
    from infosec_harness.agents.validators import validate_probe

    ctx = SimpleNamespace(deps=AgentDeps(repo_path="/tmp"))
    with pytest.raises(ModelRetry, match="skip_all"):
        validate_probe(ctx, _perl_probe(
            PERL_PROBE_BODY.replace("done_testing();", "plan skip_all => 'nope';")))


def test_a_jvm_command_with_no_selector_is_told_to_name_a_class_not_a_path():
    """Routing on the selector alone gave a JVM command the opposite of the advice it needs.

    `mvn test` carries no `-Dtest=`, so it used to fall through to the path-runner branch and be
    told to add `{test_file}` — which Maven does not accept. It needs a class name.
    """
    from infosec_harness.agents.ecosystem_contract import environment_spec_violations
    from infosec_harness.domain.models import EnvironmentSpec

    for command in ("mvn -B test", "./gradlew --no-daemon -i test"):
        problems = environment_spec_violations(
            EnvironmentSpec(base_image="maven:3.9-eclipse-temurin-21", test_command=command))
        assert any("test class" in p for p in problems), command
        assert not any("{test_file}" in p for p in problems), command


def test_the_stub_models_own_specs_satisfy_the_contract():
    """The stub is the offline stand-in; if the contract rejects it, every offline test lies."""
    from infosec_harness.agents.ecosystem_contract import (
        environment_spec_violations,
        install_path_violations,
        offline_warmup_violations,
    )
    from infosec_harness.agents.stubs import _env_plan
    from infosec_harness.domain.models import EnvironmentSpec, StackFingerprint

    for languages, manifests in (({"python": 1}, ["requirements.txt"]),
                                 ({"javascript": 1}, ["package.json"]),
                                 ({"java": 1}, ["pom.xml"]),
                                 ({"perl": 1}, ["cpanfile"])):
        stack = StackFingerprint(languages=languages, manifests=manifests)
        spec = EnvironmentSpec.model_validate(_env_plan(stack.model_dump(mode="json")))
        problems = (environment_spec_violations(spec) + install_path_violations(spec)
                    + offline_warmup_violations(spec))
        assert problems == [], (languages, spec.test_command, problems)


async def test_partial_build_stub_runs_through_its_validator_with_a_root_module():
    """The offline agent must satisfy the role-specific output contract it exercises."""
    from infosec_harness.agents.deps import AgentDeps
    from infosec_harness.agents.registry import build_agent
    from infosec_harness.agents.render import render_prompt
    from infosec_harness.domain.models import StackFingerprint

    stack = StackFingerprint(languages={"python": 1}, manifests=["requirements.txt"])
    result = await build_agent("partial-build", durable=False).run(
        render_prompt("narrow the failed environment", {"stack_fingerprint": stack}, stack=stack),
        deps=AgentDeps(repo_path="/tmp"),
    )
    assert result.output.scope == "partial"
    assert result.output.module_path == "."


def test_partial_build_stub_preserves_a_failed_spec_module_path():
    from infosec_harness.agents.stubs import _partial_build_plan

    text = '<failed_spec>\n{"scope": "full", "module_path": "services/api"}\n</failed_spec>'
    assert _partial_build_plan(text)["module_path"] == "services/api"


def test_the_stub_models_own_probes_satisfy_the_contract():
    """Same argument for the probe side: the stub's Test::More template must declare a plan."""
    from infosec_harness.agents.stubs import _PROBE_TEMPLATES
    from infosec_harness.agents.validators import _skipping_probe_violations
    from infosec_harness.domain.models import ProbeSource

    for language, (path, body) in _PROBE_TEMPLATES.items():
        probe = ProbeSource(test_file_path=path, content=body.replace("{nonce}", "n"))
        assert _skipping_probe_violations(probe) == [], language


# --- The two-path sandbox layout (build under /opt, run under /work) ---------------------

def test_an_install_that_writes_under_work_is_rejected():
    """/work is the probe tmpfs; it does not exist while the image is being built."""
    from infosec_harness.agents.ecosystem_contract import install_path_violations
    from infosec_harness.domain.models import EnvironmentSpec

    spec = EnvironmentSpec(
        base_image="perl:5.38-slim", test_command="prove -v {test_file}",
        install_commands=["cpanm --notest --local-lib=/work/home/perl5 --installdeps ."],
        env={"PERL5LIB": "/work/home/perl5/lib/perl5"})
    assert any("/work" in p for p in install_path_violations(spec))


def test_cpanm_without_local_lib_is_rejected():
    """The worst failure shape: cpanm reports success and installs nothing importable.

    Install commands run as the non-root sandbox user, which cannot write perl's site directory.
    Without --local-lib cpanm warns, exits 0, and the build goes green with the dependency
    absent — so the fault first appears inside the probe as `Can't locate DBI.pm`, past build
    repair (the only stage that could install it) and unfixable by probe repair (the probe is
    correct). Both Perl SQLi corpus cases were lost this way, twice.
    """
    from infosec_harness.agents.ecosystem_contract import install_path_violations
    from infosec_harness.domain.models import EnvironmentSpec

    spec = EnvironmentSpec(base_image="perl:5.38-slim", test_command="prove -v {test_file}",
                           install_commands=["cpanm --notest --installdeps ."])
    problems = install_path_violations(spec)
    assert any("--local-lib" in p for p in problems)
    assert any("PERL5LIB" in p for p in problems)


def test_legacy_work_perl5lib_remains_admissible_for_durable_replay():
    from infosec_harness.agents.ecosystem_contract import install_path_violations
    from infosec_harness.domain.models import EnvironmentSpec

    spec = EnvironmentSpec(
        base_image="perl:5.38-slim", test_command="prove -v {test_file}",
        install_commands=["cpanm --notest --local-lib=/opt/home/perl5 --installdeps ."],
        env={"PERL5LIB": "/work/home/perl5/lib/perl5"})
    assert install_path_violations(spec) == []


def test_the_recipe_verified_against_the_corpus_passes():
    """The /opt PERL5LIB shape loaded DBI/SQLite and queried it under managed runsc."""
    from infosec_harness.agents.ecosystem_contract import (
        environment_spec_violations,
        install_path_violations,
    )
    from infosec_harness.domain.models import EnvironmentSpec

    spec = EnvironmentSpec(
        base_image="perl:5.38-slim",
        system_packages=["gcc", "make", "libc6-dev"],
        install_commands=["cpanm --notest --local-lib=/opt/home/perl5 --installdeps ."],
        env={"PERL5LIB": "/opt/home/perl5/lib/perl5"},
        test_command="prove -v {test_file}")
    assert environment_spec_violations(spec) == []
    assert install_path_violations(spec) == []


# --- Maven's lazily resolved Surefire provider --------------------------------------------

MAVEN_PROBE_COMMAND = (
    "mvn -B -o -Dmaven.repo.local=/work/home/.m2/repository test-compile "
    "org.apache.maven.plugins:maven-surefire-plugin:3.2.5:test -Dtest=HarnessProbeTest "
    "-Dmaven.test.redirectTestOutputToFile=false"
)
MAVEN_COMPILE_COMMAND = "mvn -B -Dmaven.repo.local=/opt/home/.m2/repository -DskipTests test-compile"


def test_a_maven_warmup_that_runs_no_test_is_rejected():
    """The exact spec that scored the Java corpus 0–25%, and the exact reason it did.

    Surefire resolves its *provider* at test-execution time, so invoking the pinned goal with an
    empty test tree fetches the plugin and all of its own dependencies and stops there. The build
    exits 0; the offline probe then dies on `surefire-junit-platform:jar:3.2.5 (absent) ... has
    not been downloaded from it before`. Build repair never sees that failure and probe repair
    cannot fix it, because the probe is correct — so nothing downstream can recover.
    """
    from infosec_harness.agents.ecosystem_contract import (
        MAVEN_WARMUP_COMMAND,
        offline_warmup_violations,
    )
    from infosec_harness.domain.models import EnvironmentSpec

    spec = EnvironmentSpec(
        base_image="maven:3.9-eclipse-temurin-21",
        install_commands=[
            MAVEN_COMPILE_COMMAND,
            "mvn -B -Dmaven.repo.local=/opt/home/.m2/repository "
            "org.apache.maven.plugins:maven-surefire-plugin:3.2.5:test -DfailIfNoTests=false"],
        test_command=MAVEN_PROBE_COMMAND)
    problems = offline_warmup_violations(spec)
    assert problems
    assert any(MAVEN_WARMUP_COMMAND in p for p in problems), (
        "the violation must name the corrected install command, not just the symptom"
    )


def test_failifnotests_disqualifies_a_warmup_even_with_a_selector():
    """`-DfailIfNoTests=false` turns "no test ran" into a success, which is the whole defect.

    A warm-up carrying both `-Dtest=` and that flag looks right and can still execute nothing —
    and would then go green while leaving the provider unfetched, which is precisely the silent
    shape this check exists to stop coming back.
    """
    from infosec_harness.agents.ecosystem_contract import offline_warmup_violations
    from infosec_harness.domain.models import EnvironmentSpec

    spec = EnvironmentSpec(
        base_image="maven:3.9-eclipse-temurin-21",
        install_commands=[
            MAVEN_COMPILE_COMMAND,
            "mvn -B -Dmaven.repo.local=/opt/home/.m2/repository "
            "org.apache.maven.plugins:maven-surefire-plugin:3.2.5:test "
            "-Dtest=HarnessWarmupTest -DfailIfNoTests=false"],
        test_command=MAVEN_PROBE_COMMAND)
    assert offline_warmup_violations(spec) != []


def test_a_2_12_4_warmup_does_not_count_as_warming_the_provider():
    """Surefire 2.12.4 has no JUnit Platform provider, so running a test under it warms nothing."""
    from infosec_harness.agents.ecosystem_contract import offline_warmup_violations
    from infosec_harness.domain.models import EnvironmentSpec

    spec = EnvironmentSpec(
        base_image="maven:3.9-eclipse-temurin-21",
        install_commands=[
            MAVEN_COMPILE_COMMAND,
            "mvn -B -Dmaven.repo.local=/opt/home/.m2/repository "
            "org.apache.maven.plugins:maven-surefire-plugin:2.12.4:test -Dtest=HarnessWarmupTest"],
        test_command=MAVEN_PROBE_COMMAND)
    assert offline_warmup_violations(spec) != []


def test_a_non_maven_spec_is_not_asked_to_warm_surefire():
    """The check must stay silent for every other stack, or it fails good specs."""
    from infosec_harness.agents.ecosystem_contract import (
        GRADLE_TEST_COMMAND,
        offline_warmup_violations,
    )
    from infosec_harness.domain.models import EnvironmentSpec

    for base, command in (("python:3.12-slim", "python -m pytest -q -s {test_file}"),
                          ("perl:5.38-slim", "prove -v {test_file}"),
                          ("gradle:8-jdk21", GRADLE_TEST_COMMAND)):
        spec = EnvironmentSpec(base_image=base, test_command=command)
        assert offline_warmup_violations(spec) == [], command


def test_the_maven_recipe_verified_against_the_corpus_passes():
    """This exact spec was built and probed for all four Java corpus cases.

    The image came from the harness's own ``render_dockerfile``; the probe ran under gVisor with
    ``--network=none`` and ``--read-only``, exited 0, and its HARNESS_ markers reached stdout.
    """
    from infosec_harness.agents.ecosystem_contract import (
        MAVEN_WARMUP_COMMAND,
        environment_spec_violations,
        install_path_violations,
        offline_warmup_violations,
    )
    from infosec_harness.domain.models import EnvironmentSpec

    spec = EnvironmentSpec(
        base_image="maven:3.9-eclipse-temurin-21",
        install_commands=[MAVEN_COMPILE_COMMAND, MAVEN_WARMUP_COMMAND],
        test_command=MAVEN_PROBE_COMMAND)
    assert environment_spec_violations(spec) == []
    assert install_path_violations(spec) == []
    assert offline_warmup_violations(spec) == []


def test_a_jvm_selector_given_a_file_path_is_rejected_with_the_class_name():
    """Measured on java-sqli-fixed: `-Dtest={test_file}` substituted to a path, Surefire matched
    nothing, and the case burned its repair budget to `inconclusive`. The existing check only
    required the selector to be non-empty, which a path satisfies."""
    from infosec_harness.agents.ecosystem_contract import (
        MAVEN_WARMUP_COMMAND,
        environment_spec_violations,
    )
    from infosec_harness.domain.models import EnvironmentSpec

    spec = EnvironmentSpec(
        base_image="maven:3.9-eclipse-temurin-17",
        install_commands=[MAVEN_WARMUP_COMMAND],
        test_command=("mvn -B -o test-compile "
                      "org.apache.maven.plugins:maven-surefire-plugin:3.2.5:test "
                      "-Dtest=src/test/java/com/example/UserDaoTest.java "
                      "-Dmaven.test.redirectTestOutputToFile=false"),
    )
    problems = environment_spec_violations(spec)
    assert any("file path, not a class name" in p for p in problems), problems
    # House style: the message names the corrected value, not just the defect.
    assert any("-Dtest=UserDaoTest" in p for p in problems), problems


def test_a_jvm_selector_holding_the_test_file_placeholder_is_rejected():
    """`{test_file}` is the shape that produced the failure, and it is recognisable before the
    substitution ever happens."""
    from infosec_harness.agents.ecosystem_contract import (
        MAVEN_WARMUP_COMMAND,
        environment_spec_violations,
    )
    from infosec_harness.domain.models import EnvironmentSpec

    spec = EnvironmentSpec(
        base_image="maven:3.9-eclipse-temurin-17",
        install_commands=[MAVEN_WARMUP_COMMAND],
        test_command=("mvn -B -o test-compile "
                      "org.apache.maven.plugins:maven-surefire-plugin:3.2.5:test "
                      "-Dtest={test_file} -Dmaven.test.redirectTestOutputToFile=false"),
    )
    problems = environment_spec_violations(spec)
    assert any("do not use {test_file} in a jvm selector" in p.lower() for p in problems), problems


def test_a_gradle_selector_given_a_path_names_the_glob_form():
    from infosec_harness.agents.ecosystem_contract import _pathish_selector_violation

    msg = _pathish_selector_violation(
        "./gradlew --no-daemon --offline -i test --tests 'src/test/java/FooTest.java'")
    assert msg is not None and "--tests '*FooTest'" in msg, msg


def test_a_proper_class_selector_is_accepted():
    """Guards against over-firing: the canonical commands must stay clean."""
    from infosec_harness.agents.ecosystem_contract import (
        GRADLE_TEST_COMMAND,
        MAVEN_TEST_COMMAND,
        _pathish_selector_violation,
    )

    assert _pathish_selector_violation(MAVEN_TEST_COMMAND) is None
    assert _pathish_selector_violation(GRADLE_TEST_COMMAND) is None


def test_surefires_own_no_match_wording_is_recognised_as_a_zero_test_run():
    """The two halves must meet: the validator stops the bad selector being written, and if one
    slips through, the runner's output is still classified rather than left to be inferred."""
    from infosec_harness.sandbox import docker

    output = ('[ERROR] No tests matching pattern "src/test/java/com/example/UserDaoTest.java" '
              'were executed!\n')
    reason = docker.no_tests_executed(output)
    assert reason is not None and "matched no test class" in reason
    assert "not a negative result" in reason


def test_every_canonical_command_satisfies_every_validator():
    """The commands the retry messages tell an agent to write must themselves be accepted.

    This is the invariant that would have prevented the whole class of bug: `MAVEN_TEST_COMMAND`
    is cited by name in several `ModelRetry` messages, but omitted `-Dmaven.repo.local`, so an
    agent that copied it verbatim to fix the selector was immediately rejected for a *different*
    violation. Measured on java-sqli-vulnerable: it oscillated between the two corrections and
    burned its output retries into `environment_unbuildable`. An exemplar that fails the checker
    it exemplifies does not teach, it traps.
    """
    from infosec_harness.agents.ecosystem_contract import (
        GRADLE_TEST_COMMAND,
        MAVEN_TEST_COMMAND,
        MAVEN_WARMUP_COMMAND,
        environment_spec_violations,
        install_path_violations,
    )
    from infosec_harness.domain.models import EnvironmentSpec

    for label, command in (("MAVEN_TEST_COMMAND", MAVEN_TEST_COMMAND),
                           ("GRADLE_TEST_COMMAND", GRADLE_TEST_COMMAND)):
        spec = EnvironmentSpec(base_image="maven:3.9-eclipse-temurin-17",
                               install_commands=[MAVEN_WARMUP_COMMAND], test_command=command)
        problems = environment_spec_violations(spec) + install_path_violations(spec)
        assert not problems, (
            f"{label} is what the retry messages tell the agent to write, but the validators "
            f"reject it: {problems}"
        )


def test_a_pytest_probe_that_can_skip_itself_is_rejected():
    """The protocol names `collected 0 items` as a zero-test run, but only the Perl and JUnit
    idioms that cause one were detected. `importorskip` is what a model actually reaches for
    when an import might fail — which is precisely the environment signal build repair needs.
    """
    from infosec_harness.agents.validators import _skipping_probe_violations
    from infosec_harness.domain.models import ProbeSource

    for idiom in ("pytest.importorskip('psycopg2')", "pytest.skip('no db')",
                  "@pytest.mark.skipif(True, reason='x')"):
        probe = ProbeSource(test_file_path="tests/test_probe.py",
                            content=f"import pytest\n{idiom}\ndef test_probe():\n    pass\n")
        problems = _skipping_probe_violations(probe)
        assert any("zero-test run is never a negative result" in p for p in problems), (
            f"{idiom} was not rejected: {problems}"
        )


def test_a_jest_probe_that_can_skip_itself_is_rejected():
    from infosec_harness.agents.validators import _skipping_probe_violations
    from infosec_harness.domain.models import ProbeSource

    for idiom in ("test.skip('probe', () => {})", "describe.skip('x', () => {})"):
        probe = ProbeSource(test_file_path="__tests__/probe.test.js", content=idiom)
        assert _skipping_probe_violations(probe), f"{idiom} was not rejected"


def test_test_only_is_rejected_because_it_excludes_every_other_test():
    """Not skipping, and that is why it is worse: a probe placed after a `.only` never runs and
    the file still exits 0."""
    from infosec_harness.agents.validators import _skipping_probe_violations
    from infosec_harness.domain.models import ProbeSource

    probe = ProbeSource(test_file_path="probe.test.js",
                        content="test.only('setup', () => {});\ntest('harness probe', () => {});")
    problems = _skipping_probe_violations(probe)
    assert any("excludes every other test" in p for p in problems), problems


def test_an_honest_probe_in_either_language_is_accepted():
    """Guards against over-firing: the word 'skip' appearing in a comment or a payload must not
    reject a probe that runs to completion."""
    from infosec_harness.agents.validators import _skipping_probe_violations
    from infosec_harness.domain.models import ProbeSource

    py = ProbeSource(test_file_path="tests/test_probe.py",
                     content="def test_probe():\n    print('HARNESS_PRECONDITION::n')\n")
    js = ProbeSource(test_file_path="probe.test.js",
                     content="test('harness probe', () => { console.log('HARNESS_PRECONDITION::n'); });")
    assert _skipping_probe_violations(py) == []
    assert _skipping_probe_violations(js) == []


def test_a_static_claim_alone_does_not_support_a_safe_verdict():
    """Neither `unreachable` nor `neutralized` is a valid negative execution.

    It says untrusted input arrives and a control stops it — a claim about behaviour that only
    a probe can support. If it were accepted here, a verdict could assert safety on reasoning
    alone, which is precisely the gap the value was introduced to close.
    """
    from infosec_harness.evals.adapters import is_unevidenced_safe

    def case(reachability):
        return {"facts": {"reachability": reachability}, "payload": {}}

    assert is_unevidenced_safe("verdict", case("unreachable"), "likely_not_exploitable")
    assert is_unevidenced_safe("verdict", case("neutralized"), "likely_not_exploitable"), (
        "a neutralized claim with no probe behind it is an unevidenced safe verdict"
    )


def test_the_jdk_a_base_image_provides_is_read_past_the_build_tool_version():
    """`maven:3.9-...` and `gradle:8-...` lead with the build tool's version, so a naive
    first-number read validates against JDK 3 or JDK 8 and silently passes anything."""
    from infosec_harness.agents.ecosystem_contract import image_jdk_major

    assert image_jdk_major("maven:3.9-eclipse-temurin-17") == 17
    assert image_jdk_major("gradle:8-jdk21") == 21
    assert image_jdk_major("eclipse-temurin:11-jdk") == 11
    assert image_jdk_major("openjdk:8") == 8
    assert image_jdk_major("python:3.12-slim") is None


def test_the_oldest_declared_language_level_is_the_binding_one():
    """A pom with source 7 and target 8 needs a JDK that still accepts 7, so the lower number
    is the constraint."""
    from infosec_harness.agents.ecosystem_contract import declared_java_release

    pom = ("<properties><maven.compiler.source>1.7</maven.compiler.source>"
           "<maven.compiler.target>1.8</maven.compiler.target></properties>")
    assert declared_java_release(pom) == 7
    assert declared_java_release("sourceCompatibility = 1.8") == 8
    assert declared_java_release("languageVersion = JavaLanguageVersion.of(17)") == 17
    assert declared_java_release("<groupId>org.example</groupId>") is None


def test_a_modern_jdk_is_rejected_for_a_project_that_declares_an_old_source_level():
    """The Vul4J case: its 79 reproducible vulnerabilities target Java 7 through 16, so one
    pinned image cannot build the corpus. JDK 20 removed -source 7 outright, and the failure is
    a fixed javac message that build repair cannot reason its way out of.
    """
    from infosec_harness.agents.ecosystem_contract import jdk_compatibility_violations

    problems = jdk_compatibility_violations("maven:3.9-eclipse-temurin-21", 7)
    assert problems and "no longer supported" in problems[0]
    # Names a working image rather than only the defect, per the house style -- and the *newest*
    # image that works, which for source 7 is temurin-17. Measured: Zulu 17 compiles -source 1.7
    # with a deprecation warning, and Zulu 21 fails with "Source option 7 is no longer supported".
    assert "eclipse-temurin-17" in problems[0]
    # And must not suggest editing the project's compiler level, which changes the subject.
    assert "changes what is being tested" in problems[0]


def test_the_javac_source_floors_are_the_ones_that_were_measured():
    """Each floor was executed, not read off a release note: javac from Zulu 8/11/17/21 under
    Maven 3.9.16 was asked for -source 1.5/1.6/1.7/1.8. JDK 8 accepted all four, JDK 11 rejected
    5, JDK 17 rejected 6, JDK 21 rejected 7.

    The 11-floor was missing before this, and three poms in the harvested Vul4J corpus declare
    `<source>1.5</source>` -- so their specs were accepted here naming temurin-11 and then died in
    the image build on the very message this check exists to predict.
    """
    from infosec_harness.agents.ecosystem_contract import (
        jdk_compatibility_violations,
        maven_image_for_release,
    )

    assert jdk_compatibility_violations("maven:3.9-eclipse-temurin-11", 5)
    assert "eclipse-temurin-8" in jdk_compatibility_violations("maven:3.9-eclipse-temurin-11", 5)[0]
    assert jdk_compatibility_violations("maven:3.9-eclipse-temurin-11", 6) == []
    assert jdk_compatibility_violations("maven:3.9-eclipse-temurin-17", 6)
    assert jdk_compatibility_violations("maven:3.9-eclipse-temurin-17", 7) == []
    assert jdk_compatibility_violations("maven:3.9-eclipse-temurin-8", 5) == []
    # The image the message names must itself be one the floors accept, for every level in the
    # corpus: a remedy that fails the same check is what made the old message useless.
    for release in (5, 6, 7, 8, 11, 17, 21):
        image = maven_image_for_release(release)
        assert jdk_compatibility_violations(image, release) == [], (release, image)


def test_a_jdk_older_than_the_project_is_rejected_too():
    from infosec_harness.agents.ecosystem_contract import jdk_compatibility_violations

    problems = jdk_compatibility_violations("openjdk:8", 11)
    assert problems and "invalid target release: 11" in problems[0]


def test_a_compatible_pairing_and_an_unreadable_one_are_both_left_alone():
    """Silence when it cannot tell: an unknown image or an undeclared level must not be
    guessed at, because a wrong floor would reject a spec that builds."""
    from infosec_harness.agents.ecosystem_contract import jdk_compatibility_violations

    assert jdk_compatibility_violations("maven:3.9-eclipse-temurin-17", 11) == []
    assert jdk_compatibility_violations("python:3.12-slim", 7) == []
    assert jdk_compatibility_violations("maven:3.9-eclipse-temurin-21", None) == []


def test_the_declared_level_is_read_from_a_real_repository(tmp_path):
    """Multi-module projects keep the compiler properties in the root pom, so the root and one
    level down is where to look."""
    from infosec_harness.agents.ecosystem_contract import repo_java_release

    (tmp_path / "pom.xml").write_text("<project><properties>"
                                      "<maven.compiler.source>1.7</maven.compiler.source>"
                                      "</properties></project>")
    assert repo_java_release(str(tmp_path)) == 7
    module = tmp_path / "core"
    module.mkdir()
    (module / "pom.xml").write_text(
        "<project><properties><java.version>11</java.version></properties></project>")
    # Still 7: the oldest level anywhere in the project binds the JDK choice.
    assert repo_java_release(str(tmp_path)) == 7
    assert repo_java_release(None) is None
    assert repo_java_release(str(tmp_path / "nope")) is None


def test_a_pytest_command_that_inherits_the_projects_addopts_is_rejected():
    """Verified against real pytest, not reasoned about.

    A project's `addopts` are prepended to *our* invocation from pytest.ini, setup.cfg,
    tox.ini or pyproject.toml. `-s` does override an inherited `--capture=sys` — that much was
    fine. But `addopts = --collect-only` makes pytest exit **0** having printed neither the
    markers nor the words "collected 0 items": the observed output is literally
    `tests/test_probe.py: 1`. The probe never runs, `no_tests_executed` cannot see it, and
    nothing downstream distinguishes it from a probe that ran and observed nothing. That is the
    costliest failure shape this system has.
    """
    from infosec_harness.agents.ecosystem_contract import environment_spec_violations
    from infosec_harness.domain.models import EnvironmentSpec

    inheriting = EnvironmentSpec(base_image="python:3.12-slim",
                                 test_command="python -m pytest -q -s {test_file}")
    problems = environment_spec_violations(inheriting)
    assert any("-o addopts=" in p for p in problems), problems
    assert any("--collect-only" in p for p in problems), "the message must say why"

    for neutralised in ("python -m pytest -q -s -o addopts= {test_file}",
                        "python -m pytest -q -s --override-ini addopts= {test_file}"):
        spec = EnvironmentSpec(base_image="python:3.12-slim", test_command=neutralised)
        assert environment_spec_violations(spec) == [], neutralised


def test_only_pytest_is_asked_to_neutralise_addopts():
    """Invent a requirement only where it is real: no other runner has this behaviour."""
    from infosec_harness.agents.ecosystem_contract import environment_spec_violations
    from infosec_harness.domain.models import EnvironmentSpec

    for command in ("npx jest --runTestsByPath {test_file}", "prove -v {test_file}"):
        spec = EnvironmentSpec(base_image="node:22-slim", test_command=command)
        assert not any("addopts" in p for p in environment_spec_violations(spec)), command


# --- The JUnit 4 / JUnit 5 compatibility matrix ----------------------------------------------
#
# Everything asserted below was executed before it was written down: Maven 3.9.16 with Surefire
# 3.2.5 on Zulu JDK 8/11/17/21, against minimal fixture projects at source levels 1.5 to 1.8 and
# against three harvested corpus repositories at their vulnerable revisions (zeroturnaround/zt-zip,
# apache/commons-imaging, apache/commons-fileupload). The harness previously assumed JUnit 5
# everywhere, and 50 of the 51 Maven entries harvested from Vul4J are JUnit 4.

JUNIT4_POM = ("<project><properties>"
              "<maven.compiler.source>1.8</maven.compiler.source></properties>"
              "<dependencies><dependency><groupId>junit</groupId>"
              "<artifactId>junit</artifactId><version>4.12</version><scope>test</scope>"
              "</dependency></dependencies></project>")
JUNIT5_POM = ("<project><properties>"
              "<maven.compiler.source>1.8</maven.compiler.source></properties>"
              "<dependencies><dependency><groupId>org.junit.jupiter</groupId>"
              "<artifactId>junit-jupiter</artifactId><version>5.10.2</version><scope>test</scope>"
              "</dependency></dependencies></project>")


def test_the_jvm_test_framework_is_read_from_the_build_file():
    """`junit` in the pom used to mean `junit5`, which is wrong for most Java in the wild.

    Precedence is the provider Surefire actually selects: with jupiter present it uses the JUnit
    Platform provider, and a JUnit-4-annotated test then runs zero tests and still exits 0 -- so
    jupiter wins over junit4 even when both are declared. With junit and testng together it uses
    the TestNG provider, which runs a JUnit 4 test anyway, so junit4 is the safe answer there.
    """
    from infosec_harness.repo.detect import jvm_test_framework

    assert jvm_test_framework(JUNIT4_POM) == "junit4"
    assert jvm_test_framework(JUNIT5_POM) == "junit5"
    assert jvm_test_framework(JUNIT4_POM + JUNIT5_POM) == "junit5"
    assert jvm_test_framework("<artifactId>testng</artifactId>") == "testng"
    assert jvm_test_framework("testImplementation 'junit:junit:4.13.2'") == "junit4"
    assert jvm_test_framework("<project><artifactId>batik-dom</artifactId></project>") is None


def test_a_junit5_warmup_in_a_junit4_project_is_rejected(tmp_path):
    """The defect that would have failed 50 of the 51 harvested Maven entries.

    The warm-up's throwaway test is compiled against the project's own test classpath, so a
    jupiter warm-up in a JUnit-4-only project dies inside the warm-up's own `test-compile` with
    `HarnessWarmupTest.java:[1,63] cannot find symbol / symbol: class Test` -- the image is never
    built, so there is no probe run at all. Executed on zt-zip, commons-imaging and
    commons-fileupload at their harvested revisions: all three fail, and all three then pass with
    all three markers once the warm-up is JUnit 4.
    """
    from infosec_harness.agents.ecosystem_contract import (
        MAVEN_WARMUP_COMMANDS,
        offline_warmup_violations,
        repo_jvm_test_framework,
    )
    from infosec_harness.domain.models import EnvironmentSpec

    (tmp_path / "pom.xml").write_text(JUNIT4_POM)
    framework = repo_jvm_test_framework(str(tmp_path))
    assert framework == "junit4"

    jupiter = EnvironmentSpec(
        base_image="maven:3.9-eclipse-temurin-17",
        install_commands=[MAVEN_COMPILE_COMMAND, MAVEN_WARMUP_COMMANDS["junit5"]],
        test_command=MAVEN_PROBE_COMMAND)
    problems = offline_warmup_violations(jupiter, framework)
    assert problems, "a jupiter warm-up in a JUnit 4 project must be rejected"
    assert any(MAVEN_WARMUP_COMMANDS["junit4"] in p for p in problems), (
        "the violation must name the corrected install command, not just the symptom"
    )
    assert any("cannot find symbol" in p for p in problems)

    matching = jupiter.model_copy(update={
        "install_commands": [MAVEN_COMPILE_COMMAND, MAVEN_WARMUP_COMMANDS["junit4"]]})
    assert offline_warmup_violations(matching, framework) == []


def test_an_unwarmed_build_is_told_the_warmup_in_its_own_framework():
    """The provider Surefire needs is per-project (a JUnit-4 project warmed with nothing to run
    failed offline on `surefire-junit4:jar:3.2.5 (absent)`), so the cited warm-up must run a test
    in the project's own framework."""
    from infosec_harness.agents.ecosystem_contract import (
        MAVEN_WARMUP_COMMANDS,
        offline_warmup_violations,
    )
    from infosec_harness.domain.models import EnvironmentSpec

    spec = EnvironmentSpec(
        base_image="maven:3.9-eclipse-temurin-17",
        install_commands=[MAVEN_COMPILE_COMMAND],
        test_command=MAVEN_PROBE_COMMAND)
    for framework, command in MAVEN_WARMUP_COMMANDS.items():
        [problem] = offline_warmup_violations(spec, framework)
        assert repr(command) in problem, framework


def test_every_shipped_maven_warmup_satisfies_the_checks_that_judge_it():
    """Each warm-up the harness hands out must itself pass, or an agent that copies one verbatim
    is rejected for following the instruction -- the oscillation that exhausted java-sqli's
    output retries once already."""
    from infosec_harness.agents.ecosystem_contract import (
        MAVEN_WARMUP_COMMANDS,
        install_path_violations,
        offline_warmup_violations,
    )
    from infosec_harness.domain.models import EnvironmentSpec

    for framework, warmup in MAVEN_WARMUP_COMMANDS.items():
        spec = EnvironmentSpec(
            base_image="maven:3.9-eclipse-temurin-17",
            install_commands=[MAVEN_COMPILE_COMMAND, warmup],
            test_command=MAVEN_PROBE_COMMAND)
        assert offline_warmup_violations(spec, framework) == [], framework
        assert install_path_violations(spec) == [], framework


def test_a_java_probe_written_for_the_wrong_framework_is_rejected():
    """Both directions, and both were measured as silent failures rather than loud ones.

    A jupiter probe in a JUnit-4 project does not compile. A JUnit-4-annotated probe in a project
    with jupiter on the classpath compiles, is selected by `-Dtest=`, and then reports
    `Tests run: 0` with **exit 0** -- the shape the harness cannot tell from a probe that reached
    nothing, because that is exactly what it looks like.
    """
    from infosec_harness.agents.validators import _java_probe_violations
    from infosec_harness.domain.models import ProbeSource

    jupiter_probe = ProbeSource(
        test_file_path="src/test/java/com/example/HarnessProbeTest.java",
        content=("import org.junit.jupiter.api.Test;\n"
                 "class HarnessProbeTest { @Test void probe() {} }\n"))
    junit4_probe = ProbeSource(
        test_file_path="src/test/java/com/example/HarnessProbeTest.java",
        content=("import org.junit.Test;\n"
                 "public class HarnessProbeTest { @Test public void probe() {} }\n"))

    wrong = _java_probe_violations(jupiter_probe, "junit4", 8)
    assert any("org.junit.jupiter.api does not exist" in p for p in wrong)
    assert any("test-junit4" in p for p in wrong)
    assert _java_probe_violations(junit4_probe, "junit4", 8) == []

    wrong = _java_probe_violations(junit4_probe, "junit5", 8)
    assert any("Tests run: 0" in p for p in wrong)
    assert _java_probe_violations(jupiter_probe, "junit5", 8) == []
    # No repository to read: the framework-dependent rules stay silent rather than guess.
    assert _java_probe_violations(jupiter_probe, None, None) == []


def test_a_junit4_probe_that_is_not_public_is_rejected():
    """`class X { @Test void probe() }` is correct JUnit 5 and broken JUnit 4.

    Measured: the JUnit4Provider reports `com.example.HarnessProbeTest.initializationError`,
    prints no markers, and exits 1. Downstream that is indistinguishable from a defective probe,
    so probe repair is handed a probe whose logic is right.
    """
    from infosec_harness.agents.validators import _java_probe_violations
    from infosec_harness.domain.models import ProbeSource

    def probe(body):
        return ProbeSource(test_file_path="src/test/java/HarnessProbeTest.java",
                           content="import org.junit.Test;\n" + body)

    both_private = _java_probe_violations(
        probe("class HarnessProbeTest {\n    @Test\n    void probe() {}\n}\n"), "junit4", 8)
    assert any("public class HarnessProbeTest" in p for p in both_private)
    assert any("public void" in p for p in both_private)

    method_private = _java_probe_violations(
        probe("public class HarnessProbeTest {\n    @Test\n    void probe() {}\n}\n"), "junit4", 8)
    assert [p for p in method_private if "public void" in p]
    assert not [p for p in method_private if "public class" in p]

    ok = probe("public class HarnessProbeTest {\n    @Test\n    public void probe() {}\n}\n")
    assert _java_probe_violations(ok, "junit4", 8) == []
    # JUnit 3 style on the JUnit 4 artefact: two harvested entries write their tests this way,
    # and it runs under the same provider (measured).
    junit3 = ProbeSource(
        test_file_path="src/test/java/HarnessProbeTest.java",
        content=("public class HarnessProbeTest extends junit.framework.TestCase {\n"
                 "    public void testProbe() {}\n}\n"))
    assert _java_probe_violations(junit3, "junit4", 8) == []


def test_a_probe_using_syntax_the_project_cannot_compile_is_rejected():
    """The published JUnit 5 exemplar used `var`, and the corpus is Java 7 and 8.

    javac at source 8 fails the whole build with `cannot find symbol: class var`, and at source 5
    or 6 the exemplar's multi-catch fails too -- three harvested poms pin `<source>1.5</source>`.
    Both were executed. The probe reads as correct, so nothing downstream can attribute it.
    """
    from infosec_harness.agents.validators import _java_probe_violations
    from infosec_harness.domain.models import ProbeSource

    var_probe = ProbeSource(
        test_file_path="src/test/java/HarnessProbeTest.java",
        content=("import org.junit.Test;\n"
                 "public class HarnessProbeTest {\n    @Test\n    public void probe() {\n"
                 "        var payload = \"x\";\n    }\n}\n"))
    assert any("cannot find symbol: class var" in p
               for p in _java_probe_violations(var_probe, "junit4", 8))
    assert _java_probe_violations(var_probe, "junit4", 11) == []

    multi_catch = ProbeSource(
        test_file_path="src/test/java/HarnessProbeTest.java",
        content=("import org.junit.Test;\n"
                 "public class HarnessProbeTest {\n    @Test\n    public void probe() {\n"
                 "        try { sink(); } catch (IllegalArgumentException | SecurityException e) {}\n"
                 "    }\n}\n"))
    assert any("multi-catch" in p for p in _java_probe_violations(multi_catch, "junit4", 5))
    assert _java_probe_violations(multi_catch, "junit4", 7) == []


def test_the_stub_java_plan_is_read_from_the_fingerprint_and_survives_its_own_validators():
    """The stub is the offline stand-in for env-planner, so a stub plan the validators reject
    makes every offline Java test a lie -- and a stub that hardcodes JUnit 5 and temurin-21 makes
    the offline tests agree with the two defects this change fixes."""
    from infosec_harness.agents.ecosystem_contract import (
        environment_spec_violations,
        install_path_violations,
        offline_warmup_violations,
    )
    from infosec_harness.agents.stubs import _env_plan
    from infosec_harness.domain.models import EnvironmentSpec

    for framework, release, image in (("junit4", 7, "maven:3.9-eclipse-temurin-17"),
                                      ("junit5", 8, "maven:3.9-eclipse-temurin-17"),
                                      ("testng", 5, "maven:3.9-eclipse-temurin-8"),
                                      ("junit4", None, "maven:3.9-eclipse-temurin-17")):
        plan = _env_plan({"languages": {"java": 10}, "manifests": ["pom.xml"],
                          "test_frameworks": [framework], "java_release": release})
        assert plan["base_image"] == image, (framework, release)
        spec = EnvironmentSpec.model_validate(plan)
        assert environment_spec_violations(spec) == []
        assert install_path_violations(spec) == []
        assert offline_warmup_violations(spec, framework) == []


def test_a_gradle_test_command_that_can_report_up_to_date_is_rejected():
    """Gradle's own silent no-op, which Maven has no equivalent of.

    `test` is an incremental task: with unchanged inputs Gradle reports `> Task :test UP-TO-DATE`,
    executes nothing, prints no marker, and exits 0. Measured on Gradle 8.14.3 / JDK 17 against a
    JUnit 4 fixture -- the first run printed all three markers, and the identical command twice
    more printed none and exited 0 both times. Same family as an un-`-s`ed pytest: a correct probe
    recorded as having reached nothing, with nothing downstream able to attribute it.
    """
    from infosec_harness.agents.ecosystem_contract import (
        GRADLE_TEST_COMMAND,
        environment_spec_violations,
    )
    from infosec_harness.domain.models import EnvironmentSpec

    incremental = EnvironmentSpec(
        base_image="gradle:8-jdk17",
        test_command="./gradlew --no-daemon --offline -i test --tests '*HarnessProbeTest'")
    problems = environment_spec_violations(incremental)
    assert any("--rerun-tasks" in p for p in problems)
    assert any("UP-TO-DATE" in p for p in problems), "the message must name the symptom"
    assert any(GRADLE_TEST_COMMAND in p for p in problems), (
        "and the corrected command, like every other message here"
    )

    for ok in (GRADLE_TEST_COMMAND,
               "./gradlew --no-daemon --offline -i cleanTest test --tests '*HarnessProbeTest'"):
        assert environment_spec_violations(
            EnvironmentSpec(base_image="gradle:8-jdk17", test_command=ok)) == [], ok


def test_the_gradle_exemplar_satisfies_every_check_that_judges_it():
    """The same rule as the Maven exemplar: a retry message naming a command the validator would
    itself reject is what made java-sqli oscillate between two violations until its output retries
    ran out."""
    from infosec_harness.agents.ecosystem_contract import (
        GRADLE_TEST_COMMAND,
        MAVEN_TEST_COMMAND,
        environment_spec_violations,
        install_path_violations,
    )
    from infosec_harness.domain.models import EnvironmentSpec

    for image, command in (("gradle:8-jdk17", GRADLE_TEST_COMMAND),
                           ("maven:3.9-eclipse-temurin-17", MAVEN_TEST_COMMAND)):
        spec = EnvironmentSpec(base_image=image, test_command=command)
        assert environment_spec_violations(spec) == [], command
        assert install_path_violations(spec) == [], command
