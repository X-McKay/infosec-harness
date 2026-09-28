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


def test_exploitable_requires_oracle():
    facts = VerdictFacts(environment_ready=True, oracle_fired=False)
    assert verdict_violations(v(VerdictLabel.potentially_exploitable), facts)


def test_exploitable_valid_positive_ok():
    facts = VerdictFacts(environment_ready=True, oracle_fired=True, precondition_reached=True,
                         last_diagnosis=DiagnosisKind.valid_positive)
    assert verdict_violations(v(VerdictLabel.potentially_exploitable), facts) == []


def test_not_exploitable_needs_valid_negative_or_unreachable():
    facts = VerdictFacts(environment_ready=True, oracle_fired=False, precondition_reached=False)
    assert verdict_violations(v(VerdictLabel.likely_not_exploitable), facts)
    facts_ok = VerdictFacts(environment_ready=True, oracle_fired=False, precondition_reached=True,
                            last_diagnosis=DiagnosisKind.valid_negative)
    assert verdict_violations(v(VerdictLabel.likely_not_exploitable), facts_ok) == []


def test_unreachable_negative_needs_evidence():
    facts = VerdictFacts(environment_ready=False, reachability=Reachability.unreachable)
    assert verdict_violations(v(VerdictLabel.likely_not_exploitable), facts)  # no evidence
    assert verdict_violations(
        v(VerdictLabel.likely_not_exploitable, evidence=[CodeRef(file_path="a", start_line=1, end_line=2)]),
        facts) == []


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
    from infosec_harness.agents.validators import environment_spec_violations
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
    from infosec_harness.agents.validators import environment_spec_violations
    from infosec_harness.domain.models import EnvironmentSpec

    captured = EnvironmentSpec(base_image="python:3.12-slim",
                              test_command="python -m pytest -q {test_file}")
    assert any("-s" in p for p in environment_spec_violations(captured))
    for ok in ("python -m pytest -q -s {test_file}",
               "python -m pytest --capture=no {test_file}"):
        spec = EnvironmentSpec(base_image="python:3.12-slim", test_command=ok)
        assert environment_spec_violations(spec) == [], ok


def test_non_pytest_runners_are_not_held_to_pytests_flag():
    """Only invent a requirement where it is real: jest does not capture as pytest does."""
    from infosec_harness.agents.validators import environment_spec_violations
    from infosec_harness.domain.models import EnvironmentSpec

    for command in ("npx jest {test_file}", "npx jest --runTestsByPath {test_file}",
                    "npx vitest run {test_file}", "node --test {test_file}"):
        spec = EnvironmentSpec(base_image="node:22-slim", test_command=command)
        assert environment_spec_violations(spec) == [], command


def test_the_environment_agents_all_carry_the_contract():
    """A spec from any of the three build agents reaches run_probe, so all three are bound."""
    from infosec_harness.agents.validators import OUTPUT_VALIDATORS, validate_environment_spec

    for agent in ("env-planner", "build-repair", "partial-build"):
        assert validate_environment_spec in OUTPUT_VALIDATORS[agent], agent


def test_the_retry_message_names_the_fix_rather_than_the_violation():
    """A retry the model cannot act on just burns the budget (cf. verdict's inconclusive_reason)."""
    from infosec_harness.agents.validators import environment_spec_violations
    from infosec_harness.domain.models import EnvironmentSpec

    spec = EnvironmentSpec(base_image="python:3.12-slim", test_command="python -m pytest tests/t.py")
    joined = " ".join(environment_spec_violations(spec))
    assert "{test_file}" in joined and "-s" in joined
    assert "python -m pytest -q -s {test_file}" in joined  # shows the corrected command


def test_jvm_runners_select_by_class_and_are_not_required_to_carry_the_placeholder():
    """Maven and Gradle take a test *class*, not a path — the skills had this right.

    A blanket {test_file} requirement rejected every valid Java spec, including the one the
    stub model produces, which would have broken the Java corpus runs outright. The coupling
    for these runners is that the probe's class name matches the selector.
    """
    from infosec_harness.agents.validators import (
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
    from infosec_harness.agents.validators import environment_spec_violations
    from infosec_harness.domain.models import EnvironmentSpec

    spec = EnvironmentSpec(base_image="maven:3.9", test_command="mvn -q -B test -Dtest=")
    assert any("test class" in p for p in environment_spec_violations(spec))


def test_a_non_verbose_prove_command_is_rejected():
    """prove is a TAP consumer: without -v it throws away every non-TAP line, markers included.

    Exactly the pytest `-s` failure in another ecosystem — the probe runs, exits 0, and the
    harness records `precondition_reached=false`, which probe repair cannot fix.
    """
    from infosec_harness.agents.validators import environment_spec_violations
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
    from infosec_harness.agents.validators import environment_spec_violations
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
    from infosec_harness.agents.validators import environment_spec_violations
    from infosec_harness.domain.models import EnvironmentSpec

    unreachable = EnvironmentSpec(
        base_image="perl:5.40", test_command="prove -v {test_file}",
        install_commands=["cpanm --notest -l /work/home/perl5 --installdeps ."])
    assert any("PERL5LIB" in p for p in environment_spec_violations(unreachable))
    reachable = unreachable.model_copy(
        update={"env": {"PERL5LIB": "/work/home/perl5/lib/perl5"}})
    assert environment_spec_violations(reachable) == []


def test_a_maven_command_that_cannot_discover_a_junit5_probe_is_rejected():
    """Maven 3.x binds surefire 2.12.4, which has no JUnit Platform provider.

    A JUnit 5 probe is then never discovered: `-Dtest=HarnessProbeTest` matches no runnable
    test, the build fails with "No tests were executed", and the harness sees a nonzero exit
    with no markers — probe_defect, forever, on a probe that is correct. The plugin version
    bound to a phase cannot be overridden from the command line, so the spec must compile with
    `test-compile` and then invoke a pinned surefire goal directly.
    """
    from infosec_harness.agents.validators import MAVEN_TEST_COMMAND, environment_spec_violations
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
    from infosec_harness.agents.validators import MAVEN_TEST_COMMAND, environment_spec_violations
    from infosec_harness.domain.models import EnvironmentSpec

    quiet = MAVEN_TEST_COMMAND.replace("mvn -B", "mvn -q -B")
    problems = environment_spec_violations(
        EnvironmentSpec(base_image="maven:3.9", test_command=quiet))
    assert any("-q" in p and "-B" in p for p in problems)


def test_a_maven_command_must_keep_surefire_output_on_stdout():
    """A pom that redirects test output writes the markers to a file the harness never reads."""
    from infosec_harness.agents.validators import MAVEN_TEST_COMMAND, environment_spec_violations
    from infosec_harness.domain.models import EnvironmentSpec

    without = MAVEN_TEST_COMMAND.replace(" -Dmaven.test.redirectTestOutputToFile=false", "")
    problems = environment_spec_violations(
        EnvironmentSpec(base_image="maven:3.9", test_command=without))
    assert any("redirectTestOutputToFile=false" in p for p in problems)


def test_a_gradle_command_below_the_info_log_level_is_rejected():
    """Gradle's Test task forwards a test's standard streams only from INFO up."""
    from infosec_harness.agents.validators import GRADLE_TEST_COMMAND, environment_spec_violations
    from infosec_harness.domain.models import EnvironmentSpec

    default = "./gradlew --no-daemon --offline test --tests '*HarnessProbeTest'"
    problems = environment_spec_violations(
        EnvironmentSpec(base_image="gradle:8-jdk21", test_command=default))
    assert any("-i" in p for p in problems)
    assert environment_spec_violations(
        EnvironmentSpec(base_image="gradle:8-jdk21", test_command=GRADLE_TEST_COMMAND)) == []


def test_a_d_property_is_not_mistaken_for_a_short_flag():
    """`-Dmaven.test.redirectTestOutputToFile=false` contains an 'i' and a 'q'; neither counts."""
    from infosec_harness.agents.validators import _short_flag

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
    from infosec_harness.agents.validators import environment_spec_violations
    from infosec_harness.domain.models import EnvironmentSpec

    for command in ("mvn -B test", "./gradlew --no-daemon -i test"):
        problems = environment_spec_violations(
            EnvironmentSpec(base_image="maven:3.9-eclipse-temurin-21", test_command=command))
        assert any("test class" in p for p in problems), command
        assert not any("{test_file}" in p for p in problems), command


def test_the_stub_models_own_specs_satisfy_the_contract():
    """The stub is the offline stand-in; if the contract rejects it, every offline test lies."""
    from infosec_harness.agents.stubs import _env_plan
    from infosec_harness.agents.validators import (
        environment_spec_violations,
        install_path_violations,
        offline_warmup_violations,
    )
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
    from infosec_harness.agents.validators import install_path_violations
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
    from infosec_harness.agents.validators import install_path_violations
    from infosec_harness.domain.models import EnvironmentSpec

    spec = EnvironmentSpec(base_image="perl:5.38-slim", test_command="prove -v {test_file}",
                           install_commands=["cpanm --notest --installdeps ."])
    problems = install_path_violations(spec)
    assert any("--local-lib" in p for p in problems)
    assert any("PERL5LIB" in p for p in problems)


def test_perl5lib_must_point_at_the_probe_time_path():
    from infosec_harness.agents.validators import install_path_violations
    from infosec_harness.domain.models import EnvironmentSpec

    spec = EnvironmentSpec(
        base_image="perl:5.38-slim", test_command="prove -v {test_file}",
        install_commands=["cpanm --notest --local-lib=/opt/home/perl5 --installdeps ."],
        env={"PERL5LIB": "/opt/home/perl5/lib/perl5"})
    assert any("probe time" in p for p in install_path_violations(spec))


def test_the_recipe_verified_against_the_corpus_passes():
    """This exact spec was built and probed under gVisor: DBI imports, markers reach prove."""
    from infosec_harness.agents.validators import (
        environment_spec_violations,
        install_path_violations,
    )
    from infosec_harness.domain.models import EnvironmentSpec

    spec = EnvironmentSpec(
        base_image="perl:5.38-slim",
        system_packages=["gcc", "make", "libc6-dev"],
        install_commands=["cpanm --notest --local-lib=/opt/home/perl5 --installdeps ."],
        env={"PERL5LIB": "/work/home/perl5/lib/perl5"},
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
    from infosec_harness.agents.validators import (
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
    assert any("surefire-junit-platform" in p for p in problems)
    assert any(MAVEN_WARMUP_COMMAND in p for p in problems), (
        "the violation must name the corrected install command, not just the symptom"
    )


def test_failifnotests_disqualifies_a_warmup_even_with_a_selector():
    """`-DfailIfNoTests=false` turns "no test ran" into a success, which is the whole defect.

    A warm-up carrying both `-Dtest=` and that flag looks right and can still execute nothing —
    and would then go green while leaving the provider unfetched, which is precisely the silent
    shape this check exists to stop coming back.
    """
    from infosec_harness.agents.validators import offline_warmup_violations
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
    from infosec_harness.agents.validators import offline_warmup_violations
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
    from infosec_harness.agents.validators import (
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
    from infosec_harness.agents.validators import (
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
    from infosec_harness.agents.validators import (
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
    from infosec_harness.agents.validators import (
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
    from infosec_harness.agents.validators import _pathish_selector_violation

    msg = _pathish_selector_violation(
        "./gradlew --no-daemon --offline -i test --tests 'src/test/java/FooTest.java'")
    assert msg is not None and "--tests '*FooTest'" in msg, msg


def test_a_proper_class_selector_is_accepted():
    """Guards against over-firing: the canonical commands must stay clean."""
    from infosec_harness.agents.validators import (
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
    from infosec_harness.agents.validators import (
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


def test_a_neutralized_claim_alone_does_not_support_a_safe_verdict():
    """`unreachable` supports safety on its own; `neutralized` must not.

    It says untrusted input arrives and a control stops it — a claim about behaviour that only
    a probe can support. If it were accepted here, a verdict could assert safety on reasoning
    alone, which is precisely the gap the value was introduced to close.
    """
    from infosec_harness.evals.adapters import is_unevidenced_safe

    def case(reachability):
        return {"facts": {"reachability": reachability}, "payload": {}}

    assert not is_unevidenced_safe("verdict", case("unreachable"), "likely_not_exploitable")
    assert is_unevidenced_safe("verdict", case("neutralized"), "likely_not_exploitable"), (
        "a neutralized claim with no probe behind it is an unevidenced safe verdict"
    )


def test_the_jdk_a_base_image_provides_is_read_past_the_build_tool_version():
    """`maven:3.9-...` and `gradle:8-...` lead with the build tool's version, so a naive
    first-number read validates against JDK 3 or JDK 8 and silently passes anything."""
    from infosec_harness.agents.validators import image_jdk_major

    assert image_jdk_major("maven:3.9-eclipse-temurin-17") == 17
    assert image_jdk_major("gradle:8-jdk21") == 21
    assert image_jdk_major("eclipse-temurin:11-jdk") == 11
    assert image_jdk_major("openjdk:8") == 8
    assert image_jdk_major("python:3.12-slim") is None


def test_the_oldest_declared_language_level_is_the_binding_one():
    """A pom with source 7 and target 8 needs a JDK that still accepts 7, so the lower number
    is the constraint."""
    from infosec_harness.agents.validators import declared_java_release

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
    from infosec_harness.agents.validators import jdk_compatibility_violations

    problems = jdk_compatibility_violations("maven:3.9-eclipse-temurin-21", 7)
    assert problems and "no longer supported" in problems[0]
    # Names a working image rather than only the defect, per the house style.
    assert "eclipse-temurin-11" in problems[0]
    # And must not suggest editing the project's compiler level, which changes the subject.
    assert "changes what is being tested" in problems[0]


def test_a_jdk_older_than_the_project_is_rejected_too():
    from infosec_harness.agents.validators import jdk_compatibility_violations

    problems = jdk_compatibility_violations("openjdk:8", 11)
    assert problems and "invalid target release: 11" in problems[0]


def test_a_compatible_pairing_and_an_unreadable_one_are_both_left_alone():
    """Silence when it cannot tell: an unknown image or an undeclared level must not be
    guessed at, because a wrong floor would reject a spec that builds."""
    from infosec_harness.agents.validators import jdk_compatibility_violations

    assert jdk_compatibility_violations("maven:3.9-eclipse-temurin-17", 11) == []
    assert jdk_compatibility_violations("python:3.12-slim", 7) == []
    assert jdk_compatibility_violations("maven:3.9-eclipse-temurin-21", None) == []


def test_the_declared_level_is_read_from_a_real_repository(tmp_path):
    """Multi-module projects keep the compiler properties in the root pom, so the root and one
    level down is where to look."""
    from infosec_harness.agents.validators import repo_java_release

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
