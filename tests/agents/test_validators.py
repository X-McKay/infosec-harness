import pytest

from infosec_harness.domain.models import (
    CodeRef,
    DiagnosisKind,
    InconclusiveReason,
    Reachability,
    Verdict,
    VerdictFacts,
    VerdictLabel,
)
from infosec_harness.runtime.validators import verdict_violations
from infosec_harness.sandbox.output import no_tests_executed


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

    from infosec_harness.runtime.validators import NO_FACTS_VIOLATION, validate_verdict

    ctx = SimpleNamespace(deps=SimpleNamespace(facts=None))
    with pytest.raises(ModelRetry) as error:
        validate_verdict(ctx, v(label))
    assert NO_FACTS_VIOLATION in error.value.message
    inconclusive = v(VerdictLabel.inconclusive,
                     inconclusive_reason=InconclusiveReason.conflicting_evidence)
    assert validate_verdict(ctx, inconclusive) is inconclusive


def test_the_no_facts_rule_matches_the_offered_tools():
    from infosec_harness.runtime.outputs import allowed_verdict_labels

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


def test_partial_build_rejects_the_shared_full_scope_default():
    from pydantic_ai import ModelRetry

    from infosec_harness.domain.models import EnvironmentSpec
    from infosec_harness.runtime.validators import validate_partial_build_scope

    spec = EnvironmentSpec(
        base_image="python:3.12-slim",
        test_command="python -m pytest -q -s -o addopts= {test_file}",
    )
    with pytest.raises(ModelRetry, match="scope.*partial"):
        validate_partial_build_scope(None, spec)


@pytest.mark.parametrize("module_path", [None, "", "   "])
def test_partial_build_rejects_missing_or_blank_module_path(module_path):
    from pydantic_ai import ModelRetry

    from infosec_harness.domain.models import EnvironmentSpec
    from infosec_harness.runtime.validators import validate_partial_build_scope

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
    from infosec_harness.domain.models import EnvironmentSpec
    from infosec_harness.runtime.validators import validate_partial_build_scope

    spec = EnvironmentSpec(
        base_image="python:3.12-slim",
        test_command="python -m pytest -q -s -o addopts= {test_file}",
        scope="partial",
        module_path=module_path,
    )
    assert validate_partial_build_scope(None, spec) is spec


async def test_partial_build_stub_runs_through_its_validator_with_a_root_module(tmp_path):
    """The offline agent must satisfy the role-specific output contract it exercises."""
    from infosec_harness.domain.models import StackFingerprint
    from infosec_harness.runtime.deps import AgentDeps
    from infosec_harness.runtime.registry import build_agent
    from infosec_harness.runtime.render import render_prompt

    stack = StackFingerprint(languages={"python": 1}, manifests=["requirements.txt"])
    result = await build_agent("partial-build", durable=False).run(
        render_prompt("narrow the failed environment", {"stack_fingerprint": stack}, stack=stack),
        deps=AgentDeps(repo_path=str(tmp_path)),
    )
    assert result.output.scope == "partial"
    assert result.output.module_path == "."


def test_partial_build_stub_preserves_a_failed_spec_module_path():
    from infosec_harness.runtime.stubs import _partial_build_plan

    text = '<failed_spec>\n{"scope": "full", "module_path": "services/api"}\n</failed_spec>'
    assert _partial_build_plan(text)["module_path"] == "services/api"


def test_surefires_own_no_match_wording_is_recognised_as_a_zero_test_run():
    """The two halves must meet: the validator stops the bad selector being written, and if one
    slips through, the runner's output is still classified rather than left to be inferred."""

    output = ('[ERROR] No tests matching pattern "src/test/java/com/example/UserDaoTest.java" '
              'were executed!\n')
    reason = no_tests_executed(output)
    assert reason is not None and "matched no test class" in reason
    assert "not a negative result" in reason


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


def test_the_oldest_declared_language_level_is_the_binding_one():
    """A pom with source 7 and target 8 needs a JDK that still accepts 7, so the lower number
    is the constraint."""
    from infosec_harness.repo.detect import declared_java_release

    pom = ("<properties><maven.compiler.source>1.7</maven.compiler.source>"
           "<maven.compiler.target>1.8</maven.compiler.target></properties>")
    assert declared_java_release(pom) == 7
    assert declared_java_release("sourceCompatibility = 1.8") == 8
    assert declared_java_release("languageVersion = JavaLanguageVersion.of(17)") == 17
    assert declared_java_release("<groupId>org.example</groupId>") is None


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
