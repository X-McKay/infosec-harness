"""Truthful capability declarations for the four initial unit-probe ecosystems."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from infosec_harness.domain.models import SupportStatus

CapabilityStatus = Literal["implemented", "partial", "declined"]


@dataclass(frozen=True)
class Capability:
    status: CapabilityStatus
    implementation: tuple[str, ...] = ()
    limitation: str = ""


@dataclass(frozen=True)
class EcosystemProfile:
    ecosystem_id: str
    version: str
    support: SupportStatus
    discovery: Capability
    toolchain: Capability
    preparation_plan: Capability
    readiness: Capability
    selector_injection: Capability
    observation_parsing: Capability
    failure_repair: Capability
    compatibility_evidence: Capability
    fixture_refs: tuple[str, ...]
    limitations: tuple[str, ...]

    def identity(self) -> dict[str, str]:
        return {"id": self.ecosystem_id, "version": self.version,
                "support": self.support.value}


_DISCOVERY = Capability("implemented", ("infosec_harness.repo.detect.detect_stack",
                                         "infosec_harness.repo.components.owning_component"))
_PLAN = Capability("partial", ("infosec_harness.domain.models.EnvironmentSpec",
                               "infosec_harness.graph.prepare.run_prepare"),
                   "Plans are typed and validated, but dependency resolution is not locked "
                   "for every repository layout.")
_READINESS = Capability("implemented", ("infosec_harness.workflows.activities.smoke_test_activity",
                                          "infosec_harness.sandbox.canary.canary_for"))
_SELECTOR = Capability("implemented", ("infosec_harness.sandbox.canary.canary_for",
                                         "infosec_harness.agents.validators.validate_probe"))
_OBSERVATIONS = Capability(
    "partial", ("infosec_harness.sandbox.evidence.execution_record",
                "infosec_harness.sandbox.docker.no_tests_executed"),
    "The migration adapter labels oracle markers as self-reported; target binding and exact "
    "discovered/executed test counts are unavailable.")
_REPAIR = Capability("implemented", ("infosec_harness.graph.prepare.run_prepare",
                                      "infosec_harness.graph.triage.RepairEnvironment"))
_COMPATIBILITY = Capability(
    "partial", (),
    "Deterministic fixtures exist, but the real offline positive/negative/environment-failure "
    "matrix required for tested support is incomplete.")


ECOSYSTEM_PROFILES: Mapping[str, EcosystemProfile] = {
    "python": EcosystemProfile(
        ecosystem_id="python-unit-probe", version="1", support=SupportStatus.experimental,
        discovery=_DISCOVERY,
        toolchain=Capability(
            "partial", ("infosec_harness.repo.detect.detect_stack",),
            "Package manifests are detected, but interpreter and lock compatibility are not "
            "resolved for every packaging layout."),
        preparation_plan=_PLAN, readiness=_READINESS, selector_injection=_SELECTOR,
        observation_parsing=_OBSERVATIONS, failure_repair=_REPAIR,
        compatibility_evidence=_COMPATIBILITY,
        fixture_refs=(
            "tests/test_validators.py::test_a_pytest_command_that_captures_output_is_rejected",
            "tests/test_sandbox.py::test_smoke_test_passes_when_the_runner_answers",
        ),
        limitations=("pytest unit probes only", "real isolation acceptance remains separate"),
    ),
    "java": EcosystemProfile(
        ecosystem_id="jvm-unit-probe", version="1", support=SupportStatus.experimental,
        discovery=_DISCOVERY,
        toolchain=Capability(
            "partial", ("infosec_harness.repo.detect.declared_java_release",
                        "infosec_harness.agents.ecosystem_contract.repo_jvm_test_framework"),
            "Declared Java levels and common frameworks are checked; wrappers, plugins, and "
            "multi-module dependency resolution are not fully resolved."),
        preparation_plan=_PLAN, readiness=_READINESS, selector_injection=_SELECTOR,
        observation_parsing=_OBSERVATIONS, failure_repair=_REPAIR,
        compatibility_evidence=_COMPATIBILITY,
        fixture_refs=(
            "tests/test_detect_polyglot.py::test_components_keep_distinct_declared_java_releases",
            "tests/test_validators.py::test_the_stub_java_plan_is_read_from_the_fingerprint_and_survives_its_own_validators",
        ),
        limitations=("Maven/Gradle unit probes only", "compatibility matrix is experimental"),
    ),
    "javascript": EcosystemProfile(
        ecosystem_id="javascript-unit-probe", version="1", support=SupportStatus.experimental,
        discovery=_DISCOVERY,
        toolchain=Capability(
            "partial", ("infosec_harness.repo.detect.js_test_runners",
                        "infosec_harness.agents.ecosystem_contract.repo_js_runners"),
            "Declared runners and lockfiles are inspected; package-manager/runtime/workspace "
            "compatibility is not resolved for every layout."),
        preparation_plan=_PLAN, readiness=_READINESS, selector_injection=_SELECTOR,
        observation_parsing=_OBSERVATIONS, failure_repair=_REPAIR,
        compatibility_evidence=_COMPATIBILITY,
        fixture_refs=(
            "tests/test_detect_polyglot.py::test_a_lockfile_makes_the_install_reproducible",
            "tests/test_validators.py::test_an_honest_probe_in_either_language_is_accepted",
        ),
        limitations=("supported runner shapes are bounded", "workspace coverage is incomplete"),
    ),
    "perl": EcosystemProfile(
        ecosystem_id="perl-unit-probe", version="1", support=SupportStatus.experimental,
        discovery=_DISCOVERY,
        toolchain=Capability(
            "partial", ("infosec_harness.repo.detect.detect_stack",
                        "infosec_harness.agents.ecosystem_contract.install_path_violations"),
            "Test dialect and local-lib paths are checked; Perl/runtime and distribution "
            "compatibility are not resolved broadly."),
        preparation_plan=_PLAN, readiness=_READINESS, selector_injection=_SELECTOR,
        observation_parsing=_OBSERVATIONS, failure_repair=_REPAIR,
        compatibility_evidence=_COMPATIBILITY,
        fixture_refs=(
            "tests/test_detect_polyglot.py::test_the_perl_plan_names_the_module_root",
            "tests/test_validators.py::test_a_test_more_probe_with_no_plan_is_rejected",
        ),
        limitations=("prove-based unit probes only", "distribution coverage is incomplete"),
    ),
}

_LANGUAGE_PROFILE_ALIASES = {"typescript": "javascript"}


def profile_manifest(languages: Mapping[str, int]) -> dict:
    """Return recognized profile identities and explicit unsupported language observations."""
    present = sorted(language for language, count in languages.items() if count > 0)
    canonical = sorted({
        _LANGUAGE_PROFILE_ALIASES.get(language, language)
        for language in present
        if _LANGUAGE_PROFILE_ALIASES.get(language, language) in ECOSYSTEM_PROFILES
    })
    profiles = [ECOSYSTEM_PROFILES[language].identity() for language in canonical]
    unmapped = [{"language": language, "support": SupportStatus.unsupported.value}
                for language in present
                if _LANGUAGE_PROFILE_ALIASES.get(language, language) not in ECOSYSTEM_PROFILES]
    return {"profiles": profiles, "unmapped_languages": unmapped}
