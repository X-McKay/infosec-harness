import importlib
from dataclasses import fields
from pathlib import Path

from infosec_harness.agents.ecosystem_profiles import (
    ECOSYSTEM_PROFILES,
    Capability,
    EcosystemProfile,
    profile_manifest,
)
from infosec_harness.domain.models import SupportStatus

CAPABILITIES = {
    "discovery",
    "toolchain",
    "preparation_plan",
    "readiness",
    "selector_injection",
    "observation_parsing",
    "failure_repair",
    "compatibility_evidence",
}


def test_four_experimental_profiles_declare_every_capability_and_real_fixture():
    assert set(ECOSYSTEM_PROFILES) == {"python", "java", "javascript", "perl"}
    assert {field.name for field in fields(EcosystemProfile)} >= CAPABILITIES
    identities = set()
    root = Path(__file__).parents[1]
    for profile in ECOSYSTEM_PROFILES.values():
        assert profile.support is SupportStatus.experimental
        assert profile.version and (profile.ecosystem_id, profile.version) not in identities
        identities.add((profile.ecosystem_id, profile.version))
        assert profile.fixture_refs and profile.limitations
        for name in CAPABILITIES:
            capability = getattr(profile, name)
            assert isinstance(capability, Capability)
            if capability.status == "implemented":
                assert capability.implementation
            else:
                assert capability.limitation
            for reference in capability.implementation:
                module_name, _, attribute = reference.rpartition(".")
                assert getattr(importlib.import_module(module_name), attribute)
        for reference in profile.fixture_refs:
            path, separator, test_name = reference.partition("::")
            assert separator and (root / path).is_file()
            assert f"def {test_name}(" in (root / path).read_text()


def test_profile_manifest_marks_unknown_languages_unsupported_without_guessing():
    manifest = profile_manifest({"ruby": 4, "python": 2, "empty": 0})
    assert manifest["profiles"] == [
        {"id": "python-unit-probe", "version": "1", "support": "experimental"}
    ]
    assert manifest["unmapped_languages"] == [
        {"language": "ruby", "support": "unsupported"}
    ]


def test_typescript_uses_the_javascript_profile_once_for_mixed_components():
    manifest = profile_manifest({"javascript": 2, "typescript": 5})
    assert manifest == {
        "profiles": [
            {"id": "javascript-unit-probe", "version": "1", "support": "experimental"}
        ],
        "unmapped_languages": [],
    }
