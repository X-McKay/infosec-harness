from infosec_harness.agents.ecosystem_profiles import ECOSYSTEM_PROFILES, profile_manifest


def test_each_supported_language_maps_to_one_distinct_profile():
    assert set(ECOSYSTEM_PROFILES) == {"python", "java", "javascript", "perl"}
    assert len(set(ECOSYSTEM_PROFILES.values())) == len(ECOSYSTEM_PROFILES)


def test_profile_manifest_marks_unknown_languages_unsupported_without_guessing():
    manifest = profile_manifest({"ruby": 4, "python": 2, "empty": 0})
    assert manifest["profiles"] == [{"id": "python-unit-probe", "support": "experimental"}]
    assert manifest["unmapped_languages"] == [{"language": "ruby", "support": "unsupported"}]


def test_typescript_uses_the_javascript_profile_once_for_mixed_components():
    manifest = profile_manifest({"javascript": 2, "typescript": 5})
    assert manifest == {
        "profiles": [{"id": "javascript-unit-probe", "support": "experimental"}],
        "unmapped_languages": [],
    }
