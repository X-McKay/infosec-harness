"""Detection reads untrusted manifests through the same confined snapshot boundary."""

import json

import pytest

from infosec_harness.repo.access import RepositoryAccessError
from infosec_harness.repo.detect import detect_stack, java_build_texts, js_test_runners


@pytest.mark.parametrize("package", [[], None, 3, {"scripts": ["jest"]},
                                     {"scripts": "jest"}, {"scripts": {"test": ["jest"]}}])
def test_malformed_package_fields_do_not_crash_or_invent_a_runner(tmp_path, package):
    (tmp_path / "package.json").write_text(json.dumps(package))
    assert js_test_runners(tmp_path) == []
    assert detect_stack(str(tmp_path)).test_frameworks == []


def test_package_description_is_not_a_dependency_declaration(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "description": "Migrated away from jest and mocha",
        "devDependencies": {"vitest": "^2"},
    }))
    assert js_test_runners(tmp_path) == ["vitest"]


@pytest.mark.parametrize(("reader", "name"), [(java_build_texts, "pom.xml"),
                                               (js_test_runners, "package.json")])
def test_standalone_detection_rejects_escaping_manifest_links(tmp_path, reader, name):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "private"
    outside.write_text('{"scripts":{"test":"jest"}}')
    (repo / name).symlink_to(outside)
    with pytest.raises(RepositoryAccessError, match="unsafe repository link"):
        reader(repo)


def test_java_helper_and_fingerprint_share_candidates(tmp_path):
    (tmp_path / "module").mkdir()
    (tmp_path / "module" / "build.gradle.kts").write_text(
        'java { toolchain { languageVersion = JavaLanguageVersion.of(17) } }')
    assert len(java_build_texts(tmp_path)) == 1
    assert detect_stack(str(tmp_path)).java_release == 17


def test_gradle_kotlin_framework_is_detected_from_its_declared_runner(tmp_path):
    (tmp_path / "build.gradle.kts").write_text('tasks.test { useJUnitPlatform() }')
    assert detect_stack(str(tmp_path)).test_frameworks == ["junit5"]
