"""Harvested corpus cases: remote checkouts, and the leakage guard that makes them meaningful.

A benchmark like Vul4J establishes its ground truth with a proof-of-vulnerability test. On a
`-fixed` revision that test is in the repository by construction, because the fix commit added
it — measured: 53 of Vul4J's 58 usable entries. An agent handed that checkout can copy the test
instead of writing a probe, and `probe-author` then measures transcription. Stripping those
paths before anything reads the tree is what makes the case worth scoring at all.
"""
import json
from pathlib import Path

import pytest

from infosec_harness.domain.models import RepoRef
from infosec_harness.evals.corpus import load_corpus
from infosec_harness.repo.checkout import checkout
from infosec_harness.settings import REPO_ROOT

VUL4J = REPO_ROOT / "eval-corpus" / "external" / "vul4j.json"
pytestmark = pytest.mark.skipif(not VUL4J.is_file(), reason="vul4j.json not harvested")


def _cases():
    return load_corpus(manifest_path=VUL4J, dataset="vul4j")


def test_a_harvested_case_keeps_its_remote_url_intact():
    """Resolving a URL against the repo root yields `<repo>/https:/github.com/...`, which then
    fails to clone with a message about a missing directory rather than about a URL."""
    for case in _cases()[:5]:
        assert case.finding.repo_url.startswith("https://"), case.finding.repo_url
        assert not case.is_vendored
        with pytest.raises(ValueError, match="no path in this repository"):
            _ = case.repo_path


def test_harvested_revisions_are_commits_rather_than_a_branch_name():
    """`HEAD` would silently re-point as upstream moves, so a benchmark case that used it would
    stop being the revision its ground truth describes."""
    for case in _cases():
        assert case.finding.revision != "HEAD", case.name
        assert len(case.finding.revision) >= 7, f"{case.name}: {case.finding.revision}"


def test_quarantined_entries_are_never_loaded_as_cases():
    """They exist precisely because they are not safe to run: their PoV is present at the
    *vulnerable* revision, so the exploit is in the tree the agent reads."""
    doc = json.loads(VUL4J.read_text())
    assert doc.get("quarantined"), "expected quarantined entries to be recorded, not dropped"
    loaded = {c.name for c in _cases()}
    for entry in doc["quarantined"]:
        name = entry.get("name") or entry.get("id") or ""
        assert name not in loaded, f"{name} is quarantined but was loaded as a case"


def test_the_fixed_half_of_a_pair_carries_the_paths_that_must_be_stripped():
    cases = {c.name: c for c in _cases()}
    masked = [c for c in cases.values() if c.mask_paths]
    assert masked, "no case carries mask_paths; the leakage guard would be inert"
    for case in masked:
        for rel in case.mask_paths:
            assert not rel.startswith("/"), f"{case.name}: {rel} is absolute"
            assert ".." not in Path(rel).parts, f"{case.name}: {rel} escapes the checkout"


async def test_checkout_strips_the_masked_paths_before_anything_reads_the_tree(tmp_path):
    """The guard itself, against a real checkout."""
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "App.java").write_text("class App {}\n")
    pov = repo / "src" / "test" / "PoVTest.java"
    pov.parent.mkdir(parents=True)
    pov.write_text("class PoVTest { /* the answer */ }\n")

    unmasked = await checkout(RepoRef(repo_url=str(repo), revision="HEAD"))
    assert (Path(unmasked.path) / "src/test/PoVTest.java").is_file()

    masked = await checkout(RepoRef(repo_url=str(repo), revision="HEAD",
                                    exclude_paths=["src/test/PoVTest.java"]))
    assert not (Path(masked.path) / "src/test/PoVTest.java").exists()
    assert (Path(masked.path) / "src/App.java").is_file(), "masking removed more than it should"
    # The hash identifies the tree downstream, so a masked checkout must not be mistaken for
    # the unmasked one.
    assert masked.content_hash != unmasked.content_hash


async def test_a_mask_path_cannot_escape_the_checkout(tmp_path):
    """The list comes from a dataset, which is untrusted input like any other."""
    outside = tmp_path / "secret.txt"
    outside.write_text("do not delete me")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.txt").write_text("x")

    await checkout(RepoRef(repo_url=str(repo), revision="HEAD",
                           exclude_paths=["../secret.txt", "/etc/hosts"]))
    assert outside.is_file(), "a mask path escaped the checkout"


def test_the_dataset_label_is_recorded_rather_than_rewritten_to_suit_our_scorer():
    """Vul4J spans far more CWEs than our eight skills. Relabelling a dataset's classification
    so the scorer is happy would be inventing ground truth, so coverage is recorded instead."""
    cases = _cases()
    statuses = {c.cwe_coverage for c in cases}
    assert statuses <= {"covered", "adjacent", "uncovered"}, statuses
    assert any(c.cwe_coverage == "uncovered" for c in cases), (
        "every harvested CWE is covered, which means the label was rewritten"
    )
    assert all(c.dataset == "vul4j" for c in cases)


def test_harness_ui_directory_rename_preserves_upstream_java_source_paths():
    """These paths belong to immutable upstream revisions, not the harness frontend.

    Vul4J's Apache Shiro and Spring fixtures retain their original Java package and module
    paths. Replacing web/ during a local layout change would target nonexistent upstream files.
    """
    shiro = [case for case in _cases() if case.finding.repo_url.endswith("apache/shiro.git")]
    assert shiro
    for case in shiro:
        assert case.finding.file_path == "web/src/main/java/org/apache/shiro/web/util/WebUtils.java"
        assert case.sink_file == case.finding.file_path
    spring = [case for case in _cases()
              if case.finding.repo_url.endswith("spring-projects/spring-framework.git")
              and case.finding.file_path.endswith("/ResourceServlet.java")]
    assert spring
    for case in spring:
        assert "/org/springframework/web/" in case.finding.file_path
        assert "/org/springframework/ui/" not in case.finding.file_path
