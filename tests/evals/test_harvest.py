"""Tests for the Vul4J corpus harvester.

These run against `eval-corpus/external/vul4j_excerpt.csv` and a fake GitHub resolver, never
the network: a test that needs GitHub to be up and a token to be present is a test that gets
skipped, and the properties asserted here — the pair convention, real SHAs, attribution on
every case, and the leakage quarantine — are exactly the ones we cannot afford to have
quietly skipped.

The fake's commit payloads are hand-written to the shape of the GitHub API. They are not
recordings of upstream responses, so nothing here carries anyone else's licence.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
EXCERPT = REPO_ROOT / "eval-corpus" / "external" / "vul4j_excerpt.csv"

_spec = importlib.util.spec_from_file_location("harvest_vul4j", REPO_ROOT / "scripts" / "harvest_vul4j.py")
harvest_vul4j = importlib.util.module_from_spec(_spec)
# `scripts/` is not a package, so register the module before executing it: `@dataclass`
# resolves annotations through `sys.modules[cls.__module__]` and fails if it is not there.
sys.modules[_spec.name] = harvest_vul4j
_spec.loader.exec_module(harvest_vul4j)

COVERED = harvest_vul4j.FALLBACK_COVERED_CWES

SHA40 = re.compile(r"^[0-9a-f]{40}$")

# Full SHAs for the excerpt's five resolvable entries, plus their parents. `fix` is what the
# resolver reports as the canonical SHA; VUL4J-15's dataset row records only `d9e2a6e7`, which
# is the point of including it.
COMMITS = {
    "VUL4J-5": ("a080293da69f3fe3d11d5214432e1469ee195870", "1111111111111111111111111111111111111111"),
    "VUL4J-6": ("2a2f1dc48e22a34ddb72321a4db211da91aa933b", "2222222222222222222222222222222222222222"),
    "VUL4J-15": ("d9e2a6e7000000000000000000000000000000ab", "3333333333333333333333333333333333333333"),
    "VUL4J-42": ("b38a1b3a4352303e4312b2bb601a0d7ec6e28f41", "4444444444444444444444444444444444444444"),
    "VUL4J-53": ("e5046911c57e60a1d6d8aca9b21bd9093b0f3763", "5555555555555555555555555555555555555555"),
}

EXPANDER_TEST = "src/test/java/org/apache/commons/compress/archivers/examples/ExpanderTest.java"
ATOM_TEST = ("rt/rs/extensions/providers/src/test/java/org/apache/cxf/jaxrs/provider/atom/"
             "AtomPojoProviderTest.java")
COMMANDLINE_TEST = "src/test/java/org/codehaus/plexus/util/cli/CommandlineTest.java"
CRONTAB_TEST = "core/src/test/java/hudson/scheduler/CronTabTest.java"


def _commit(sha: str, parent: str, files: list[dict]) -> dict:
    return {"sha": sha, "parents": [{"sha": parent}], "files": files}


def _java(path: str, status: str, line: int = 40, changes: int = 20) -> dict:
    return {"filename": path, "status": status, "changes": changes,
            "patch": f"@@ -{line},4 +{line},6 @@ some context\n+    // changed\n"}


class FakeResolver:
    """Stands in for `GitHubResolver`, answering from fixtures and counting what was asked."""

    def __init__(self, commits: dict, files: dict, trees: dict | None = None) -> None:
        self.commits, self.files, self.trees = commits, files, trees or {}

    def commit(self, slug: str, sha: str) -> dict:
        try:
            return self.commits[(slug, sha)]
        except KeyError:
            raise LookupError(f"commit {slug}@{sha} not found") from None

    def file_at(self, slug: str, ref: str, path: str) -> str | None:
        return self.files.get((slug, ref, path))

    def tree(self, slug: str, ref: str) -> tuple[list[str], bool]:
        return self.trees.get((slug, ref), ([], False))


@pytest.fixture(scope="module")
def entries() -> list:
    return harvest_vul4j.parse_dataset(EXCERPT.read_text())


@pytest.fixture(scope="module")
def resolver() -> FakeResolver:
    cc = "apache/commons-compress"
    fix5, par5 = COMMITS["VUL4J-5"]
    fix6, par6 = COMMITS["VUL4J-6"]
    fix15, par15 = COMMITS["VUL4J-15"]
    fix42, par42 = COMMITS["VUL4J-42"]
    fix53, par53 = COMMITS["VUL4J-53"]
    commits = {
        # VUL4J-5: the fix adds the PoV test file outright. The clean case.
        (cc, fix5): _commit(fix5, par5, [
            _java("src/main/java/org/apache/commons/compress/archivers/examples/Expander.java", "modified", 118),
            _java(EXPANDER_TEST, "added"),
        ]),
        # VUL4J-6: the fix touches no test at all; Vul4J wrote `Test_CVE_2018_1324` themselves.
        (cc, fix6): _commit(fix6, par6, [
            _java("src/main/java/org/apache/commons/compress/archivers/zip/X0017_StrongEncryptionHeader.java",
                  "modified", 210),
        ]),
        # VUL4J-15: the dataset records an abbreviated SHA; the API answers with the full one.
        ("apache/cxf", "d9e2a6e7"): _commit(fix15, par15, [
            _java("rt/rs/extensions/providers/src/main/java/org/apache/cxf/jaxrs/provider/atom/"
                  "AtomPojoProvider.java", "modified", 92),
            _java(ATOM_TEST, "modified"),
        ]),
        # VUL4J-42: the PoV method is already in the tree before the fix. The leakage case.
        ("codehaus-plexus/plexus-utils", fix42): _commit(fix42, par42, [
            _java("src/main/java/org/codehaus/plexus/util/cli/shell/BourneShell.java", "modified", 60),
            _java(COMMANDLINE_TEST, "modified"),
        ]),
        # VUL4J-53: the fix adds the PoV method to a test file that already existed.
        ("jenkinsci/jenkins", fix53): _commit(fix53, par53, [
            _java("core/src/main/java/hudson/scheduler/CronTab.java", "modified", 300),
            _java(CRONTAB_TEST, "modified"),
        ]),
    }
    files = {
        ("apache/cxf", par15, ATOM_TEST): "public class AtomPojoProviderTest {\n  void other() {}\n}\n",
        ("codehaus-plexus/plexus-utils", par42, COMMANDLINE_TEST):
            "public class CommandlineTest {\n  public void testGetShellCommandLineBash() {}\n}\n",
        ("jenkinsci/jenkins", par53, CRONTAB_TEST):
            "public class CronTabTest {\n  public void testAnotherThing() {}\n}\n",
    }
    return FakeResolver(commits, files)


@pytest.fixture(scope="module")
def result(entries, resolver):
    return harvest_vul4j.harvest(entries, resolver, COVERED)


def test_excerpt_parses_in_stable_numeric_order(entries):
    assert [e.vul_id for e in entries] == [
        "VUL4J-5", "VUL4J-6", "VUL4J-15", "VUL4J-27", "VUL4J-29", "VUL4J-42", "VUL4J-53", "VUL4J-80-S"]


def test_every_case_is_half_of_a_pair(result):
    names = [c["name"] for c in result.cases]
    assert len(names) == len(set(names)), "case names must be unique"
    bases = {n.rsplit("-", 1)[0] for n in names}
    for base in bases:
        assert f"{base}-vulnerable" in names
        assert f"{base}-fixed" in names


def test_the_pair_differs_only_in_revision_and_verdict(result):
    by_name = {c["name"]: c for c in result.cases}
    vuln, fixed = by_name["vul4j-5-vulnerable"], by_name["vul4j-5-fixed"]
    assert vuln["truth"]["expected_verdict"] == "potentially_exploitable"
    assert vuln["truth"]["reachability"] == "reachable"
    assert fixed["truth"]["expected_verdict"] == "likely_not_exploitable"
    assert fixed["truth"]["reachability"] == "neutralized"
    assert vuln["finding"]["repo_url"] == fixed["finding"]["repo_url"]
    assert vuln["finding"]["cwe"] == fixed["finding"]["cwe"]
    # The vulnerable revision is the fix commit's parent, not some other point in history.
    fix, parent = COMMITS["VUL4J-5"]
    assert vuln["finding"]["revision"] == parent
    assert fixed["finding"]["revision"] == fix


def test_revisions_are_real_commit_shas(result):
    for case in result.cases + result.quarantined:
        rev = case["finding"]["revision"]
        assert rev != "HEAD", f"{case['name']} points at a moving revision"
        assert SHA40.match(rev), f"{case['name']} revision {rev!r} is not a full commit SHA"


def test_abbreviated_dataset_shas_are_expanded(result):
    """Vul4J records some fix commits abbreviated, one of them to eight characters.

    An abbreviated SHA resolves today and may not resolve later, and it is not the identity
    of the commit. The harvester keeps what the API reports as canonical.
    """
    fixed = next(c for c in result.cases if c["name"] == "vul4j-15-fixed")
    assert fixed["finding"]["revision"] == COMMITS["VUL4J-15"][0]
    assert "d9e2a6e7" in fixed["source"]["human_patch_url"], "the abbreviated original stays on record"


def test_every_case_carries_attribution(result):
    for case in result.cases + result.quarantined:
        source = case["source"]
        assert source["dataset"] == "vul4j"
        assert "Bui" in source["authors"] and "MSR 2022" in source["authors"]
        assert source["url"] == "https://github.com/tuhh-softsec/vul4j"
        assert "CC-BY-4.0" in source["licence"]
        assert source["entry_id"].startswith("VUL4J-")
        assert source["fix_commit"] and source["vulnerable_commit"]


def test_a_pov_present_at_the_vulnerable_revision_is_quarantined(result):
    """VUL4J-42's `testGetShellCommandLineBash` predates its fix, so the entry is not usable."""
    assert not any(c["source"]["entry_id"] == "VUL4J-42" for c in result.cases)
    quarantined = [c for c in result.quarantined if c["source"]["entry_id"] == "VUL4J-42"]
    assert len(quarantined) == 2, "the whole pair is withheld, not just the vulnerable half"
    for case in quarantined:
        assert case["truth"]["pov"]["origin"] == "pre-existing"
        assert "already present at the vulnerable revision" in case["quarantine_reason"]
    assert quarantined[0]["truth"]["pov"]["present_at_revision"] is True


def test_an_unverifiable_pov_is_quarantined_too(entries, resolver):
    """A tree we could not enumerate is treated exactly like one we caught leaking."""
    truncated = FakeResolver(
        {k: v for k, v in resolver.commits.items() if k[0] == "apache/commons-compress"},
        {},
        trees={("apache/commons-compress", COMMITS["VUL4J-6"][1]): ([], True)},
    )
    only_six = [e for e in entries if e.vul_id == "VUL4J-6"]
    out = harvest_vul4j.harvest(only_six, truncated, COVERED)
    assert out.cases == []
    assert all(c["truth"]["pov"]["present_at_revision"] is None for c in out.quarantined)
    assert "unverified is not the same as safe" in out.quarantined[0]["quarantine_reason"]


def test_pov_origin_is_recorded_for_the_cases_we_keep(result):
    by_entry = {c["source"]["entry_id"]: c for c in result.cases if c["name"].endswith("-vulnerable")}
    # The fix adds the file; the fix adds the method to an existing file; nobody upstream has it.
    assert by_entry["VUL4J-5"]["truth"]["pov"]["origin"] == "fix-commit"
    assert by_entry["VUL4J-53"]["truth"]["pov"]["origin"] == "fix-commit"
    assert by_entry["VUL4J-6"]["truth"]["pov"]["origin"] == "not-in-repository"
    for case in result.cases:
        assert case["truth"]["pov"]["present_at_revision"] is not None


def test_kept_vulnerable_cases_never_contain_the_pov(result):
    for case in result.cases:
        if case["name"].endswith("-vulnerable"):
            assert case["truth"]["pov"]["present_at_revision"] is False


def test_fixed_cases_admit_the_pov_is_in_the_tree(result):
    """The fix commit adds the PoV, so on the fixed side it is always visible to the agent.

    Nothing the harvester can do prevents that, which is why the mask paths are recorded and
    the note spells out that consumers have to apply them.
    """
    fixed = {c["source"]["entry_id"]: c for c in result.cases if c["name"].endswith("-fixed")}
    for entry_id in ("VUL4J-5", "VUL4J-53"):
        case = fixed[entry_id]
        assert case["truth"]["pov"]["present_at_revision"] is True
        assert case["truth"]["pov"]["mask_paths"], "a visible PoV must name a path to mask"
    # The exception: a PoV that exists in neither revision because Vul4J wrote it.
    assert fixed["VUL4J-6"]["truth"]["pov"]["present_at_revision"] is False


def test_skipped_entries_say_why(result):
    reasons = {s["entry_id"]: s["reason"] for s in result.skipped}
    assert "static-analysis-warning subset" in reasons["VUL4J-80-S"]
    assert "commit range" in reasons["VUL4J-27"]
    assert "Vul4J-owned mirror" in reasons["VUL4J-29"]
    assert set(reasons) | {c["source"]["entry_id"] for c in result.cases + result.quarantined} == {
        "VUL4J-5", "VUL4J-6", "VUL4J-15", "VUL4J-27", "VUL4J-29", "VUL4J-42", "VUL4J-53", "VUL4J-80-S"}


def test_cwe_coverage_is_marked_not_rewritten(result):
    coverage = {c["source"]["entry_id"]: c["cwe_coverage"] for c in result.cases}
    findings = {c["source"]["entry_id"]: c["finding"] for c in result.cases}
    assert coverage["VUL4J-15"]["status"] == "covered"      # CWE-611, we ship the skill
    assert coverage["VUL4J-6"]["status"] == "uncovered"     # CWE-835, we do not
    assert coverage["VUL4J-6"]["cwe"] is None
    # The dataset's own classification is never overwritten to suit our scorer.
    assert findings["VUL4J-6"]["cwe"] == "CWE-835"
    assert findings["VUL4J-5"]["cwe"] == "Not Mapping"


def test_the_one_cwe_mapping_we_allow_is_marked_adjacent():
    adjacent = harvest_vul4j.classify_cwe("CWE-77", COVERED)
    assert adjacent["status"] == "adjacent"
    assert adjacent["cwe"] == "CWE-78"
    assert harvest_vul4j.classify_cwe("CWE-74", COVERED)["status"] == "uncovered"


def test_no_build_recipe_is_carried_over(result):
    """The whole point of harvesting facts rather than Vul4J's environment.

    If a `mvn` invocation ever appears in the output, env-planner and build-repair stop being
    measured on these cases and we would not notice from the scores alone.
    """
    blob = json.dumps(harvest_vul4j.render(result))
    for recipe in ("mvn ", "gradle ", "-DskipTests", "-Denforcer.skip", "./gradlew"):
        assert recipe not in blob
    build = next(c["build"] for c in result.cases)
    assert build["system"] in {"maven", "gradle"} and build["jdk"]


def test_harvest_is_deterministic(entries, resolver):
    first = json.dumps(harvest_vul4j.render(harvest_vul4j.harvest(entries, resolver, COVERED)), indent=2)
    second = json.dumps(harvest_vul4j.render(harvest_vul4j.harvest(entries, resolver, COVERED)), indent=2)
    assert first == second
    assert "generated_at" not in first, "a timestamp would make every re-run a diff"


def test_the_written_corpus_matches_the_schema_the_loader_expects():
    """The committed output has to keep the shape `eval-corpus/manifest.json` uses."""
    written = json.loads((REPO_ROOT / "eval-corpus" / "external" / "vul4j.json").read_text())
    assert written["version"] == "1"
    assert "MUST NOT be exposed to any agent" in written["note"]
    assert written["cases"], "the committed harvest should not be empty"
    for case in written["cases"]:
        assert case["language"] == "java"
        assert set(case["finding"]) >= {"title", "repo_url", "revision", "cwe"}
        assert set(case["truth"]) >= {"expected_verdict", "reachability", "sink_file", "sink_line",
                                      "target_callable", "pov"}
        assert case["finding"]["repo_url"].startswith("https://github.com/")
        assert SHA40.match(case["finding"]["revision"])


def test_the_test_framework_is_read_from_the_module_pom_and_its_enclosing_poms():
    """`build.test_framework` is as load-bearing as `build.jdk`, and it has to be *read*.

    The Maven recipe's warm-up is compiled against the project's own test classpath, so a JUnit 5
    warm-up in a JUnit 4 project fails `test-compile` with "cannot find symbol: class Test" and no
    image is ever built (measured). 43 of the 58 harvested entries are JUnit 4 and one is JUnit 5,
    so a consumer that assumes JUnit 5 fails essentially the whole harvest.

    Innermost first, then upwards: a multi-module project often declares the shared test dependency
    at an intermediate level rather than in the module or the root -- onos declares it in
    `protocols/pom.xml`, which is why walking up matters and reading only the two ends does not.
    """
    entry = harvest_vul4j.Entry(
        vul_id="VUL4J-63", cve_id="", cwe_id="CWE-20", cwe_name="", repo_slug="opennetworkinglab/onos",
        human_patch="", build_system="Maven", jdk="8", failing_tests=(),
        module="protocols/ovsdb/rfc", src_dir="", test_dir="")
    jupiter = ("<dependency><groupId>org.junit.jupiter</groupId>"
               "<artifactId>junit-jupiter</artifactId></dependency>")
    junit4 = "<dependency><groupId>junit</groupId><artifactId>junit</artifactId></dependency>"

    intermediate = FakeResolver({}, {
        ("opennetworkinglab/onos", "abc", "protocols/pom.xml"): junit4,
        ("opennetworkinglab/onos", "abc", "pom.xml"): jupiter,
    })
    assert harvest_vul4j.detect_test_framework(entry, intermediate, "abc") == "junit4", (
        "the nearest enclosing pom that declares a framework wins over the root"
    )

    module_only = FakeResolver({}, {
        ("opennetworkinglab/onos", "abc", "protocols/ovsdb/rfc/pom.xml"): jupiter,
        ("opennetworkinglab/onos", "abc", "pom.xml"): junit4,
    })
    assert harvest_vul4j.detect_test_framework(entry, module_only, "abc") == "junit5"

    root_only = FakeResolver({}, {("opennetworkinglab/onos", "abc", "pom.xml"): junit4})
    assert harvest_vul4j.detect_test_framework(entry, root_only, "abc") == "junit4"

    # Nothing declared anywhere the harvester can see: `null`, not a guess. 11 of the 58 entries
    # are like this -- a parent pom outside the repository declares it -- and recording a guess as
    # a dataset fact is worse than recording that it is unknown.
    assert harvest_vul4j.detect_test_framework(entry, FakeResolver({}, {}), "abc") is None


def test_the_written_corpus_records_a_test_framework_for_every_case():
    written = json.loads((REPO_ROOT / "eval-corpus" / "external" / "vul4j.json").read_text())
    for case in written["cases"] + written["quarantined"]:
        assert "test_framework" in case["build"], case["name"]
        assert case["build"]["test_framework"] in (None, "junit4", "junit5", "testng"), case["name"]
    declared = [c["build"]["test_framework"] for c in written["cases"]
                if c["name"].endswith("-vulnerable")]
    # The number this whole change exists for: the seeded corpus is 100% JUnit 5 and the harvest
    # is not. If this ever flips to a JUnit 5 majority, the Maven recipe's default is worth
    # revisiting -- until then, assuming JUnit 5 is assuming the rare case.
    assert declared.count("junit4") > 10 * max(declared.count("junit5"), 1)
