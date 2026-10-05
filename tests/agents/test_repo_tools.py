"""The batched and whole-repository read tools: correct, bounded, and still confined.

`read_files`, `list_tree` and `repo_digest` exist to turn several model round trips into one
(see tests/agents/test_exploration_cost.py for that measurement). Adding reach to a toolset that reads
customer source under triage is the part that needs pinning here: the confinement, the output
bounds the tool policy declares, and the property each tool was added for.
"""

from __future__ import annotations

import time
import types
from pathlib import Path

import pytest
from pydantic_ai import ModelRetry

from infosec_harness.runtime import capabilities as cap
from infosec_harness.runtime.deps import AgentDeps
from infosec_harness.tools import repository as repo_tools
from infosec_harness.tools import repository as rt
from infosec_harness.tools.policies import load_policies


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "pom.xml").write_text("<project/>\n")
    (root / "README.md").write_text("# app\n")
    (root / "src/main/java/com/example").mkdir(parents=True)
    (root / "src/test/java/com/example").mkdir(parents=True)
    for i in range(30):
        (root / "src/main/java/com/example" / f"A{i:02d}.java").write_text(
            f"package com.example;\nclass A{i:02d} {{ void go() {{}} }}\n")
    (root / "src/test/java/com/example/A00Test.java").write_text(
        "package com.example;\nclass A00Test {}\n")
    (root / "target").mkdir()
    (root / "target/ignored.class").write_text("binary-ish\n")
    return root


def ctx(repo: Path):
    return types.SimpleNamespace(deps=AgentDeps(repo_path=str(repo)))


# --- read_files ---------------------------------------------------------------------------


def test_read_files_returns_every_file_in_one_result(repo):
    out = repo_tools.read_files(ctx(repo), ["pom.xml", "README.md",
                                     "src/main/java/com/example/A00.java"])
    assert "<project/>" in out and "# app" in out and "class A00" in out


def test_one_bad_path_does_not_cost_the_whole_call(repo):
    """The failure mode that would make a batched read worse than N single reads.

    Raising on the first missing path would throw away the files that *were* read, and cost the
    run a retry per bad path — the opposite of what this tool is for. So a missing path is
    reported against that path and the rest come back.
    """
    out = repo_tools.read_files(ctx(repo), ["pom.xml", "nope.txt"])
    assert "<project/>" in out
    assert "nope.txt" in out and "does not exist" in out


def test_a_call_with_no_readable_path_at_all_is_a_retry_that_names_the_correction(repo):
    """With nothing read, the model needs telling how to fix the call, not a body of notes
    it may mistake for content."""
    with pytest.raises(ModelRetry, match="list_files|list_tree"):
        repo_tools.read_files(ctx(repo), ["nope.txt", "also-nope.txt"])


def test_read_files_cannot_escape_the_snapshot(repo):
    """Confinement is per path, not per call: one traversal attempt must not be let through
    just because the other paths were fine."""
    out = repo_tools.read_files(ctx(repo), ["pom.xml", "../../etc/passwd"])
    assert "outside the repository" in out
    assert "root:" not in out


def test_read_files_refuses_more_paths_than_it_will_read(repo):
    """Silently reading the first 20 of 50 would look like a complete answer."""
    with pytest.raises(ModelRetry, match="at most"):
        repo_tools.read_files(ctx(repo), ["pom.xml"] * (repo_tools.MAX_BATCH_FILES + 1))


def test_read_files_bounds_its_total_output(repo):
    big = repo / "src/main/java/com/example/Big.java"
    big.write_text("\n".join(f"// {'x' * 300}" for _ in range(400)) + "\n")
    out = repo_tools.read_files(ctx(repo), [big.relative_to(repo).as_posix()] * 1)
    assert len(out.encode()) <= repo_tools.MAX_BATCH_BYTES + 200


# --- list_tree ---------------------------------------------------------------------------


def test_list_tree_names_every_directory_and_states_the_totals(repo):
    out = repo_tools.list_tree(ctx(repo), ".")
    assert "src/main/java/com/example/" in out
    assert "src/test/java/com/example/" in out
    # The count it is summarising is stated, so a truncated answer is visibly truncated.
    assert "files in" in out.splitlines()[0]


def test_list_tree_skips_build_output_like_every_other_tool(repo):
    assert "target/" not in repo_tools.list_tree(ctx(repo), ".")


def test_a_path_from_list_tree_is_the_directory_joined_to_the_name(repo):
    """The whole tool is useless if the caller cannot form a path from its output.

    One line per directory with names relative to it is compact, but only unambiguous if a
    directory is never split across lines — so this reconstructs a path the way a reader would
    and checks the file is really there.
    """
    from conftest import load_script

    exploration = load_script("exploration")
    _paths_from_tree = exploration._paths_from_tree

    paths = _paths_from_tree(repo_tools.list_tree(ctx(repo), "."))
    assert paths, "the listing named no files at all"
    for p in paths:
        assert (repo / p).is_file(), f"{p!r} was named by list_tree but does not exist"


def test_list_tree_gives_up_file_names_before_it_gives_up_directories(tmp_path):
    """Which directories exist is the one thing a caller cannot recover by asking again.

    A file name in a directory they can see is one `list_files` away. A directory they were
    never told about is invisible — nothing in the answer says to go looking. So on a tree too
    large for the byte budget the names thin out and the directory census stays complete.
    """
    root = tmp_path
    dirs = 600
    for d in range(dirs):
        p = root / f"pkg{d:04d}"
        p.mkdir()
        for i in range(6):
            (p / f"File{i}.java").write_text("class X {}\n")
    out = repo_tools.list_tree(ctx(root), ".")
    assert len(out.encode()) <= repo_tools.MAX_TREE_BYTES + 200
    named = {line.split("/", 1)[0] for line in out.splitlines() if line.startswith("pkg")}
    assert len(named) == dirs, f"only {len(named)} of {dirs} directories were named"


def test_a_tree_too_large_to_show_still_names_every_branch(tmp_path):
    """The failure this selection rule exists to stop: a whole branch going unmentioned.

    Taking a prefix of `os.walk` order spends the byte budget on the first branch, and on a
    Maven layout that is `src/main` — measured on a 4000-file tree, nothing under `src/test` was
    named at all, so an agent whose required output includes the test layout would be told the
    repository has no tests. Depth order does not fix it either: every leaf package is at the
    same depth and `src/main` sorts first.
    """
    root = tmp_path
    (root / "pom.xml").write_text("<project/>\n")
    for branch in ("src/main/java/com/example", "src/test/java/com/example"):
        for d in range(500):
            p = root / branch / f"mod{d:04d}"
            p.mkdir(parents=True)
            (p / f"C{d:04d}.java").write_text("class C {}\n")
    out = repo_tools.list_tree(ctx(root), ".")
    lines = [ln for ln in out.splitlines() if "files=" in ln]
    assert len(lines) < 1000, "the fixture must be too large to show in full"
    assert any("/main/" in ln for ln in lines)
    assert any("/test/" in ln for ln in lines), "the test branch was not named at all"
    # And the answer says how much it left out, so the caller knows to ask for more.
    assert "not shown" in out


def test_list_tree_refuses_a_file_and_says_what_to_call_instead(repo):
    with pytest.raises(ModelRetry, match="read_file"):
        repo_tools.list_tree(ctx(repo), "pom.xml")


def test_list_tree_cannot_escape_the_snapshot(repo):
    with pytest.raises(ModelRetry, match="outside the repository"):
        repo_tools.list_tree(ctx(repo), "../..")


# --- repo_digest -------------------------------------------------------------------------


def test_the_digest_answers_the_tree_the_manifests_and_the_tests(repo):
    """The three things every profiling run needs before it can say anything."""
    out = repo_tools.repo_digest(ctx(repo))
    assert "src/main/java/com/example/" in out          # tree
    assert "<project/>" in out and "# app" in out       # manifests, with content
    assert "## Test layout" in out and "A00Test.java" in out


def test_the_digest_is_bounded_by_what_the_policy_declares(tmp_path):
    """A single tool result larger than the declared cap makes the policy a fiction.

    The manifests are the unbounded part: a line cap is not a byte cap, and a minified or
    generated manifest has arbitrarily long lines. So this makes every manifest line long
    enough that only the final byte clip can hold the result down.
    """
    root = tmp_path
    long_line = "  <!-- " + "x" * 4000 + " -->\n"
    for name in ("pom.xml", "package.json", "Makefile", "Dockerfile", "README.md",
                 "requirements.txt", "setup.py", "tox.ini"):
        (root / name).write_text(long_line * 200)
    for d in range(300):
        p = root / f"pkg{d:04d}"
        p.mkdir()
        for i in range(12):
            (p / f"File{i}.java").write_text("class X {}\n")
    out = repo_tools.repo_digest(ctx(root))
    declared = load_policies()["repo-read-only"].max_output_bytes
    assert len(out.encode()) > declared / 2, (
        "the fixture must be big enough that the bound is doing something"
    )
    assert len(out.encode()) <= declared, (len(out.encode()), declared)


def test_a_repository_with_no_manifest_says_so_rather_than_saying_nothing(repo):
    """Silence reads as "not checked"; the absence of a build manifest is a finding."""
    (repo / "pom.xml").unlink()
    (repo / "README.md").unlink()
    out = repo_tools.repo_digest(ctx(repo))
    assert "0 found" in out or "none found" in out


def test_repo_digest_does_not_follow_an_external_manifest_symlink(tmp_path):
    outside = tmp_path / "secret-package.json"
    outside.write_text('{"token":"must-not-leak"}')
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").symlink_to(outside)

    out = repo_tools.repo_digest(ctx(repo))

    assert "must-not-leak" not in out
    assert "0 found" in out or "none found" in out


def test_the_digest_never_executes_or_imports_what_it_reads(repo):
    """The snapshot holds the unfixed vulnerability under triage, so this is load-bearing."""
    (repo / "conftest.py").write_text("raise SystemExit('this must never run')\n")
    (repo / "setup.py").write_text("import os; os.write(2, b'ran')\n")
    out = repo_tools.repo_digest(ctx(repo))  # would not return if either were executed
    assert "setup.py" in out


def _test_layout_dirs(digest: str) -> set[str]:
    section = digest.split("## Test layout", 1)[1]
    return {line.split("/  files=", 1)[0] for line in section.splitlines() if "/  files=" in line}


def test_test_directories_are_matched_by_whole_path_segment_not_by_prefix(tmp_path):
    """`tools/`, `templates/` and `third_party/` are not test directories under any convention.

    Matching by string prefix against a set containing Perl's `t` made every directory whose
    name begins with "t" a test directory, so a profile of the repository would point a probe
    author at build tooling and vendored code as the place the existing tests live.
    """
    root = tmp_path
    for rel in ("tools/x.py", "templates/a.html", "third_party/b.c", "testing_utils/h.py",
                "tests/test_a.py", "src/test/Foo.java", "t/basic.t", "web/__tests__/a.test.js",
                "src/main/App.java"):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text("x\n")
    assert _test_layout_dirs(repo_tools.repo_digest(ctx(root))) == {
        "tests", "src/test", "t", "web/__tests__"}
    for rel in ("tools", "templates", "third_party", "testing_utils", "src/main", "src/testing"):
        assert not rt._is_test_dir(rel), rel
    for rel in ("tests", "src/test/java/com/example", "t", "spec/models", "web/__tests__"):
        assert rt._is_test_dir(rel), rel


def test_a_catastrophically_backtracking_regex_is_stopped_at_the_deadline(tmp_path, monkeypatch):
    """`(\\w|\\d)+x` has no repeat nested inside a repeat, so a shape guard let it through, and
    against a long run of word characters it backtracks for far longer than any tool call may
    take (quadratic in the run length: measured ~0.17 s at 5 000 characters, so ~17 s at 50 000).
    Python's `re` cannot be interrupted, so the only real bound is a process killed at a
    deadline -- and a stopped search must say it was stopped, keeping what it had found rather
    than reading as "no matches"."""
    (tmp_path / "a.txt").write_text("ax\n")  # walked first: matches before the hang
    (tmp_path / "big.txt").write_text("a" * 50_000 + "\n")
    monkeypatch.setattr(rt, "SEARCH_TIMEOUT_SECONDS", 1.5)
    began = time.monotonic()
    out = repo_tools.search_code(ctx(tmp_path), r"(\w|\d)+x")
    assert time.monotonic() - began < 8, "the search was not stopped at its deadline"
    assert "timed out" in out and "partial" in out
    assert "a.txt:1: ax" in out
    assert "(no matches)" not in out


def test_the_search_deadline_fits_inside_the_toolsets_declared_timeout():
    """A deadline longer than the policy's own timeout would let the tool, not the search, be
    what gets cut off -- with no result at all."""
    declared = load_policies()["repo-read-only"].timeout_seconds
    assert 0 < rt.SEARCH_TIMEOUT_SECONDS < declared


def test_search_code_keeps_its_output_format_confinement_and_exclusions(repo):
    out = repo_tools.search_code(ctx(repo), r"class A0[01] ", "*.java")
    assert out.splitlines() == [
        "src/main/java/com/example/A00.java:2: class A00 { void go() {} }",
        "src/main/java/com/example/A01.java:2: class A01 { void go() {} }",
    ]
    assert repo_tools.search_code(ctx(repo), "binary-ish") == "(no matches)"  # target/ is excluded
    every = repo_tools.search_code(ctx(repo), "^package", "*.java")
    assert len(every.splitlines()) == 31  # 30 sources + 1 test, each declaring its package once
    assert all(line.endswith(":1: package com.example;") for line in every.splitlines())
    (repo / "many").mkdir()
    for i in range(repo_tools.MAX_MATCHES + 10):
        (repo / "many" / f"m{i:03d}.txt").write_text("needle\n")
    capped = repo_tools.search_code(ctx(repo), "needle", "*.txt")
    assert capped.endswith(f"\n... truncated at {repo_tools.MAX_MATCHES} matches")
    assert len(capped.splitlines()) == repo_tools.MAX_MATCHES + 1
    with pytest.raises(ModelRetry, match="Invalid regex"):
        repo_tools.search_code(ctx(repo), "(")


def test_a_file_larger_than_the_read_cap_is_read_only_up_to_the_cap(repo, monkeypatch):
    """Reading a whole file and then truncating it costs the whole file in memory first.

    Every line is `L` + 7 digits + newline = 9 bytes, so exactly 2_000_000 // 9 = 222_222 whole
    lines fit in the cap. Line 222_223 straddles it and line 250_000 lies wholly beyond it: a
    reader bounded before the read cannot return either, and must say the file is larger.
    """
    assert rt.MAX_FILE_BYTES == 2_000_000
    big = repo / "big.txt"
    big.write_text("".join(f"L{n:07d}\n" for n in range(1, 300_001)))
    assert big.stat().st_size == 2_700_000
    read_sizes: list[int] = []
    real_open = Path.open

    def counting_open(self, *args, **kwargs):
        fh = real_open(self, *args, **kwargs)
        real_read = fh.read

        def read(n=-1):
            data = real_read(n)
            read_sizes.append(len(data))
            return data

        fh.read = read
        return fh

    monkeypatch.setattr(Path, "open", counting_open)
    edge = repo_tools.read_file(ctx(repo), "big.txt", 222_221, 222_230)
    assert sum(read_sizes) <= rt.MAX_FILE_BYTES + 1, "more than the cap was read from disk"
    assert "L0222222" in edge and "L0222223" not in edge
    assert "of at least 222222" in edge.splitlines()[0]
    assert "larger than 2000000 bytes" in edge.splitlines()[0]
    beyond = repo_tools.read_file(ctx(repo), "big.txt", 250_000, 250_010)
    assert "L0250000" not in beyond


def test_one_huge_line_cannot_flood_a_single_read(repo):
    """400 lines is not a byte bound when one line is megabytes, as in minified bundles."""
    (repo / "bundle.min.js").write_text("v" * 3_000_000)
    out = repo_tools.read_file(ctx(repo), "bundle.min.js")
    assert len(out.encode()) <= repo_tools.MAX_BATCH_BYTES + 100
    assert out.rstrip().endswith(f"truncated at {repo_tools.MAX_BATCH_BYTES} bytes")


def test_a_file_link_leaving_the_listed_directory_but_not_the_snapshot_is_still_listed(repo):
    """The checkout admits a link that stays inside the snapshot, so listing a subdirectory
    must not reject it merely because its target lies outside that subdirectory."""
    (repo / "docs").mkdir()
    (repo / "docs/README.md").symlink_to("../README.md")
    assert repo_tools.list_files(ctx(repo), "docs") == "docs/README.md"
    assert "docs/  files=1" in repo_tools.list_tree(ctx(repo), "docs")
    assert "# app" in repo_tools.read_file(ctx(repo), "docs/README.md")


@pytest.mark.parametrize("kind", ["external-file-link", "directory-link"])
def test_listing_fails_closed_on_an_entry_the_snapshot_boundary_rejects(tmp_path, kind):
    """The read tools traverse with the same rule the checkout admits snapshots by
    (`repo.access.walk_files`), so an entry it would refuse is refused here too, loudly,
    and nothing behind it is listed or read."""
    secret = tmp_path / "outside"
    secret.mkdir()
    (secret / "token.txt").write_text("must-not-leak\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print(1)\n")
    if kind == "external-file-link":
        (repo / "token.txt").symlink_to(secret / "token.txt")
    else:
        (repo / "linked").symlink_to(secret, target_is_directory=True)
    for tool in (lambda: repo_tools.list_files(ctx(repo), "."), lambda: repo_tools.list_tree(ctx(repo), "."),
                 lambda: repo_tools.search_code(ctx(repo), "must-not-leak")):
        with pytest.raises(ModelRetry, match="traversal was rejected"):
            tool()
    digest = repo_tools.repo_digest(ctx(repo))
    assert "traversal was rejected" in digest and "must-not-leak" not in digest


# --- the toolset's identity ---------------------------------------------------------------


def test_a_narrowed_toolset_keeps_one_stable_instance():
    """pydantic-ai compares capability toolsets by identity against the construction-time set.

    Skills is dynamic, so the toolsets are re-collected each run; a fresh instance would be
    rejected as a runtime addition under Temporal. Memoising on the tool names is what makes
    narrowing safe, and this is the property that makes it so.
    """
    a = cap.RepoReadOnly(tools=["read_file", "list_files"])
    b = cap.RepoReadOnly(tools=["list_files", "read_file"])  # different order, same surface
    assert a.get_toolset() is b.get_toolset()
    assert cap.RepoReadOnly().get_toolset() is cap.RepoReadOnly().get_toolset()
    assert a.get_toolset() is not cap.RepoReadOnly().get_toolset()


def test_a_narrowed_toolset_exposes_exactly_what_it_names():
    toolset = cap.RepoReadOnly(tools=["read_files", "list_tree"]).get_toolset()
    assert set(toolset.tools) == {"read_files", "list_tree"}


def test_selecting_a_tool_that_does_not_exist_fails_loudly():
    with pytest.raises(ValueError, match="Unknown repo-read-only tools"):
        cap.RepoReadOnly(tools=["read_everything"]).get_toolset()


def test_an_unknown_tool_beside_known_ones_fails_at_toolset_construction():
    """Regression: the capability dropped unknown names silently when any known one remained,
    so a typo narrowed the agent's tools and only build_agent's governance check caught it."""
    with pytest.raises(ValueError, match=r"Unknown repo-read-only tools: \['read_fiels'\]"):
        cap.RepoReadOnly(tools=["read_file", "read_fiels"]).get_toolset()


def test_an_empty_selection_fails_rather_than_exposing_nothing():
    with pytest.raises(ValueError, match="selects no tool"):
        cap.RepoReadOnly(tools=[]).get_toolset()


def test_clip_bytes_keeps_each_callers_model_visible_marker_byte_for_byte():
    """One helper serves every byte clip; the markers the model sees must not change."""
    from infosec_harness.tools.repository import clip_bytes

    assert clip_bytes("abc", 3) == "abc"
    assert clip_bytes("abcdef", 3) == "abc\n... truncated at 3 bytes"
    assert clip_bytes("abcdef", 3, "\n... truncated") == "abc\n... truncated"
    assert (clip_bytes("abcdef", 3, "\n[truncated: request a smaller range]")
            == "abc\n[truncated: request a smaller range]")
    # Never cut inside a character.
    assert clip_bytes("éé", 3) == "é\n... truncated at 3 bytes"
