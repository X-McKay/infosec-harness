"""The batched and whole-repository read tools: correct, bounded, and still confined.

`read_files`, `list_tree` and `repo_digest` exist to turn several model round trips into one
(see tests/test_exploration_cost.py for that measurement). Adding reach to a toolset that reads
customer source under triage is the part that needs pinning here: the confinement, the output
bounds the tool policy declares, and the property each tool was added for.
"""

from __future__ import annotations

import types
from pathlib import Path

import pytest
from pydantic_ai import ModelRetry

from infosec_harness.agents import capabilities as cap
from infosec_harness.agents.deps import AgentDeps
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
    out = cap.read_files(ctx(repo), ["pom.xml", "README.md",
                                     "src/main/java/com/example/A00.java"])
    assert "<project/>" in out and "# app" in out and "class A00" in out


def test_one_bad_path_does_not_cost_the_whole_call(repo):
    """The failure mode that would make a batched read worse than N single reads.

    Raising on the first missing path would throw away the files that *were* read, and cost the
    run a retry per bad path — the opposite of what this tool is for. So a missing path is
    reported against that path and the rest come back.
    """
    out = cap.read_files(ctx(repo), ["pom.xml", "nope.txt"])
    assert "<project/>" in out
    assert "nope.txt" in out and "does not exist" in out


def test_a_call_with_no_readable_path_at_all_is_a_retry_that_names_the_correction(repo):
    """With nothing read, the model needs telling how to fix the call, not a body of notes
    it may mistake for content."""
    with pytest.raises(ModelRetry, match="list_files|list_tree"):
        cap.read_files(ctx(repo), ["nope.txt", "also-nope.txt"])


def test_read_files_cannot_escape_the_snapshot(repo):
    """Confinement is per path, not per call: one traversal attempt must not be let through
    just because the other paths were fine."""
    out = cap.read_files(ctx(repo), ["pom.xml", "../../etc/passwd"])
    assert "outside the repository" in out
    assert "root:" not in out


def test_read_files_refuses_more_paths_than_it_will_read(repo):
    """Silently reading the first 20 of 50 would look like a complete answer."""
    with pytest.raises(ModelRetry, match="at most"):
        cap.read_files(ctx(repo), ["pom.xml"] * (cap.MAX_BATCH_FILES + 1))


def test_read_files_bounds_its_total_output(repo):
    big = repo / "src/main/java/com/example/Big.java"
    big.write_text("\n".join(f"// {'x' * 300}" for _ in range(400)) + "\n")
    out = cap.read_files(ctx(repo), [big.relative_to(repo).as_posix()] * 1)
    assert len(out.encode()) <= cap.MAX_BATCH_BYTES + 200


# --- list_tree ---------------------------------------------------------------------------


def test_list_tree_names_every_directory_and_states_the_totals(repo):
    out = cap.list_tree(ctx(repo), ".")
    assert "src/main/java/com/example/" in out
    assert "src/test/java/com/example/" in out
    # The count it is summarising is stated, so a truncated answer is visibly truncated.
    assert "files in" in out.splitlines()[0]


def test_list_tree_skips_build_output_like_every_other_tool(repo):
    assert "target/" not in cap.list_tree(ctx(repo), ".")


def test_a_path_from_list_tree_is_the_directory_joined_to_the_name(repo):
    """The whole tool is useless if the caller cannot form a path from its output.

    One line per directory with names relative to it is compact, but only unambiguous if a
    directory is never split across lines — so this reconstructs a path the way a reader would
    and checks the file is really there.
    """
    from infosec_harness.evals.exploration import _paths_from_tree

    paths = _paths_from_tree(cap.list_tree(ctx(repo), "."))
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
    out = cap.list_tree(ctx(root), ".")
    assert len(out.encode()) <= cap.MAX_TREE_BYTES + 200
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
    out = cap.list_tree(ctx(root), ".")
    lines = [ln for ln in out.splitlines() if "files=" in ln]
    assert len(lines) < 1000, "the fixture must be too large to show in full"
    assert any("/main/" in ln for ln in lines)
    assert any("/test/" in ln for ln in lines), "the test branch was not named at all"
    # And the answer says how much it left out, so the caller knows to ask for more.
    assert "not shown" in out


def test_list_tree_refuses_a_file_and_says_what_to_call_instead(repo):
    with pytest.raises(ModelRetry, match="read_file"):
        cap.list_tree(ctx(repo), "pom.xml")


def test_list_tree_cannot_escape_the_snapshot(repo):
    with pytest.raises(ModelRetry, match="outside the repository"):
        cap.list_tree(ctx(repo), "../..")


# --- repo_digest -------------------------------------------------------------------------


def test_the_digest_answers_the_tree_the_manifests_and_the_tests(repo):
    """The three things every profiling run needs before it can say anything."""
    out = cap.repo_digest(ctx(repo))
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
    out = cap.repo_digest(ctx(root))
    declared = load_policies()["repo-read-only"].max_output_bytes
    assert len(out.encode()) > declared / 2, (
        "the fixture must be big enough that the bound is doing something"
    )
    assert len(out.encode()) <= declared, (len(out.encode()), declared)


def test_a_repository_with_no_manifest_says_so_rather_than_saying_nothing(repo):
    """Silence reads as "not checked"; the absence of a build manifest is a finding."""
    (repo / "pom.xml").unlink()
    (repo / "README.md").unlink()
    out = cap.repo_digest(ctx(repo))
    assert "0 found" in out or "none found" in out


def test_the_digest_never_executes_or_imports_what_it_reads(repo):
    """The snapshot holds the unfixed vulnerability under triage, so this is load-bearing."""
    (repo / "conftest.py").write_text("raise SystemExit('this must never run')\n")
    (repo / "setup.py").write_text("import os; os.write(2, b'ran')\n")
    out = cap.repo_digest(ctx(repo))  # would not return if either were executed
    assert "setup.py" in out


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
    with pytest.raises(ValueError, match="selects no known tool"):
        cap.RepoReadOnly(tools=["read_everything"]).get_toolset()
