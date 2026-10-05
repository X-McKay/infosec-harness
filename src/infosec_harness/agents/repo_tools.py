"""Bounded, path-confined read tools for immutable repository snapshots."""

from __future__ import annotations

import contextlib
import fnmatch
import json
import re
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from pydantic_ai import ModelRetry, RunContext

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.repo.access import (
    BUILD_OUTPUT_DIRS,
    DEPENDENCY_DIRS,
    RepositoryAccessError,
    resolve_confined,
    walk_files,
)

SKIP_DIRS = DEPENDENCY_DIRS | BUILD_OUTPUT_DIRS
MAX_READ_LINES = 400
MAX_LIST = 300
MAX_MATCHES = 60
# Batched read and whole-repository summary. Every one of these keeps the toolset's declared
# `max_output_bytes` (tools/repo-read-only/tool.yaml) truthful, which is why they are named
# here next to the others rather than inline.
MAX_BATCH_FILES = 20
MAX_BATCH_BYTES = 80_000
MAX_TREE_DIRS = 1200
MAX_TREE_NAMED_FILES = 12  # per directory, before falling back to the extension histogram
MAX_TREE_BYTES = 40_000
MAX_DIGEST_MANIFESTS = 8
MAX_MANIFEST_LINES = 120
MAX_DIGEST_BYTES = 110_000
# The most bytes taken from disk for any one file, by the readers and by search_code alike. It is
# applied to the read itself, so a multi-gigabyte file costs this much memory and no more; what
# lies beyond it is reported as unreadable rather than silently missing.
MAX_FILE_BYTES = 2_000_000
# search_code runs the regex in a child process that is killed at this deadline. Python's `re`
# has no match timeout, and no inspection of a pattern's shape can tell every catastrophically
# backtracking regex from a safe one, so the work is bounded by time instead. It stays well under
# the toolset's declared `timeout_seconds` (tools/repo-read-only/tool.yaml).
SEARCH_TIMEOUT_SECONDS = 10.0
MAX_MATCH_CHARS = 200


def _resolve(root: str, rel: str) -> Path:
    try:
        return resolve_confined(root, rel)
    except (OSError, RepositoryAccessError) as exc:
        raise ModelRetry(
            f"Path {rel!r} is outside the repository. Every path is relative to the repository "
            "root; call list_files('.') and pass a path exactly as it is printed there."
        ) from exc


def _traversal_rejected(exc: RepositoryAccessError) -> str:
    return f"Repository traversal was rejected: {exc}"


def _snapshot_files(root: Path, start: Path) -> Iterator[tuple[str, Path]]:
    """(root-relative path, path) of every confined file under `start`, in walk order.

    Every traversal in this module goes through `walk_files`, the same rule the checkout applies
    when it admits a snapshot, so the tools fail closed on what the snapshot boundary rejects (a
    link that leaves the snapshot, a directory link, a special file) rather than each skipping
    its own idea of it. `walk_files` judges a link against the root it is handed, though, and a
    file link from `start` to elsewhere in the snapshot is confined even though it leaves
    `start`; so a rejection below the root is judged again against the snapshot root before it
    stands.
    """
    yielded: set[str] = set()
    try:
        for _, path in walk_files(start, skip_dirs=SKIP_DIRS):
            rel = path.relative_to(root).as_posix()
            yielded.add(rel)
            yield rel, path
        return
    except RepositoryAccessError:
        if start == root:
            raise
    prefix = start.relative_to(root).as_posix() + "/"
    for rel, path in walk_files(root, skip_dirs=SKIP_DIRS):
        if rel.startswith(prefix) and rel not in yielded:
            yield rel, path


def list_files(ctx: RunContext[AgentDeps], directory: str = ".", pattern: str = "*") -> str:
    """List repository files under `directory` (recursive) whose name matches the glob `pattern`.

    Returns repo-relative paths, one per line, truncated to 300 entries.
    """
    root = Path(ctx.deps.repo_path).resolve()
    start = _resolve(ctx.deps.repo_path, directory)
    if not start.is_dir():
        raise ModelRetry(f"{directory!r} is not a directory.")
    out: list[str] = []
    try:
        for rel, path in _snapshot_files(root, start):
            if fnmatch.fnmatch(path.name, pattern):
                out.append(rel)
                if len(out) >= MAX_LIST:
                    return "\n".join(out) + f"\n... truncated at {MAX_LIST} entries"
    except RepositoryAccessError as exc:
        raise ModelRetry(_traversal_rejected(exc)) from exc
    return "\n".join(out) or "(no matches)"


def read_file(ctx: RunContext[AgentDeps], path: str, start_line: int = 1, end_line: int = 200) -> str:
    """Read lines `start_line`..`end_line` (1-based, inclusive) of a repository file.

    Output lines are prefixed with their line numbers. At most 400 lines per call. To read
    several files, call `read_files` once instead of this tool several times.
    """
    target = _resolve(ctx.deps.repo_path, path)
    if not target.is_file():
        raise ModelRetry(f"{path!r} does not exist.")
    # 400 lines is not a byte bound: one minified line can be megabytes. Hold a single read to
    # the same budget as a batched one.
    return _clip_bytes(_read_one(target, path, start_line, end_line), MAX_BATCH_BYTES)


def _read_capped(target: Path) -> tuple[str, bool]:
    """At most MAX_FILE_BYTES of `target`, decoded, and whether the file holds more than that."""
    with target.open("rb") as fh:
        raw = fh.read(MAX_FILE_BYTES + 1)
    truncated = len(raw) > MAX_FILE_BYTES
    if truncated:
        raw = raw[:MAX_FILE_BYTES]
        # The cut almost always falls inside a line. Drop that fragment rather than present part
        # of a line as the whole of it; a file with no line break at all keeps its fragment.
        cut = max(raw.rfind(b"\n"), raw.rfind(b"\r"))
        if cut >= 0:
            raw = raw[: cut + 1]
    return raw.decode(errors="replace"), truncated


def _read_one(target: Path, path: str, start_line: int, end_line: int) -> str:
    start_line = max(1, start_line)
    end_line = min(max(start_line, end_line), start_line + MAX_READ_LINES - 1)
    text, truncated = _read_capped(target)
    lines = text.splitlines()
    chunk = lines[start_line - 1 : end_line]
    body = "\n".join(f"{i:>5}  {line}" for i, line in enumerate(chunk, start=start_line))
    total = (f"at least {len(lines)}; the file is larger than {MAX_FILE_BYTES} bytes and only "
             f"its first {len(lines)} lines are readable" if truncated else str(len(lines)))
    return f"{path} (lines {start_line}-{start_line + len(chunk) - 1} of {total})\n{body}"


def read_files(ctx: RunContext[AgentDeps], paths: list[str], start_line: int = 1,
               end_line: int = 200) -> str:
    """Read the same line range of SEVERAL repository files in one call.

    Prefer this over repeated `read_file` calls whenever you already know which files you want:
    every tool call costs a full model round trip, so reading eight files one at a time costs
    eight of them and reading them together costs one.

    `paths` are repo-relative, spelled exactly as `list_files` or `list_tree` print them; at
    most 20 per call, each bounded like `read_file`. A path that does not exist is reported
    against that path and the rest are still returned, so one bad path does not cost the call.
    """
    if not paths:
        raise ModelRetry("read_files needs at least one path. Pass the paths exactly as "
                         "list_files or list_tree printed them.")
    if len(paths) > MAX_BATCH_FILES:
        # Truncating silently would hand back fewer files than were asked for and look like a
        # complete answer, which is the failure mode this tool exists to remove.
        raise ModelRetry(f"read_files takes at most {MAX_BATCH_FILES} paths and was given "
                         f"{len(paths)}. Split them across two calls.")
    sections: list[str] = []
    missing: list[str] = []
    budget = MAX_BATCH_BYTES
    for path in paths:
        try:
            target = _resolve(ctx.deps.repo_path, path)
        except ModelRetry as e:  # outside the repository: report it, keep the other files
            sections.append(f"--- {path}\n[not read: {e}]")
            missing.append(path)
            continue
        if not target.is_file():
            sections.append(f"--- {path}\n[not read: does not exist in the repository]")
            missing.append(path)
            continue
        if budget <= 0:
            sections.append(f"--- {path}\n[not read: this call's {MAX_BATCH_BYTES}-byte output "
                            "budget was already spent; read it in a second call]")
            continue
        body = _read_one(target, path, start_line, end_line)
        if len(body.encode()) > budget:
            body = body.encode()[:budget].decode(errors="ignore") + "\n... truncated"
        budget -= len(body.encode())
        sections.append(f"--- {body}")
    if len(missing) == len(paths):
        # Nothing was read, so the model has to be told how to correct the call rather than
        # being handed a body of error notes it may treat as content.
        raise ModelRetry(f"None of {paths!r} exist in the repository. Call list_files('.') or "
                         "list_tree('.') and pass paths exactly as they are printed there.")
    return "\n".join(sections)


# --- list_tree ---------------------------------------------------------------------------
# `list_files` is recursive but capped at MAX_LIST *entries*, so on a large repository its
# answer is a PREFIX of the tree rather than the tree. A prefix costs twice. It costs round
# trips, because the only way to cover the repository is to list each directory the window did
# name and repeat wherever that is truncated too -- measured at 54 tool calls over 55 model
# requests on a 500-file Maven tree, against a scaled request budget of 27. And it costs
# accuracy, because a truncated listing does not name the directories it left out: on the same
# tree the procedure ends knowing 101 of 127 directories and 304 of 500 sources, and on a
# 2000-file tree 288 of 501 directories -- a profile of part of a repository is wrong rather
# than merely expensive. tests/agents/test_exploration_cost.py holds those measurements.
#
# This returns one line per DIRECTORY instead of one per file, so what it truncates is a
# summary rather than the existence of most of the repository, and it always states the total
# file count it is summarising.

@dataclass(frozen=True)
class _DirSummary:
    rel: str
    files: tuple[str, ...]
    total_bytes: int


def _walk_dirs(root: Path, start: Path) -> tuple[list[_DirSummary], int, int]:
    """(per-directory summaries, total files, total directories) under `start`.

    Summaries come in walk order (sorted, top-down). The directory total counts `start` and
    every directory that holds a file somewhere beneath it; `walk_files` yields files only, so a
    directory with nothing readable under it is not counted.

    Raises RepositoryAccessError when the snapshot holds an entry `walk_files` rejects.
    """
    groups: dict[Path, list[str]] = {}
    for _, path in _snapshot_files(root, start):
        groups.setdefault(path.parent, []).append(path.name)
    dirs = {start}
    for here in groups:
        while here not in dirs and here != here.parent:
            dirs.add(here)
            here = here.parent
    out: list[_DirSummary] = []
    total_files = 0
    for here, names in groups.items():
        total_files += len(names)
        size = 0
        for name in names:
            # A broken symlink or a file removed between the walk and the stat must not sink
            # the whole listing; the size is a hint, and the name is the part that matters.
            with contextlib.suppress(OSError):
                size += (here / name).stat().st_size
        rel = here.relative_to(root).as_posix() or "."
        out.append(_DirSummary(rel=rel, files=tuple(names), total_bytes=size))
    return out, total_files, len(dirs)


def _ext_histogram(names: tuple[str, ...]) -> str:
    """`ext=count` pairs. The `=` is deliberate: it is what distinguishes a histogram entry
    from a file name on the same line, for a reader and for a parser alike."""
    counts: dict[str, int] = {}
    for name in names:
        ext = Path(name).suffix or "(noext)"
        counts[ext] = counts.get(ext, 0) + 1
    return ",".join(f"{ext}={n}" for ext, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def list_tree(ctx: RunContext[AgentDeps], directory: str = ".") -> str:
    """Summarise the repository tree under `directory`: one line per directory, with counts.

    Use this FIRST, before `list_files`. It answers "what is in this repository and where" in a
    single call on a repository of any size. Each line is one directory: how many files it holds,
    their total size, the first few file names, and `+N-more[.ext=count,...]` for the rest.
    `list_files` is a flat per-file listing capped at 300 entries, so on a large repository it
    returns a fragment of the tree without saying which directories it omitted; this states the
    totals it is summarising, so a truncated answer is visibly truncated and says what to call
    to expand it.

    Follow it with `read_files` on the paths you want, or `list_files(dir, pattern)` when you
    need every file name in one large directory.
    """
    root = Path(ctx.deps.repo_path).resolve()
    start = _resolve(ctx.deps.repo_path, directory)
    if not start.is_dir():
        raise ModelRetry(f"{directory!r} is not a directory. Pass a directory path, or use "
                         f"read_file/read_files for a file.")
    try:
        summaries, total_files, total_dirs = _walk_dirs(root, start)
    except RepositoryAccessError as exc:
        raise ModelRetry(_traversal_rejected(exc)) from exc
    return _tree_text(directory, summaries, total_files, total_dirs)


def _tree_text(directory: str, summaries: list[_DirSummary], total_files: int,
               total_dirs: int) -> str:
    # Names are given up first, directories last, and the count of what was dropped is always
    # said out loud. Which directories exist is the one thing a caller cannot recover by asking
    # again -- it is what tells them the repository is bigger than the answer -- whereas a file
    # name in a directory they can see is one follow-up call away.
    limit = min(len(summaries), MAX_TREE_DIRS)
    for names_per_dir in (MAX_TREE_NAMED_FILES, 6, 3, 1, 0):
        body = _render_tree(directory, total_files, total_dirs, summaries,
                            _pick_dirs(summaries, limit), names_per_dir)
        if len(body.encode()) <= MAX_TREE_BYTES:
            return body
    # No names at all and still too large: shrink the number of directories and re-render, so
    # `_pick_dirs` keeps sharing what is left between branches. Clipping the rendered text
    # instead would cut the tail of a path-ordered listing, which on a Maven tree is everything
    # under src/test -- and a run whose required output includes the test layout would then be
    # told the repository has no tests.
    while limit > 1:
        limit = max(1, limit * 2 // 3)
        body = _render_tree(directory, total_files, total_dirs, summaries,
                            _pick_dirs(summaries, limit), 0)
        if len(body.encode()) <= MAX_TREE_BYTES:
            return body
    return _clip_bytes(body, MAX_TREE_BYTES)


def _tree_branch(rel: str) -> str:
    """The part of a path that says which part of the project a directory belongs to."""
    return "/".join(rel.split("/")[:2])


def _pick_dirs(summaries: list[_DirSummary], limit: int) -> list[_DirSummary]:
    """At most `limit` directories to show: shallowest first, and every branch gets a share.

    Taking a prefix of `os.walk` order spends the whole budget on the first branch. Measured on
    a 4000-file Maven tree: `src/main/...` filled it and NOTHING under `src/test` was named, so
    a run whose required output includes the test layout would be told the repository has no
    tests. Depth alone does not fix that, because in a package-per-directory layout every leaf
    is at the same depth and `src/main` still sorts before `src/test`.

    So the budget is shared round-robin between branches (the first two path segments), taking
    shallower directories first within each. A branch that exists is therefore always
    represented, however many leaves some other branch has.

    The *printed* order is still path order: a tree with its levels and branches interleaved
    reads worse than one in path order, and the selection is the only thing this decides.
    """
    if len(summaries) <= limit:
        return summaries
    ordered = sorted(summaries,
                     key=lambda s: (0 if s.rel == "." else s.rel.count("/") + 1, s.rel))
    branches: dict[str, list[_DirSummary]] = {}
    for s in ordered:
        branches.setdefault(_tree_branch(s.rel), []).append(s)
    picked: list[_DirSummary] = []
    queues = list(branches.values())
    while len(picked) < limit and any(queues):
        for queue in queues:
            if queue and len(picked) < limit:
                picked.append(queue.pop(0))
    return sorted(picked, key=lambda s: s.rel)


def _render_tree(directory: str, total_files: int, total_dirs: int,
                 summaries: list[_DirSummary], shown: list[_DirSummary],
                 names_per_dir: int) -> str:
    out = [f"{directory}: {total_files} files in {total_dirs} directories "
           f"({len(shown)} non-empty directories shown of {len(summaries)}). "
           "Each line below is one directory; a file's path is that directory joined to the "
           "name, e.g. `src/app/` + `main.py` -> `src/app/main.py`. A trailing "
           "`+N-more[.ext=count,...]` says how many further files that directory holds and of "
           "what kind - those are counts, not names; call list_files on the directory for the "
           "names."]
    if names_per_dir < MAX_TREE_NAMED_FILES:
        out.append(f"(this tree is large, so at most {names_per_dir} file names are shown per "
                   "directory; call list_files on a directory for the rest)")
    for s in shown:
        # One line per directory, always: names up to the cap, then a histogram and a count of
        # what the names left out. Splitting a directory across two lines would make a path
        # ambiguous, which is the mistake this tool exists to stop making.
        head = f"{s.rel}/  files={len(s.files)}  bytes={s.total_bytes}"
        named = s.files[:names_per_dir]
        rest = s.files[len(named):]
        # One token, no spaces: a whitespace split of this line must not be able to produce a
        # word that looks like a file name but is not one.
        tail = "" if not rest else f"  +{len(rest)}-more[{_ext_histogram(rest)}]"
        out.append(f"{head}  {' '.join(named)}{tail}".rstrip())
    if len(summaries) > len(shown):
        out.append(f"... {len(summaries) - len(shown)} further non-empty directories not shown; "
                   f"call list_tree on one of the directories above to expand it")
    return "\n".join(out)


def _clip_bytes(text: str, limit: int) -> str:
    raw = text.encode()
    if len(raw) <= limit:
        return text
    return raw[:limit].decode(errors="ignore") + f"\n... truncated at {limit} bytes"


# --- repo_digest -------------------------------------------------------------------------
# Most of what `recon` needs before it can answer at all is the same three things on every
# repository: the tree, the manifests, and where the tests live. Answering them in three
# separate tools costs three round trips at best and, once `list_files` truncates, far more.
# This answers all three in one call.

MANIFEST_NAMES = (
    "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
    "package.json", "pyproject.toml", "requirements.txt", "setup.py", "setup.cfg", "Pipfile",
    "Cargo.toml", "go.mod", "Gemfile", "composer.json", "cpanfile", "Makefile", "Makefile.PL",
    "Build.PL", "META.json", "tox.ini", "Dockerfile", "README.md", "README.rst", "README",
)
# Path segments that conventionally name a test directory: `tests/` and `test/` (Python, Maven's
# `src/test/...`), `t/` (Perl), `spec/` (Ruby, JS) and `__tests__/` (Jest). A directory is a test
# directory when ANY WHOLE segment of its path is one of these, so everything beneath
# `src/test/` counts and `tools/`, `templates/`, `third_party/` or `testing_utils/` do not.
TEST_DIR_NAMES = frozenset({"test", "tests", "t", "spec", "__tests__"})


def _is_test_dir(rel: str) -> bool:
    return any(part in TEST_DIR_NAMES for part in rel.split("/"))


def _find_manifests(summaries: list[_DirSummary]) -> list[str]:
    """Repo-relative manifest paths, root ones first, then any nested ones."""
    found: list[str] = []
    for s in summaries:
        depth = 0 if s.rel == "." else s.rel.count("/") + 1
        if depth > 2:  # a manifest four levels down is a fixture, not the project's
            continue
        found += [name if s.rel == "." else f"{s.rel}/{name}"
                  for name in s.files if name in MANIFEST_NAMES]
    # Root manifests first: they are the project's own, and the budget may not reach the rest.
    return sorted(found, key=lambda p: (p.count("/"), MANIFEST_NAMES.index(Path(p).name)))


def _test_layout(summaries: list[_DirSummary]) -> list[str]:
    """Which directories hold tests, and what the existing test files are named."""
    hits = [s for s in summaries if _is_test_dir(s.rel)]
    if not hits:
        return ["(no conventional test directory found; look for test files beside the sources)"]
    out: list[str] = []
    for s in hits[:20]:
        out.append(f"{s.rel}/  files={len(s.files)}  "
                   f"{' '.join(s.files[:MAX_TREE_NAMED_FILES])}"
                   + (" ..." if len(s.files) > MAX_TREE_NAMED_FILES else ""))
    if len(hits) > 20:
        out.append(f"... and {len(hits) - 20} further test directories")
    return out


def repo_digest(ctx: RunContext[AgentDeps]) -> str:
    """The tree, the manifests and the test layout of the whole repository, in ONE call.

    Call this first on a repository you have not seen. It returns, together:

    * a directory-level tree with per-directory file counts and sizes (as `list_tree`);
    * the content of every build/dependency manifest and README it found near the root;
    * which directories hold the existing tests and what those test files are named.

    That is most of what profiling a repository needs before any judgement can be made, and
    obtaining it one tool at a time costs a full model round trip per tool. Use `list_tree`,
    `list_files`, `read_files` and `search_code` afterwards for whatever this did not answer.
    """
    root = Path(ctx.deps.repo_path).resolve()
    if not root.is_dir():
        raise ModelRetry("The repository snapshot is not a directory; nothing to digest.")
    try:
        summaries, total_files, total_dirs = _walk_dirs(root, root)
    except RepositoryAccessError as exc:
        # Fail closed, and say so: nothing is listed or read from a snapshot the boundary
        # rejects, and the absence is stated rather than left to read as an empty repository.
        return _clip_bytes("\n".join([
            "# Repository digest: traversal rejected", "", _traversal_rejected(exc),
            "The snapshot holds an entry the read-only repository tools refuse to traverse (a "
            "link that leaves the snapshot, a directory link, or a special file), so nothing in "
            "it was listed or read.",
            "", "## Tree", "(not listed)",
            "", "## Manifests and README (0 found: none were read)",
            "", "## Test layout", "(not listed)",
        ]), MAX_DIGEST_BYTES)
    sections = [f"# Repository digest: {total_files} files in {total_dirs} directories",
                "", "## Tree (one line per non-empty directory)",
                _tree_text(".", summaries, total_files, total_dirs)]
    manifests = _find_manifests(summaries)
    sections += ["", f"## Manifests and README ({len(manifests)} found"
                     + (f", first {MAX_DIGEST_MANIFESTS} shown" if len(manifests) > MAX_DIGEST_MANIFESTS else "")
                     + ")"]
    if not manifests:
        sections.append("(none found near the root - this project declares no build manifest "
                        "where one is conventionally placed)")
    for rel in manifests[:MAX_DIGEST_MANIFESTS]:
        sections.append("")
        sections.append(_read_one(root / rel, rel, 1, MAX_MANIFEST_LINES))
    for rel in manifests[MAX_DIGEST_MANIFESTS:]:
        sections.append(f"(not shown: {rel} - read it with read_files if you need it)")
    sections += ["", "## Test layout", *_test_layout(summaries)]
    return _clip_bytes("\n".join(sections), MAX_DIGEST_BYTES)


# --- search_code -------------------------------------------------------------------------
# The regex runs in a child interpreter, never in the worker: Python's `re` cannot be
# interrupted from another thread, and a pattern such as `(\w|\d)+x` against a long run of word
# characters backtracks for minutes. A shape check on the pattern was tried and is bypassable by
# construction, so the bound is a deadline on a process that can be killed. The parent walks and
# confines; the child only opens the files it is handed, matches, and prints one JSON line per
# hit as it goes, so a search stopped at the deadline still returns the hits it had found.
# `-I -S` keeps the child from importing anything from the environment or the working tree.

_SEARCH_WORKER = r"""
import json, re, sys
req = json.load(sys.stdin)
pattern = re.compile(req["regex"])
found = 0
for rel, path in req["files"]:
    try:
        with open(path, "rb") as fh:
            raw = fh.read(req["max_bytes"] + 1)
    except OSError:
        continue
    if len(raw) > req["max_bytes"]:
        continue
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        continue
    for lineno, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            sys.stdout.write(json.dumps([rel, lineno, line.strip()[: req["line_chars"]]]) + "\n")
            sys.stdout.flush()
            found += 1
            if found >= req["max_matches"]:
                sys.exit(0)
"""


def _run_search(regex: str, files: list[tuple[str, str]]) -> tuple[list[str], str | None]:
    """(hits as `path:line: text`, why the search stopped early or None if it completed)."""
    payload = json.dumps({"regex": regex, "files": files, "max_matches": MAX_MATCHES,
                          "max_bytes": MAX_FILE_BYTES, "line_chars": MAX_MATCH_CHARS}).encode()
    try:
        proc = subprocess.run([sys.executable, "-I", "-S", "-c", _SEARCH_WORKER], input=payload,
                              capture_output=True, timeout=SEARCH_TIMEOUT_SECONDS, check=False)
        stdout = proc.stdout
        stopped = (None if proc.returncode == 0 else
                   f"search did not complete (the search process exited with status "
                   f"{proc.returncode})")
    except subprocess.TimeoutExpired as exc:  # run() has already killed and reaped the child
        stdout = exc.stdout or b""
        stopped = (f"search timed out after {SEARCH_TIMEOUT_SECONDS:g} seconds and was stopped. "
                   "The regex backtracks too much on this repository: drop nested or alternated "
                   "repetition such as `(a|b)+`, anchor it, or narrow file_glob")
    hits: list[str] = []
    for raw in stdout.splitlines():
        try:
            rel, lineno, text = json.loads(raw)
        except (ValueError, TypeError):
            continue  # the line the kill cut short
        hits.append(f"{rel}:{lineno}: {text}")
    return hits[:MAX_MATCHES], stopped


def search_code(ctx: RunContext[AgentDeps], regex: str, file_glob: str = "*") -> str:
    """Search repository files matching `file_glob` for the Python regular expression `regex`.

    Returns `path:line: text` for up to 60 matches.
    """
    if len(regex.encode()) > 512:
        raise ModelRetry("Search regex is too large; use at most 512 bytes.")
    try:
        re.compile(regex)
    except re.error as e:
        raise ModelRetry(f"Invalid regex: {e}") from e
    root = Path(ctx.deps.repo_path).resolve()
    try:
        files = [(rel, str(path)) for rel, path in walk_files(root, skip_dirs=SKIP_DIRS)
                 if fnmatch.fnmatch(path.name, file_glob)]
    except RepositoryAccessError as exc:
        raise ModelRetry(_traversal_rejected(exc)) from exc
    if not files:
        return "(no matches)"
    hits, stopped = _run_search(regex, files)
    if stopped:
        # Partial results are labelled as partial: a search that was stopped is not a search
        # that found nothing.
        return "\n".join([*hits, f"... {stopped}; any matches above are partial"])
    if len(hits) >= MAX_MATCHES:
        return "\n".join(hits) + f"\n... truncated at {MAX_MATCHES} matches"
    return "\n".join(hits) or "(no matches)"
