"""Measure what one agent run costs in *round trips*, offline and deterministically.

Two live runs over ~500-file repositories failed every case with `UsageLimitExceeded`
during preparation, and scaling the budgets 2.2x by repo size only moved the wall: the
scaled limits were exhausted too. That says the ceiling is not the variable. What this
module measures is the variable that is: **how many model requests a fixed information
need costs, given the toolset the agent is handed.**

The measurement is offline (`FunctionModel`, no provider, no container) and free, so it can
be run on a synthetic repository swept across four sizes rather than argued from one live
data point.

Why this is a measurement and not a simulation
----------------------------------------------
The thing under test is the *toolset*, not the model. So the model side is pinned to a
fixed, declared information need — the tree, the manifests, where the tests live, and a
handful of representative source files, which is exactly what `agents/recon/agent.yaml`
instructs — and the explorer below satisfies that need using whatever tools the agent
actually exposes, reacting to the tools' real output. Nothing about the repository's shape
is modelled: the truncation that forces a second listing is `MAX_LIST` firing on real
`os.walk` output, and a manifest read is the real file being read. What the sweep then
shows is a property of the tool surface, which is provider-independent and is what a
change to the tool surface can move.

What it deliberately does NOT measure: whether a live model *chooses* the cheap path. A
scripted model cannot answer that, and claiming otherwise from these numbers would be
reading a model's judgement out of a fixture. The stopping-rule and parallel-tool-call
questions are model-behaviour questions and are out of scope here by construction.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from pydantic_ai.messages import (
    ModelMessage,
    ModelRequest,
    ModelResponse,
    ToolCallPart,
    ToolReturnPart,
)
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.usage import UsageLimits
from pydantic_ai_harness.compaction import estimate_token_count

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.agents.registry import build_agent
from infosec_harness.agents.render import render_prompt
from infosec_harness.domain.models import StackFingerprint

# --- the synthetic repository ---------------------------------------------------------------
#
# Shaped like the harvested Vul4J cases the live runs failed on: a Maven project with deep
# package nesting, a parallel test tree, and several manifests. Size is the only knob, so the
# sweep isolates growth in repository size from every other difference.

_FILES_PER_PACKAGE = 8


def _java_source(package: str, name: str) -> str:
    return (f"package {package};\n\n"
            f"public class {name} {{\n"
            f"    public String handle(String input) {{\n"
            f"        return input.trim();\n"
            f"    }}\n"
            f"}}\n")


def synth_repo(root: Path, source_files: int) -> Path:
    """Write a Maven-shaped repository of `source_files` main sources under `root`.

    Package breadth grows with the file count (`_FILES_PER_PACKAGE` per package) because that
    is how a real project of this size is laid out, and directory count — not file count — is
    what a flat, capped listing has to be called repeatedly to cover.
    """
    root.mkdir(parents=True, exist_ok=True)
    (root / "pom.xml").write_text(
        '<project><groupId>com.example</groupId><artifactId>app</artifactId>\n'
        "  <properties><maven.compiler.release>17</maven.compiler.release></properties>\n"
        "  <dependencies/>\n</project>\n")
    (root / "README.md").write_text("# app\n\nBuild with `mvn -q -DskipTests package`.\n")
    (root / ".gitignore").write_text("target/\n")
    packages = max(1, -(-source_files // _FILES_PER_PACKAGE))
    for p in range(packages):
        pkg = f"com.example.mod{p:03d}"
        main = root / "src/main/java/com/example" / f"mod{p:03d}"
        test = root / "src/test/java/com/example" / f"mod{p:03d}"
        main.mkdir(parents=True, exist_ok=True)
        test.mkdir(parents=True, exist_ok=True)
        for i in range(_FILES_PER_PACKAGE):
            n = p * _FILES_PER_PACKAGE + i
            if n >= source_files:
                break
            (main / f"Handler{n:04d}.java").write_text(_java_source(pkg, f"Handler{n:04d}"))
            if i == 0:  # one test class per package, as a real project has
                (test / f"Handler{n:04d}Test.java").write_text(
                    f"package {pkg};\n\nimport org.junit.jupiter.api.Test;\n\n"
                    f"public class Handler{n:04d}Test {{\n    @Test void handles() {{}}\n}}\n")
    return root


# --- the information need -------------------------------------------------------------------


@dataclass(frozen=True)
class InfoNeed:
    """What a run must learn before it can answer, stated once and held fixed.

    Taken from `agents/recon/agent.yaml`: "read the manifests, README, and a few
    representative source and test files", plus knowing where tests live. Holding this fixed
    across toolsets is what makes the before/after numbers attributable to the toolset.
    """

    manifests: tuple[str, ...] = ("pom.xml", "README.md")
    source_files: int = 6
    test_files: int = 1
    want_tree: bool = True


DEFAULT_NEED = InfoNeed()


# --- the explorer -----------------------------------------------------------------------------


@dataclass
class Trip:
    """One model request and the tool calls it carried."""

    calls: list[str] = field(default_factory=list)
    history_tokens: int = 0
    result_bytes: int = 0


@dataclass
class Measurement:
    """What one measured agent run cost."""

    label: str
    source_files: int
    requests: int
    tool_calls: int
    result_bytes: int
    peak_history_tokens: int
    files_seen: int = 0
    dirs_seen: int = 0
    dirs_total: int = 0
    trips: list[Trip] = field(default_factory=list)
    unmet: tuple[str, ...] = ()

    @property
    def calls_per_request(self) -> float:
        return self.tool_calls / self.requests if self.requests else 0.0

    @property
    def file_coverage(self) -> float:
        """Fraction of the repository's main sources the run learned the *name* of.

        Round trips are only half of what a capped listing costs. The other half is what the
        run never found out — and a profile of a fraction of a repository is wrong, not merely
        expensive.
        """
        return self.files_seen / self.source_files if self.source_files else 0.0

    @property
    def dir_coverage(self) -> float:
        """Fraction of the repository's source directories the run was told exist.

        Separate from `file_coverage` because the two failures differ in kind. A file name the
        run did not see is one follow-up call away, as long as it knows the directory is there.
        A *directory* it was never told about is invisible: nothing in the answer says to go
        looking, so the run concludes on a repository it believes it has seen.
        """
        return self.dirs_seen / self.dirs_total if self.dirs_total else 0.0

    def as_row(self) -> dict[str, object]:
        return {"label": self.label, "source_files": self.source_files,
                "requests": self.requests, "tool_calls": self.tool_calls,
                "result_kb": round(self.result_bytes / 1024, 1),
                "peak_history_tokens": self.peak_history_tokens,
                "files_seen": self.files_seen, "file_coverage": round(self.file_coverage, 4),
                "dirs_seen": self.dirs_seen, "dirs_total": self.dirs_total,
                "dir_coverage": round(self.dir_coverage, 4), "unmet": list(self.unmet)}


_TRUNCATED = re.compile(r"\.\.\. truncated at \d+ entries")
# `list_tree` prints "<dir>/  files=N  bytes=B  name name ..." — one line per directory, with
# file names relative to it, so a path is the directory joined to the name. Reconstructing that
# here is what a model does with the same output.
_TREE_DIR = re.compile(r"^(?P<dir>[\w./-]+)/\s+files=(?P<n>\d+)(?:\s+bytes=\d+)?\s*(?P<rest>.*)$")


def _paths_from_tree(content: str) -> list[str]:
    """Repo-relative file paths named by a `list_tree` / `repo_digest` listing."""
    out: list[str] = []
    for line in content.splitlines():
        m = _TREE_DIR.match(line)
        if not m:
            continue
        directory = m.group("dir")
        prefix = "" if directory == "." else directory + "/"
        for name in m.group("rest").split():
            if name.startswith("+") or "=" in name or "[" in name:
                continue  # a `+N-more[.java=8]` count marker, not a file name
            out.append(prefix + name)
    return out


def dirs_named_by_tree(content: str) -> set[str]:
    """Directories a `list_tree` / `repo_digest` listing states exist."""
    return {m.group("dir") for line in content.splitlines()
            if (m := _TREE_DIR.match(line))}


def source_dirs(repo: Path) -> set[str]:
    """Every directory of the synthetic repository that holds files, repo-relative."""
    out: set[str] = set()
    for path in repo.rglob("*"):
        if path.is_file():
            rel = path.parent.relative_to(repo).as_posix() or "."
            out.add(rel)
    return out


def _tool_names(info: AgentInfo) -> set[str]:
    return {t.name for t in info.function_tools}


def _last_return(messages: Sequence[ModelMessage]) -> tuple[str, str] | None:
    """(tool_name, content) of the most recent tool return, or None on the first request."""
    for msg in reversed(messages):
        if not isinstance(msg, ModelRequest):
            continue
        for part in reversed(msg.parts):
            if isinstance(part, ToolReturnPart):
                return part.tool_name, str(part.content)
    return None


@dataclass
class Explorer:
    """A fixed exploration procedure, reacting to the tools' real output.

    The procedure is the one `recon`'s instructions describe, in the order they describe it:
    establish the tree, read the manifests, find the tests, sample a few sources, answer. At
    each step it uses the *cheapest tool the agent actually exposes* for that step — so adding
    a tool that answers a step in one call is visible as a shorter run, and adding a tool that
    answers nothing is visible as no change at all.

    State lives here rather than in the messages because the messages are what is being
    measured; a generator would be simpler but could not react to a truncated listing.
    """

    need: InfoNeed
    output_args: dict[str, object]
    trips: list[Trip] = field(default_factory=list)
    _plan: Iterator[list[ToolCallPart]] | None = None
    _pending_dirs: list[str] = field(default_factory=list)
    _listed: list[str] = field(default_factory=list)
    _known_files: list[str] = field(default_factory=list)
    _done: set[str] = field(default_factory=set)

    # -- steps ---------------------------------------------------------------------------
    def _digest_step(self, tools: set[str]) -> list[ToolCallPart] | None:
        """One call that answers the tree, the manifests and the test layout together."""
        if "repo_digest" not in tools or "digest" in self._done:
            return None
        self._done |= {"digest", "tree", "manifests", "tests"}
        return [ToolCallPart("repo_digest", {})]

    def _tree_step(self, tools: set[str], last: tuple[str, str] | None) -> list[ToolCallPart] | None:
        """Establish the tree, descending wherever the flat listing's cap truncated it.

        `list_files` is recursive but capped at `MAX_LIST` entries, so on a large repository
        the answer to `list_files('.')` is a *prefix* of the tree. A prefix is not a tree: it
        neither enumerates the source files nor even names every directory, so the only way
        to cover the repository is to list each directory the truncated window did name, and
        repeat wherever that is truncated too. This loop is that, and it is the growth driver
        — real `MAX_LIST` truncation on real `os.walk` output, not an assumption about a model.
        """
        if not self.need.want_tree or "tree" in self._done:
            return None
        if "list_tree" in tools:
            self._done.add("tree")
            return [ToolCallPart("list_tree", {"directory": "."})]
        if not self._listed:
            self._listed.append(".")
            return [ToolCallPart("list_files", {"directory": ".", "pattern": "*"})]
        while self._pending_dirs:
            d = self._pending_dirs.pop(0)
            if d in self._listed:
                continue
            self._listed.append(d)
            return [ToolCallPart("list_files", {"directory": d, "pattern": "*"})]
        self._done.add("tree")
        return None

    def _absorb_listing(self, directory: str, content: str) -> None:
        entries = [ln for ln in content.splitlines()
                   if ln and not ln.startswith(("(no matches)", "..."))]
        self._known_files += [e for e in entries if e not in self._known_files]
        self._dirs_seen |= {e.rsplit("/", 1)[0] for e in entries if "/" in e}
        if not _TRUNCATED.search(content):
            return  # this subtree was listed in full; nothing under it needs another call
        prefix = "" if directory == "." else directory.rstrip("/") + "/"
        for entry in entries:
            rest = entry[len(prefix):] if entry.startswith(prefix) else entry
            if "/" not in rest:
                continue
            child = prefix + rest.split("/", 1)[0]
            if child not in self._listed and child not in self._pending_dirs:
                self._pending_dirs.append(child)

    def _manifest_step(self, tools: set[str]) -> list[ToolCallPart] | None:
        if "manifests" in self._done:
            return None
        plan = self._reads(tools, list(self.need.manifests))
        if plan is None:
            return None  # nothing here can read a file, so this need stays unmet
        self._done.add("manifests")
        return plan

    def _reads(self, tools: set[str], paths: list[str]) -> list[ToolCallPart] | None:
        """One batched call if the agent has `read_files`, else one round trip per path."""
        if not paths:
            return None
        if "read_files" in tools:
            return [ToolCallPart("read_files", {"paths": paths})]
        if "read_file" not in tools:
            return None
        # One round trip per file: the cost this whole experiment is about.
        self._plan = iter([[ToolCallPart("read_file", {"path": p})] for p in paths[1:]])
        return [ToolCallPart("read_file", {"path": paths[0]})]

    def _tests_step(self, tools: set[str]) -> list[ToolCallPart] | None:
        if "tests" in self._done:
            return None
        self._done.add("tests")
        if "list_tree" in tools or "repo_digest" in tools:
            return None  # the tree already named the test root
        return [ToolCallPart("list_files", {"directory": ".", "pattern": "*Test.java"})]

    def _names_step(self, tools: set[str]) -> list[ToolCallPart] | None:
        """One listing when the tree gave counts but no names.

        On a tree too large to name every file, `list_tree` names the directories and their
        file counts and says to call `list_files` on one for the names. That follow-up is the
        tool's intended workflow, so the measurement pays for it rather than pretending the
        digest answered everything.
        """
        if "names" in self._done or self._main_sources():
            return None
        self._done.add("names")
        candidates = [d for d in sorted(self._dirs_seen) if "/main/" in d or "/test/" in d]
        if not candidates:
            return None
        self._listed.append(candidates[0])
        return [ToolCallPart("list_files", {"directory": candidates[0], "pattern": "*"})]

    def _sources_step(self, tools: set[str]) -> list[ToolCallPart] | None:
        if "sources" in self._done:
            return None
        plan = self._reads(tools, self._pick_sources())
        if plan is None:
            return None
        self._done.add("sources")
        return plan

    def _main_sources(self) -> list[str]:
        """Main-source paths this run has been told the name of, however it learned them."""
        return [p for p in self.discovered()
                if p.endswith(".java") and "/test/" not in p]

    def _pick_sources(self) -> list[str]:
        """Representative sources and tests, from what the run has actually been told."""
        mains = sorted(self._main_sources())
        tests = sorted(p for p in self.discovered() if p.endswith("Test.java"))
        return mains[: self.need.source_files] + tests[: self.need.test_files]

    _digest_seen: list[str] = field(default_factory=list)
    _dirs_seen: set[str] = field(default_factory=set)

    def discovered(self) -> set[str]:
        """Every repository path this run was ever told about, however it learned it."""
        return set(self._known_files) | set(self._digest_seen)

    # -- the model function --------------------------------------------------------------
    def __call__(self, messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        trip = Trip(history_tokens=estimate_token_count(messages))
        last = _last_return(messages)
        if last:
            trip.result_bytes = 0  # accounted against the trip that produced it, below
            self._absorb(last)
        tools = _tool_names(info)
        parts = self._next(tools, last)
        if parts is None:
            parts = [ToolCallPart(info.output_tools[0].name, self.output_args)]
        trip.calls = [p.tool_name for p in parts]
        self.trips.append(trip)
        return ModelResponse(parts=parts)

    def _absorb(self, last: tuple[str, str]) -> None:
        name, content = last
        self.trips[-1].result_bytes += len(content.encode())
        if name in ("repo_digest", "list_tree"):
            for path in _paths_from_tree(content):
                if path not in self._digest_seen:
                    self._digest_seen.append(path)
            self._dirs_seen |= dirs_named_by_tree(content)
        elif name == "list_files" and self._listed:
            self._absorb_listing(self._listed[-1], content)

    def _next(self, tools: set[str], last: tuple[str, str] | None) -> list[ToolCallPart] | None:
        if self._plan is not None:
            try:
                return next(self._plan)
            except StopIteration:
                self._plan = None
        for step in (lambda: self._digest_step(tools),
                     lambda: self._tree_step(tools, last),
                     lambda: self._manifest_step(tools),
                     lambda: self._tests_step(tools),
                     lambda: self._names_step(tools),
                     lambda: self._sources_step(tools)):
            parts = step()
            if parts:
                return parts
        return None


# --- running a measurement ------------------------------------------------------------------

# The ceiling is deliberately not the agent's own. A run that stops at its budget reports the
# budget, and the budget is not what is under test: the cost is. `MEASUREMENT_CEILING` is far
# above any healthy run and exists only so a defect in the explorer cannot loop forever
# (pydantic-ai's own default is 50, which a 500-file repository exceeds on the baseline
# toolset — that is a finding, not a place to stop measuring).
MEASUREMENT_CEILING = 2_000
MEASUREMENT_LIMITS = UsageLimits(request_limit=MEASUREMENT_CEILING,
                                 tool_calls_limit=MEASUREMENT_CEILING)

_RECON_OUTPUT: dict[str, object] = {
    "summary": "A Maven library of request handlers.",
    "primary_language": "java",
    "test_framework": "junit5",
    "test_layout": "src/test/java mirrors src/main/java",
}


async def measure_recon(repo: Path, *, label: str, source_files: int,
                        overlay: dict | None = None) -> Measurement:
    """Run `recon` against `repo` with the scripted explorer and report what it cost.

    Budgets are removed for the measurement on purpose: a run that stops at the ceiling
    reports the ceiling rather than the cost, and the cost is the number under test. What the
    ceiling would have done to it is arithmetic afterwards.
    """
    explorer = Explorer(need=DEFAULT_NEED, output_args=_RECON_OUTPUT)
    agent = build_agent("recon", overlay, durable=False)
    stack = StackFingerprint(languages={"java": source_files}, manifests=["pom.xml"],
                             test_frameworks=["junit5"])
    prompt = render_prompt("Profile this repository.", {}, stack=stack)
    with agent.override(model=FunctionModel(explorer)):
        await agent.run(prompt, deps=AgentDeps(repo_path=str(repo), source_files=source_files),
                        usage_limits=MEASUREMENT_LIMITS)
    return _summarise(label, source_files, explorer, source_dirs(repo))


def _summarise(label: str, source_files: int, explorer: Explorer,
               all_dirs: set[str]) -> Measurement:
    trips = explorer.trips
    unmet = tuple(sorted({"tree", "manifests", "tests", "sources"} - explorer._done))
    seen = {p for p in explorer.discovered() if "/main/" in p and p.endswith(".java")}
    return Measurement(
        label=label, source_files=source_files, requests=len(trips),
        tool_calls=sum(len(t.calls) for t in trips if t.calls[0] != "final_result"),
        result_bytes=sum(t.result_bytes for t in trips),
        peak_history_tokens=max((t.history_tokens for t in trips), default=0),
        files_seen=len(seen), dirs_seen=len(explorer._dirs_seen & all_dirs),
        dirs_total=len(all_dirs), trips=trips, unmet=unmet,
    )


# --- prompt-cache prefix stability ------------------------------------------------------------
#
# The README claims a stable->volatile prompt layout and records `cache_hit_ratio`. The runtime
# monitor (`WarnOnCacheBusts`) reads the provider's own verdict, so it says nothing offline.
# What *can* be checked offline is the structural precondition the provider verdict depends on:
# that the message list handed to the model keeps a growing common prefix across the requests
# of one run. A prefix that shrinks or is rewritten mid-run cannot be served from cache however
# the cache points are placed, and costs full prefill latency on every request after it.


def serialise_history(messages: Sequence[ModelMessage]) -> list[str]:
    """One stable string per message part, so two requests' prefixes can be compared."""
    out: list[str] = []
    for msg in messages:
        for part in getattr(msg, "parts", []):
            payload: object
            if isinstance(part, ToolCallPart):
                payload = (part.tool_name, str(part.args))
            elif isinstance(part, ToolReturnPart):
                payload = (part.tool_name, str(part.content))
            else:
                payload = str(getattr(part, "content", part))
            out.append(f"{type(part).__name__}:{json.dumps(payload, default=str)}")
    return out


def common_prefix_len(a: Sequence[str], b: Sequence[str]) -> int:
    n = 0
    for x, y in zip(a, b, strict=False):
        if x != y:
            break
        n += 1
    return n


@dataclass
class PrefixReport:
    """How the cacheable prefix behaved across one run's requests."""

    part_counts: list[int]
    shared_prefix: list[int]  # shared with the immediately preceding request
    rewrites: list[int]  # request indices whose prefix is shorter than the previous history

    @property
    def stable(self) -> bool:
        return not self.rewrites


def prefix_report(histories: Sequence[Sequence[str]]) -> PrefixReport:
    counts = [len(h) for h in histories]
    shared = [0]
    rewrites: list[int] = []
    for i in range(1, len(histories)):
        n = common_prefix_len(histories[i - 1], histories[i])
        shared.append(n)
        # A healthy turn appends: the whole previous history is a prefix of this one.
        if n < len(histories[i - 1]):
            rewrites.append(i)
    return PrefixReport(part_counts=counts, shared_prefix=shared, rewrites=rewrites)


def recording_model(fn: Callable[[list[ModelMessage], AgentInfo], ModelResponse],
                    sink: list[list[str]]) -> FunctionModel:
    """`fn`, with every request's serialized history appended to `sink`."""

    def wrapped(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        sink.append(serialise_history(messages))
        return fn(messages, info)

    return FunctionModel(wrapped)
