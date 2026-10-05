"""Harvest the Vul4J dataset into paired corpus cases our own pipeline can score.

Vul4J (Bui, Scandariato et al., MSR 2022) is a reproducible benchmark of real Java
vulnerabilities. It ships pinned Docker images and per-entry build and test commands so
that anyone can rebuild each project exactly as the authors did. We deliberately take
none of that. Our `env-planner` and `build-repair` stages exist to work out how to build
an unfamiliar repository, and handing them a known-good `mvn` incantation would measure
nothing. So this harvester reads Vul4J's dataset index for *facts* only — repository,
fix commit, CVE, CWE, build system, JDK level, and whether a proof-of-vulnerability test
exists — and leaves the rest to our pipeline.

Each usable entry becomes a pair of cases, matching the convention in
`eval-corpus/manifest.json`: `<base>-vulnerable` points at the fix commit's parent and is
expected to be `potentially_exploitable`, `<base>-fixed` points at the fix commit and is
expected to be `likely_not_exploitable`. Unlike the seeded corpus, `finding.repo_url` is a
remote git URL and `finding.revision` is a commit SHA; `repo.checkout.checkout()` already
handles both, keyed by `repo_url@revision`.

Output goes to `eval-corpus/external/vul4j.json`, never into the seeded manifest.

## Leakage

Vul4J's proof-of-vulnerability (PoV) test is usually *added by the fix commit*, which is
what makes the pair sound: the vulnerable checkout has no test demonstrating the bug, so
our `probe-author` stage has to write one. When the PoV predates the fix, the agent can
read it out of the tree and copy it, and the probe-author measurement degrades into
transcription. This harvester determines, per entry, whether the PoV exists at the
vulnerable revision, and refuses to emit such entries as ordinary cases — they go to a
`quarantined` list instead, with the reason.

That check protects the `-vulnerable` side only. On the `-fixed` side the PoV is present
by construction, so **every** consumer of this file must mask `truth.pov.mask_paths` out
of the checkout the agent reads. See `docs/evaluation/CORPUS_SOURCES.md`.

## Licence

Vul4J's *data* is CC-BY-4.0 and its *code* is GPL-3.0. We read the dataset index and
record attribution per case; we copy none of their code, and we do not vendor their test
files — only the path and test name, as ground truth for scoring.

    uv run python scripts/harvest_vul4j.py                    # fetch and write
    uv run python scripts/harvest_vul4j.py --dataset <path>   # use a local CSV
    uv run python scripts/harvest_vul4j.py --dry-run          # report, write nothing

Resolving parent commits and PoV presence needs the GitHub API. Pass `--token`, or set
`GITHUB_TOKEN`/`GH_TOKEN`, or have an authenticated `gh` on PATH; unauthenticated runs are
rate-limited to 60 requests an hour and will not get through the dataset. Responses are
cached under `--cache-dir` so re-runs are cheap and offline-repeatable.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

# The one answer to "which CWEs have a skill", shared with the trajectory scorer so a harvested
# case is classified covered exactly when the scorer would look for a matching skill.
from infosec_harness.evals.trajectory import skill_covered_cwes

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
# The harness's own build-file classifier, so what is recorded here and what the harness detects
# in a checkout cannot disagree about a repository's test framework.
from infosec_harness.repo.detect import jvm_test_framework  # noqa: E402

DATASET_URL = "https://raw.githubusercontent.com/tuhh-softsec/vul4j/main/dataset/vul4j_dataset.csv"

ATTRIBUTION = {
    "dataset": "vul4j",
    "name": "Vul4J: A Dataset of Reproducible Java Vulnerabilities",
    "authors": "Quang-Cuong Bui, Riccardo Scandariato, et al. (MSR 2022)",
    "url": "https://github.com/tuhh-softsec/vul4j",
    "dataset_url": DATASET_URL,
    "licence": "Dataset content licensed CC-BY-4.0 (https://creativecommons.org/licenses/by/4.0/). "
               "Vul4J's own source code is GPL-3.0 and is not used, copied, or adapted here.",
}

# The only CWE rewrite we are willing to defend. CWE-77 (Command Injection) is the direct
# parent of CWE-78 (OS Command Injection), and `skills/cwe-78-os-command-injection` reads
# correctly for both. Everything else stays verbatim: silently relabelling a dataset's own
# classification to make our scorer happy would be inventing ground truth.
ADJACENT_CWES = {"CWE-77": "CWE-78"}

# Vul4J entries numbered 80 and up carry the `-S` suffix: they are static-analysis warnings
# harvested from student projects, with no CVE, no CWE, and no proof-of-vulnerability test.
# Nothing in our pipeline can score them.
STATIC_WARNING_SUFFIX = "-S"

# A handful of entries record their fix commit against a repository the Vul4J authors own
# rather than the upstream project. Those SHAs are not in the upstream history — the commit
# was rewritten or the branch deleted — so cloning `repo_slug` and checking the SHA out
# fails. We cannot substitute the mirror either: its history is not the project's, and its
# contents are the authors' work under GPL-3.0.
VUL4J_MIRROR_OWNERS = {"tuhh-softsec", "bqcuong"}

PATCH_URL = re.compile(r"https://github\.com/([^/]+)/([^/]+)/(commit|compare)/(.+)$")


# --------------------------------------------------------------------------------------
# Dataset


@dataclass(frozen=True)
class Entry:
    """One row of Vul4J's dataset index, reduced to the columns we are willing to use."""

    vul_id: str
    cve_id: str
    cwe_id: str
    cwe_name: str
    repo_slug: str
    human_patch: str
    build_system: str
    jdk: str
    failing_tests: tuple[str, ...]
    module: str
    src_dir: str
    test_dir: str

    @property
    def patch(self) -> tuple[str, str, str] | None:
        """(`owner/repo`, kind, ref) parsed out of `human_patch`, or None if unparseable.

        The dataset's `repo_slug` and the patch URL's slug disagree for a few entries. The
        patch URL is the one that matters: the SHA demonstrably resolves there. Sometimes
        that is a benign upstream rename (`apache/batik` -> `apache/xmlgraphics-batik`) and
        sometimes it is a Vul4J mirror, which `harvest` rejects.
        """
        m = PATCH_URL.match(self.human_patch)
        return (f"{m.group(1)}/{m.group(2)}", m.group(3), m.group(4)) if m else None

    @property
    def fix_slug(self) -> str:
        return self.patch[0] if self.patch else self.repo_slug

    @property
    def fix_sha(self) -> str:
        return self.patch[2] if self.patch else self.human_patch.rstrip("/").rsplit("/", 1)[-1]

    @property
    def repo_url(self) -> str:
        return f"https://github.com/{self.fix_slug}.git"

    @property
    def sort_key(self) -> tuple[int, str]:
        # The digits after the dash, not the `4` in `VUL4J`.
        digits = re.search(r"-(\d+)", self.vul_id)
        return (int(digits.group(1)) if digits else 10**9, self.vul_id)


def _split_tests(raw: str) -> tuple[str, ...]:
    """Vul4J separates multiple failing tests with commas; parameterised names carry `[...]`."""
    return tuple(t.strip() for t in raw.split(",") if t.strip())


def parse_dataset(text: str) -> list[Entry]:
    """Parse Vul4J's dataset CSV. Order is by numeric entry id so output is stable."""
    entries = [
        Entry(
            vul_id=row["vul_id"].strip(),
            cve_id=row.get("cve_id", "").strip(),
            cwe_id=row.get("cwe_id", "").strip(),
            cwe_name=row.get("cwe_name", "").strip(),
            repo_slug=row.get("repo_slug", "").strip(),
            human_patch=row.get("human_patch", "").strip(),
            build_system=row.get("build_system", "").strip(),
            jdk=row.get("compliance_level", "").strip(),
            failing_tests=_split_tests(row.get("failing_tests", "")),
            module=row.get("failing_module", "").strip(),
            src_dir=row.get("src", "").strip(),
            test_dir=row.get("test", "").strip(),
        )
        for row in csv.DictReader(io.StringIO(text))
        if row.get("vul_id", "").strip()
    ]
    return sorted(entries, key=lambda e: e.sort_key)


# --------------------------------------------------------------------------------------
# GitHub access


class Resolver(Protocol):
    """The two GitHub reads the harvester needs. Injected so tests never touch the network."""

    def commit(self, slug: str, sha: str) -> dict: ...

    def file_at(self, slug: str, ref: str, path: str) -> str | None: ...

    def tree(self, slug: str, ref: str) -> tuple[list[str], bool]: ...


def _discover_token(explicit: str | None) -> str | None:
    if explicit:
        return explicit
    for var in ("GITHUB_TOKEN", "GH_TOKEN"):
        if os.environ.get(var):
            return os.environ[var]
    try:
        out = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() or None


class GitHubResolver:
    """Read-only GitHub API access, cached on disk so re-runs are deterministic and cheap."""

    def __init__(self, token: str | None = None, cache_dir: Path | None = None) -> None:
        self.token = token
        self.cache_dir = cache_dir
        if cache_dir:
            cache_dir.mkdir(parents=True, exist_ok=True)
        self.calls = 0

    def _get(self, url: str) -> dict | None:
        key = hashlib.sha256(url.encode()).hexdigest()[:24]
        cached = (self.cache_dir / f"{key}.json") if self.cache_dir else None
        if cached is not None and cached.exists():
            raw = json.loads(cached.read_text())
            return None if raw is None else raw
        req = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "infosec-harness-vul4j-harvester",
            **({"Authorization": f"Bearer {self.token}"} if self.token else {}),
        })
        self.calls += 1
        # GitHub answers a long run of requests with the occasional 502/504. Those are
        # transient and must not abort a harvest that is most of the way through.
        for attempt in range(5):
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - fixed https host
                    payload = json.loads(resp.read().decode())
                break
            except urllib.error.HTTPError as exc:
                if exc.code in (403, 429):
                    raise RuntimeError(
                        f"GitHub rate-limited this run ({exc.code}). Pass --token or authenticate `gh`."
                    ) from exc
                # 404 is "no such commit or file". 422 is GitHub declining to serve the
                # resource at all — usually a merge commit whose diff is too large to
                # render. Both mean we cannot harvest this entry, not that the run failed.
                if exc.code in (404, 422):
                    payload = {"__unavailable__": exc.code} if exc.code == 422 else None
                    break
                if exc.code < 500 or attempt == 4:
                    raise
            except (urllib.error.URLError, TimeoutError):
                if attempt == 4:
                    raise
            time.sleep(2 ** attempt)
        if cached is not None:
            cached.write_text(json.dumps(payload))
        return payload

    def commit(self, slug: str, sha: str) -> dict:
        got = self._get(f"https://api.github.com/repos/{slug}/commits/{sha}")
        if got is None:
            raise LookupError(f"commit {slug}@{sha} not found")
        if "__unavailable__" in got:
            raise LookupError(f"GitHub will not serve {slug}@{sha} (HTTP {got['__unavailable__']})")
        return got

    def file_at(self, slug: str, ref: str, path: str) -> str | None:
        got = self._get(
            f"https://api.github.com/repos/{slug}/contents/{urllib.parse.quote(path)}?ref={ref}"
        )
        # Files over 1MB come back with an empty `content`; treat that as "exists but
        # unreadable" rather than "absent", so we never conclude a PoV is missing on a
        # technicality. No test file in the dataset is that large, but the distinction matters.
        if got is None or "__unavailable__" in got or got.get("type") != "file":
            return None
        if got.get("encoding") != "base64" or not got.get("content"):
            return ""
        return base64.b64decode(got["content"]).decode("utf-8", errors="replace")

    def tree(self, slug: str, ref: str) -> tuple[list[str], bool]:
        """Every path at a revision, and whether GitHub truncated the answer."""
        got = self._get(f"https://api.github.com/repos/{slug}/git/trees/{ref}?recursive=1")
        if got is None or "__unavailable__" in got:
            return [], True
        return [e["path"] for e in got.get("tree", []) if e.get("type") == "blob"], bool(got.get("truncated"))


# --------------------------------------------------------------------------------------
# Proof-of-vulnerability analysis — the leakage check


@dataclass
class Pov:
    """What we could establish about an entry's proof-of-vulnerability test."""

    test_class: str = ""
    test_method: str = ""
    path: str | None = None
    additional_tests: tuple[str, ...] = ()
    present_at_vulnerable: bool | None = None
    origin: str = "unknown"  # fix-commit | pre-existing | not-in-repository | unknown
    evidence: str = ""

    @property
    def mask_paths(self) -> list[str]:
        return [self.path] if self.path else []


def split_test(spec: str) -> tuple[str, str]:
    """`com.foo.BarTest#baz[0]` -> (`com.foo.BarTest`, `baz`)."""
    cls, _, method = spec.partition("#")
    return cls.strip(), re.sub(r"\[.*$", "", method).strip()


def candidate_paths(entry: Entry, test_class: str, simple: str | None = None) -> list[str]:
    """Where the PoV's source file would live, most specific first.

    Vul4J records the failing module and the module-relative test root, so the first guess
    is exact. The rest cover the entries where those columns disagree with the tree.
    """
    package = test_class.rsplit(".", 1)[0] if "." in test_class else ""
    simple = simple or test_class.rsplit(".", 1)[-1].split("$", 1)[0]
    rel = "/".join(p for p in (package.replace(".", "/"), f"{simple}.java") if p)
    module = "" if entry.module in ("", "root") else entry.module.strip("/")
    roots = [entry.test_dir] if entry.test_dir else []
    roots += [r for r in ("src/test/java", "src/test/groovy", "src/test") if r not in roots]
    out = []
    for root in roots:
        for prefix in ([module] if module else []) + [""]:
            path = "/".join(p for p in (prefix, root, rel) if p)
            if path not in out:
                out.append(path)
    return out


def _has_method(source: str, method: str) -> bool:
    """Does this test source declare `method`?

    An empty `source` means the file exists but we could not read it (GitHub truncates
    blobs over 1MB). We answer `True` there: guessing "absent" would quietly let a leaking
    entry into the corpus, and guessing "present" only costs us one case.
    """
    if not method:
        return True
    if source == "":
        return True
    return bool(re.search(rf"\b{re.escape(method)}\s*\(", source))


def analyse_pov(entry: Entry, commit: dict, resolver: Resolver, parent_sha: str) -> Pov:
    """Decide whether the PoV test already exists at the vulnerable revision.

    Three outcomes matter, and they are different kinds of fact:

    * `fix-commit` — the fix added the test file, or added this method to an existing file.
      The vulnerable checkout does not contain it. This is the case we want.
    * `pre-existing` — the file and the method are both there at the parent commit. An
      agent reading the vulnerable checkout can copy the PoV, so the entry is quarantined.
    * `not-in-repository` — neither revision has it. Vul4J wrote the test themselves, and
      their code is GPL-3.0, so we have no PoV to point at and no right to vendor theirs.
    """
    if not entry.failing_tests:
        return Pov(origin="not-in-repository", evidence="dataset lists no failing test")

    test_class, test_method = split_test(entry.failing_tests[0])
    # A few entries name a nested test class (`Outer$Inner$Deeper`). The source file is the
    # outermost class, so everything from the first `$` on is not part of the path.
    simple = test_class.rsplit(".", 1)[-1].split("$", 1)[0]
    pov = Pov(test_class=test_class, test_method=test_method,
              additional_tests=entry.failing_tests[1:])

    # The commit's own file list answers most entries without a second request.
    files = {f["filename"]: f for f in commit.get("files", [])}
    touched = [p for p in files if p.endswith(f"/{simple}.java") or p == f"{simple}.java"]

    if touched:
        pov.path = sorted(touched, key=len)[0]
        status = files[pov.path].get("status")
        if status == "added":
            pov.present_at_vulnerable = False
            pov.origin = "fix-commit"
            pov.evidence = "fix commit adds the test file"
            return pov
        # The file existed; the method may or may not have. Read the parent's copy.
        before = resolver.file_at(entry.fix_slug, parent_sha, pov.path)
        if before is None:
            pov.present_at_vulnerable = False
            pov.origin = "fix-commit"
            pov.evidence = f"test file absent at {parent_sha[:10]}"
            return pov
        has_method = _has_method(before, test_method)
        pov.present_at_vulnerable = has_method
        pov.origin = "pre-existing" if has_method else "fix-commit"
        pov.evidence = (
            f"test method `{test_method}` already present at {parent_sha[:10]}" if has_method
            else f"fix commit adds `{test_method}` to an existing test file"
        )
        return pov

    # The fix commit did not touch the test at all. Either it predates the fix entirely, or
    # it is one of Vul4J's own additions and lives in neither revision. Guess the path from
    # the module layout first, and if that misses, list the vulnerable tree and look for the
    # file by name — a guess that misses must never be read as "the test is not there".
    paths = candidate_paths(entry, test_class, simple)
    for path in paths:
        if (before := resolver.file_at(entry.fix_slug, parent_sha, path)) is not None:
            return _classify_existing(pov, path, before, test_method, parent_sha, touched_by_fix=False)

    tree, truncated = resolver.tree(entry.fix_slug, parent_sha)
    found = sorted((p for p in tree if p.endswith(f"/{simple}.java") or p == f"{simple}.java"), key=len)
    if found:
        before = resolver.file_at(entry.fix_slug, parent_sha, found[0])
        if before is not None:
            return _classify_existing(pov, found[0], before, test_method, parent_sha, touched_by_fix=False)
    if truncated:
        # We could not enumerate the tree, so we do not know. Say so, and let `harvest`
        # treat "unknown" the same as "present": an unverified entry is not a safe one.
        pov.present_at_vulnerable = None
        pov.origin = "unknown"
        pov.evidence = f"could not enumerate the tree at {parent_sha[:10]}; PoV presence is unverified"
        return pov

    pov.present_at_vulnerable = False
    pov.origin = "not-in-repository"
    pov.evidence = (
        f"no file named {simple}.java at {parent_sha[:10]} and the fix does not add one; "
        "Vul4J supplies this test out of tree"
    )
    return pov


def _classify_existing(pov: Pov, path: str, source: str, method: str, parent_sha: str,
                       *, touched_by_fix: bool) -> Pov:
    """Record the verdict for a test file that does exist at the vulnerable revision."""
    pov.path = path
    has_method = _has_method(source, method)
    pov.present_at_vulnerable = has_method
    pov.origin = "pre-existing" if has_method else ("fix-commit" if touched_by_fix else "not-in-repository")
    pov.evidence = (
        f"test file and method present at {parent_sha[:10]}, untouched by the fix" if has_method
        else f"test file present at {parent_sha[:10]} but without `{method}`"
    )
    return pov


# --------------------------------------------------------------------------------------
# Sink derivation


TEST_PATH = re.compile(r"(^|/)(test|tests|src/test)(/|$)")


def derive_sink(entry: Entry, commit: dict) -> tuple[str | None, int | None, str | None]:
    """Approximate the sink from the fix commit's largest non-test Java hunk.

    Vul4J records no sink location, so this is genuinely a heuristic: the file the fix
    changed most, and the first line its first hunk touches. It is recorded with
    `sink_confidence: fix-hunk-heuristic` and should be read as "where the fix landed",
    not "where the tainted value is consumed". Nothing short of building and analysing each
    project gives the real sink line, and building them is precisely what we refuse to
    inherit from Vul4J.
    """
    java = [
        f for f in commit.get("files", [])
        if f.get("filename", "").endswith(".java") and not TEST_PATH.search(f["filename"])
    ]
    if not java:
        return None, None, None
    primary = max(java, key=lambda f: (f.get("changes", 0), -len(f["filename"])))
    path = primary["filename"]
    line = None
    if hunk := re.search(r"^@@ -\d+(?:,\d+)? \+(\d+)", primary.get("patch", "") or "", re.M):
        line = int(hunk.group(1))
    # `a/b/src/main/java/com/x/Y.java` -> `com.x.Y`, which is as close to a target callable
    # as the dataset supports without parsing the file.
    fq = re.sub(r"\.java$", "", path)
    if "/java/" in fq:
        fq = fq.split("/java/", 1)[1]
    elif entry.src_dir and f"{entry.src_dir}/" in fq:
        fq = fq.split(f"{entry.src_dir}/", 1)[1]
    return path, line, fq.replace("/", ".")


# --------------------------------------------------------------------------------------
# Case construction


def classify_cwe(cwe_id: str, covered: tuple[str, ...]) -> dict:
    """Say plainly whether our scorer has a skill for this CWE. Never rewrite the dataset's."""
    if cwe_id in covered:
        return {"status": "covered", "cwe": cwe_id,
                "reason": f"skills/cwe-{cwe_id.removeprefix('CWE-')}-* covers this class"}
    if (near := ADJACENT_CWES.get(cwe_id)) and near in covered:
        return {"status": "adjacent", "cwe": near,
                "reason": f"{cwe_id} has no skill of its own; {near} is its direct child and its "
                          "skill reads correctly for this class"}
    return {"status": "uncovered", "cwe": None,
            "reason": f"no skills/cwe-* covers {cwe_id or 'an unclassified entry'}; the trajectory "
                      "scorer will find no matching skill, so score these separately"}


def build_pair(entry: Entry, fix_sha: str, parent_sha: str, pov: Pov, sink: tuple,
               coverage: dict, test_framework: str | None = None) -> list[dict]:
    """Two cases from one entry: the parent commit is vulnerable, the fix commit is fixed."""
    sink_file, sink_line, target = sink
    base = f"vul4j-{entry.vul_id.removeprefix('VUL4J-').lower()}"
    label = entry.cwe_name or entry.cwe_id or "unclassified weakness"
    source = {
        **ATTRIBUTION,
        "entry_id": entry.vul_id,
        "cve": entry.cve_id or None,
        "cwe_reported": entry.cwe_id or None,
        "repo_slug_reported": entry.repo_slug,
        "repo_slug_resolved": entry.fix_slug,
        "fix_commit": fix_sha,
        "vulnerable_commit": parent_sha,
        "human_patch_url": entry.human_patch,
    }
    # Facts about the toolchain, not a recipe. Vul4J's compile_cmd/test_cmd/cmd_options are
    # deliberately dropped: deriving them is what env-planner and build-repair are for.
    # `test_framework` is as load-bearing as `jdk` and was missing: the Maven recipe's warm-up
    # is compiled against the project's own test classpath, so a JUnit 5 warm-up in a JUnit 4
    # project fails `test-compile` and no image is ever built. 50 of the 51 Maven entries here are
    # JUnit 4, so a consumer that assumes JUnit 5 fails essentially the whole harvest.
    build = {"system": entry.build_system.lower() or "unknown", "jdk": entry.jdk or None,
             "module": entry.module or "root", "test_framework": test_framework,
             "note": "Vul4J's pinned build and test commands are intentionally not carried over."}

    cases = []
    for variant, revision, verdict, reach in (
        ("vulnerable", parent_sha, "potentially_exploitable", "reachable"),
        ("fixed", fix_sha, "likely_not_exploitable", "neutralized"),
    ):
        # On the fixed side the PoV is in the tree whenever it exists in the project at all:
        # either the fix commit added it, or it predated the fix. The one exception is a PoV
        # Vul4J wrote themselves, which is in neither revision.
        if variant == "vulnerable":
            pov_present = pov.present_at_vulnerable
        elif pov.origin == "unknown":
            pov_present = None
        else:
            pov_present = pov.origin != "not-in-repository"
        cases.append({
            "name": f"{base}-{variant}",
            "language": "java",
            "finding": {
                "external_id": entry.vul_id,
                "title": f"{label} in {entry.repo_slug}"
                         + (f" ({entry.cve_id})" if entry.cve_id else ""),
                "description": (
                    f"{entry.cve_id or entry.vul_id}: {label} reported against {entry.repo_slug}. "
                    f"The upstream fix is {fix_sha[:10]}; this case is the "
                    f"{'parent commit, before the fix' if variant == 'vulnerable' else 'fix commit'}."
                ),
                "repo_url": entry.repo_url,
                "revision": revision,
                "file_path": sink_file,
                "start_line": sink_line,
                "cwe": entry.cwe_id or None,
                "severity": "unknown",
                "source_tool": "vul4j-harvester",
            },
            "truth": {
                "expected_verdict": verdict,
                "reachability": reach,
                "sink_file": sink_file,
                "sink_line": sink_line,
                "source": "untrusted input as described by the CVE",
                "target_callable": target,
                "sink_confidence": "fix-hunk-heuristic",
                "pov": {
                    "test_class": pov.test_class,
                    "test_method": pov.test_method,
                    "path": pov.path,
                    "additional_tests": list(pov.additional_tests),
                    "origin": pov.origin,
                    "evidence": pov.evidence,
                    "present_at_revision": pov_present,
                    "mask_paths": pov.mask_paths,
                },
            },
            "cwe_coverage": coverage,
            "build": build,
            "source": source,
        })
    return cases



def detect_test_framework(entry: Entry, resolver: Resolver, revision: str) -> str | None:
    """Which JVM test framework the entry's build files declare, at the vulnerable revision.

    Read rather than assumed, and read from the module pom as well as the root: the module is
    where a multi-module project declares its own test dependencies. Returns None when nothing
    can be read, which is honest -- the framework then comes from whatever the consumer detects
    in the checkout, not from a guess recorded as a fact.
    """
    names = ("pom.xml",) if entry.build_system.lower() == "maven" else ("build.gradle",
                                                                       "build.gradle.kts")
    module = (entry.module or "").strip("/")
    parts = [] if module in ("", "root") else module.split("/")
    # Innermost first, then each enclosing directory, then the root: a multi-module project often
    # declares the shared test dependency at an intermediate level (onos does it in
    # `protocols/pom.xml`), and reading only the module and the root misses it.
    paths = [f"{'/'.join(parts[:depth])}/{name}"
             for depth in range(len(parts), 0, -1) for name in names]
    paths += list(names)
    for path in paths:
        try:
            text = resolver.file_at(entry.fix_slug, revision, path)
        except LookupError:
            continue
        if text and (framework := jvm_test_framework(text)):
            return framework
    return None


# --------------------------------------------------------------------------------------
# Harvest


@dataclass
class Harvest:
    cases: list[dict] = field(default_factory=list)
    quarantined: list[dict] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)

    def skip(self, entry: Entry, reason: str) -> None:
        self.skipped.append({"entry_id": entry.vul_id, "cve": entry.cve_id or None, "reason": reason})


def harvest(entries: list[Entry], resolver: Resolver, covered: tuple[str, ...]) -> Harvest:
    """Map dataset rows to cases, recording every rejection and why."""
    out = Harvest()
    for entry in entries:
        if entry.vul_id.endswith(STATIC_WARNING_SUFFIX):
            out.skip(entry, "static-analysis-warning subset: no CVE, no CWE, no proof-of-vulnerability test")
            continue
        if not entry.failing_tests:
            out.skip(entry, "no failing test recorded, so there is no proof of vulnerability to score against")
            continue
        if entry.patch is None:
            out.skip(entry, "fix commit is not a resolvable GitHub commit URL")
            continue
        if entry.patch[1] == "compare":
            out.skip(entry, "the dataset records a commit range rather than a single fix commit, "
                            "so there is no one revision to call `fixed`")
            continue
        if entry.fix_slug.split("/", 1)[0] in VUL4J_MIRROR_OWNERS:
            out.skip(entry, f"the fix commit exists only in the Vul4J-owned mirror {entry.fix_slug}, "
                            f"not in {entry.repo_slug}; cloning upstream would not resolve the SHA")
            continue
        try:
            commit = resolver.commit(entry.fix_slug, entry.fix_sha)
        except LookupError as exc:
            out.skip(entry, f"fix commit unreachable upstream ({exc}); the repository or commit is gone")
            continue
        parents = commit.get("parents") or []
        if len(parents) != 1:
            out.skip(entry, f"fix commit has {len(parents)} parents; the vulnerable revision is ambiguous")
            continue
        parent_sha = parents[0]["sha"]

        pov = analyse_pov(entry, commit, resolver, parent_sha)
        coverage = classify_cwe(entry.cwe_id, covered)
        sink = derive_sink(entry, commit)
        if sink[0] is None:
            out.skip(entry, "fix commit changes no non-test Java file, so no sink location can be derived")
            continue

        framework = detect_test_framework(entry, resolver, parent_sha)
        pair = build_pair(entry, commit["sha"], parent_sha, pov, sink, coverage,
                          framework)
        # `None` means we could not establish presence. An entry we cannot clear is treated
        # exactly like one we have caught leaking.
        if pov.present_at_vulnerable is not False:
            reason = (
                "the proof-of-vulnerability test is already present at the vulnerable revision "
                f"({pov.path}); an agent reading this checkout can read the exact triggering input, "
                "which would turn the probe-author measurement into transcription"
                if pov.present_at_vulnerable
                else "we could not establish whether the proof-of-vulnerability test is present at "
                     f"the vulnerable revision ({pov.evidence}); unverified is not the same as safe"
            )
            out.quarantined.extend({**c, "quarantine_reason": reason} for c in pair)
            continue
        out.cases.extend(pair)
    return out


NOTE = (
    "Harvested from the Vul4J dataset (CC-BY-4.0) by scripts/harvest_vul4j.py. Paired like the "
    "seeded corpus: `-vulnerable` is the fix commit's parent and should come out "
    "potentially_exploitable, `-fixed` is the fix commit and should come out "
    "likely_not_exploitable. `finding.repo_url` is a remote git URL and `finding.revision` is a "
    "commit SHA. "
    "LEAKAGE RULE: `truth.pov` names the upstream proof-of-vulnerability test. It is ground truth "
    "for scoring and MUST NOT be exposed to any agent. On every `-fixed` case the PoV is present "
    "in the checkout by construction, because the fix commit added it, so consumers must remove "
    "`truth.pov.mask_paths` from the tree the agent reads before the probe-author stage runs. "
    "Cases whose PoV already existed at the vulnerable revision are not in `cases` at all; they "
    "are listed under `quarantined` with the reason. "
    "`truth.sink_file`/`sink_line` are a heuristic taken from the fix commit's largest non-test "
    "hunk, not an analysed sink; `truth.sink_confidence` says so. "
    "`build.test_framework` is read from the module's build file and each pom enclosing it, "
    "innermost first; `null` means none of them declares one (a parent pom outside the "
    "repository does), so a consumer must detect it in the checkout rather than assume. It is "
    "recorded because it decides the *build*, not just the probe: the Maven warm-up is "
    "compiled against the project's own test classpath, so a JUnit 5 warm-up in a JUnit 4 "
    "project fails test-compile and no image is built at all. "
    "Vul4J's pinned Docker images and build/test commands are deliberately not carried over: "
    "deriving the build is what env-planner and build-repair exist to measure."
)


def render(result: Harvest) -> dict:
    return {
        "version": "1",
        "note": NOTE,
        "source_dataset": ATTRIBUTION,
        "generated_by": "scripts/harvest_vul4j.py",
        "cases": result.cases,
        "quarantined": result.quarantined,
        "skipped": result.skipped,
    }


def summarise(result: Harvest, out: io.TextIOBase) -> None:
    entries = len({c["source"]["entry_id"] for c in result.cases})
    quarantined = len({c["source"]["entry_id"] for c in result.quarantined})
    print(f"harvested {entries} entries -> {len(result.cases)} cases", file=out)
    print(f"quarantined {quarantined} entries ({len(result.quarantined)} cases) for PoV leakage", file=out)
    print(f"skipped {len(result.skipped)} entries", file=out)
    for reason, n in Counter(s["reason"] for s in result.skipped).most_common():
        print(f"  {n:>4}  {reason}", file=out)
    print("cwe coverage (harvested entries):", file=out)
    per_entry = {c["source"]["entry_id"]: c for c in result.cases}
    for key, n in Counter(
        f"{c['finding']['cwe']} [{c['cwe_coverage']['status']}]" for c in per_entry.values()
    ).most_common():
        print(f"  {n:>4}  {key}", file=out)
    print("jdk levels required:", file=out)
    for jdk, n in Counter(c["build"]["jdk"] for c in per_entry.values()).most_common():
        print(f"  {n:>4}  JDK {jdk}", file=out)
    print("pov origin:", file=out)
    for origin, n in Counter(c["truth"]["pov"]["origin"] for c in per_entry.values()).most_common():
        print(f"  {n:>4}  {origin}", file=out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", help="local Vul4J dataset CSV; defaults to fetching it")
    ap.add_argument("--out", default=str(REPO / "eval-corpus" / "external" / "vul4j.json"))
    # Outside the repository on purpose: the cache is a convenience for re-runs, not an
    # artifact, and `.gitignore` should not have to grow an entry for it.
    ap.add_argument("--cache-dir", default=str(Path(tempfile.gettempdir()) / "infosec-harness-vul4j-api"))
    ap.add_argument("--token", help="GitHub token; else GITHUB_TOKEN, GH_TOKEN, or `gh auth token`")
    ap.add_argument("--limit", type=int, help="process only the first N entries (for a smoke run)")
    ap.add_argument("--dry-run", action="store_true", help="report only; write nothing")
    args = ap.parse_args(argv)

    if args.dataset:
        text = Path(args.dataset).read_text()
    else:
        with urllib.request.urlopen(DATASET_URL, timeout=60) as resp:  # noqa: S310 - fixed https host
            text = resp.read().decode()

    entries = parse_dataset(text)
    if args.limit:
        entries = entries[: args.limit]

    resolver = GitHubResolver(_discover_token(args.token), Path(args.cache_dir))
    result = harvest(entries, resolver, skill_covered_cwes())
    summarise(result, sys.stdout)
    print(f"github api calls: {resolver.calls}", file=sys.stdout)

    if args.dry_run:
        return 0
    dest = Path(args.out)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(render(result), indent=2, sort_keys=False) + "\n")
    print(f"wrote {dest}", file=sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
