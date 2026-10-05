"""Deterministic stack fingerprinting (P1): language counts, manifests, frameworks, components.

No model involved. One validated walk of the snapshot (``access.walk_files``) is indexed by
directory, and every answer -- the repository fingerprint and each component's -- is read from
that index. Only regular files the walk admitted are ever read, so a directory, special file or
escaping link named like a manifest is absent rather than a crash or a read outside the tree.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
from bisect import bisect_left
from collections import defaultdict
from collections.abc import Iterable, Iterator
from pathlib import Path, PurePosixPath

from infosec_harness.domain.models import ComponentProfile, StackFingerprint, SupportStatus
from infosec_harness.repo.access import NON_SOURCE_DIRS, walk_files

EXT_LANG = {
    ".py": "python", ".java": "java", ".kt": "java", ".scala": "java",
    # `.mjs`/`.cjs` are not decoration: a package that went all-ESM renames every file, and
    # without them a pure-ESM Node repo counted ZERO javascript files, so _primary_language
    # answered "unknown" and the env plan fell through to `sh {test_file}` with no install at
    # all. Measured on a fixture whose only source was src/render.mjs.
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".pl": "perl", ".pm": "perl", ".t": "perl", ".go": "go", ".rb": "ruby",
    ".php": "php", ".cs": "csharp", ".rs": "rust", ".c": "c", ".cc": "cpp", ".cpp": "cpp",
}
MANIFESTS = {
    "requirements.txt", "pyproject.toml", "setup.py", "Pipfile", "poetry.lock", "uv.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "cpanfile", "Makefile.PL", "Build.PL", "go.mod", "Gemfile", "composer.json", "Cargo.toml",
}
BUILD_SYSTEM = {
    "pom.xml": "maven", "build.gradle": "gradle", "build.gradle.kts": "gradle",
    "package.json": "npm", "pnpm-lock.yaml": "pnpm", "yarn.lock": "yarn",
    "pyproject.toml": "python", "requirements.txt": "pip", "setup.py": "pip",
    # Build.PL is Module::Build's declaration and cpanm reads it for --installdeps exactly as
    # it reads a Makefile.PL, so omitting it left a Module::Build distribution reporting no
    # build system at all while the plan still ran cpanm against it.
    "cpanfile": "cpanm", "Makefile.PL": "cpanm", "Build.PL": "cpanm",
}
_JAVA_BUILD_FILES = ("pom.xml", "build.gradle", "build.gradle.kts")
_TEST_DIR_NAMES = frozenset({"test", "tests", "t", "spec", "__tests__"})
_SUPPORTED_LANGUAGES = frozenset({"python", "java", "javascript", "typescript", "perl"})
MAX_COMPONENTS = 256


# The JVM branch used to answer `junit5` for every repository that so much as said "junit",
# which is wrong for most Java code in the wild and measurably wrong for the harvested Vul4J
# corpus: of its 51 Maven entries, 50 are JUnit 4 (or JUnit 3 on the JUnit 4 artifact) and one
# is JUnit 5. Reporting `junit5` there routes the probe author to the wrong skill and produces a
# probe that does not compile, so the framework is now read rather than assumed.
#
# Precedence is the provider Surefire actually selects, measured under Surefire 3.2.5: with
# junit-jupiter on the test classpath it uses the JUnit Platform provider, and a JUnit-4
# annotated test then runs *zero* tests and still exits 0 -- so jupiter wins. With junit and
# testng together it uses the TestNG provider, which runs a JUnit 4 test anyway, so junit4 is
# the safe answer for that pair.
_JVM_FRAMEWORK_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("junit5", ("junit-jupiter", "org.junit.jupiter", "junit-platform", "junit5",
                "useJUnitPlatform")),
    ("junit4", ("<artifactid>junit</artifactid>", "junit-vintage", "junit:junit",
                "'junit'", '"junit"')),
    ("testng", ("org.testng", "<artifactid>testng</artifactid>", "testng:testng",
                "usetestng")),
)


def jvm_test_framework(build_text: str) -> str | None:
    """Which JVM test framework a build file declares: junit5, junit4, testng, or None."""
    lowered = build_text.lower()
    for name, markers in _JVM_FRAMEWORK_MARKERS:
        if any(marker in lowered for marker in markers):
            return name
    return None

# The runner the harness must invoke is the one the project's own `test` script invokes, not the
# alphabetically first name that appears in devDependencies: recon reports `test_frameworks[0]`
# and the env plan builds its command from it. A repo migrating from jest to vitest carries both,
# and the wrong pairing costs the whole run (`--runTestsByPath` is not a vitest option and it
# exits before a single test runs). Ordered longest-first so "vitest" is not matched as "test".
# `ava` and `tap` are deliberately absent: as bare substrings they match "available", "java" and
# "tapable", and a runner named by accident is worse than one not named at all.
_JS_RUNNER_TOKENS = (("vitest", "vitest"), ("jest", "jest"), ("mocha", "mocha"),
                     ("node --test", "node:test"), ("tsx --test", "node:test"),
                     ("jasmine", "jasmine"))
# Perl's default is Test::More, but a Test2::V0 script declares its plan as `plan N;` with no
# `tests =>` anywhere, and a bare prove-run script declares it by printing `1..N`. Naming the
# wrong one sends the probe author to a template whose plan form the validator then rejects.
_PERL_FRAMEWORK_TOKENS = (("Test2::V0", "Test2::V0"), ("Test2::Bundle", "Test2::V0"),
                          ("Test2::Tools", "Test2::V0"), ("Test::More", "Test::More"),
                          ("Test::Simple", "Test::More"))


def _read(path: Path) -> str:
    try:
        return path.read_text(errors="ignore") if path.is_file() else ""
    except OSError:
        return ""


class _Index:
    """The admitted files of one walk, grouped by their directory (``"."`` is the root)."""

    def __init__(self, base: Path, files: Iterable[str]):
        self.base = base
        self.names: dict[str, set[str]] = defaultdict(set)
        for rel in files:
            parent, _, name = rel.rpartition("/")
            self.names[parent or "."].add(name)
        self._dirs = sorted(self.names)

    def subtree(self, directory: str) -> Iterator[str]:
        """Directories at or beneath ``directory`` that directly contain admitted files."""
        if directory == ".":
            yield from self._dirs
            return
        if directory in self.names:
            yield directory
        prefix = directory + "/"
        for candidate in self._dirs[bisect_left(self._dirs, prefix):]:
            if not candidate.startswith(prefix):
                break
            yield candidate

    def has(self, rel: str) -> bool:
        parent, _, name = rel.rpartition("/")
        return name in self.names.get(parent or ".", ())

    def read(self, rel: str) -> str:
        return _read(self.base / rel) if self.has(rel) else ""


def _join(directory: str, rel: str) -> str:
    return rel if directory == "." else f"{directory}/{rel}"


def _relative(directory: str, path: str) -> str:
    if directory == ".":
        return path
    return "." if path == directory else path[len(directory) + 1:]


def _test_files(index: _Index, root: str, directory: str, suffix: str, *,
                recursive: bool, limit: int) -> list[str]:
    """``directory/*<suffix>`` (or ``directory/**/*<suffix>``) under a component root."""
    top = _join(root, directory)
    dirs = index.subtree(top) if recursive else ([top] if top in index.names else [])
    found = [f"{d}/{name}" for d in dirs for name in index.names[d] if name.endswith(suffix)]
    return sorted(found, key=lambda rel: PurePosixPath(rel).parts)[:limit]


_NODE_TEST_FILES = (("test", ".js"), ("test", ".mjs"), ("test", ".ts"), ("__tests__", ".js"))


def js_test_runners(root: Path, index: _Index | None = None, component: str = ".") -> list[str]:
    """Node test runners the repo declares, the one its own `test` script invokes first.

    `node --test` and `tsx --test` are found only here and in the test files themselves: they
    are not packages, so no manifest mentions them and a project using them otherwise reports
    no test framework at all.
    """
    if index is None:
        # A caller outside detection: index only the handful of files this reads.
        candidates = ["package.json", *(p.relative_to(root).as_posix()
                                        for directory, suffix in _NODE_TEST_FILES
                                        for p in root.glob(f"{directory}/*{suffix}"))]
        index = _Index(root, [rel for rel in candidates if (root / rel).is_file()])
    manifest = index.read(_join(component, "package.json"))
    if not manifest:
        return []
    declared = [name for token, name in _JS_RUNNER_TOKENS if token in manifest.lower()]
    try:
        scripts = json.loads(manifest).get("scripts") or {}
    except (ValueError, AttributeError):
        scripts = {}
    script = str(scripts.get("test") or "").lower()
    invoked = [name for token, name in _JS_RUNNER_TOKENS if token in script]
    if not declared and not invoked:
        for directory, suffix in _NODE_TEST_FILES:
            files = _test_files(index, component, directory, suffix, recursive=False, limit=20)
            if any("node:test" in index.read(rel) for rel in files):
                invoked = ["node:test"]
                break
    ordered = invoked + [name for name in declared if name not in invoked]
    return list(dict.fromkeys(ordered))


def _perl_test_frameworks(index: _Index, root: str) -> list[str]:
    """Which Test:: dialect the repo's own `.t` files use, Test::More when nothing says.

    Test::More is the fallback rather than a detection, because it is the ecosystem default and
    a repository with an empty `t/` still needs *some* template named for the probe author.
    """
    text = "".join(index.read(_join(root, name))
                   for name in ("cpanfile", "Makefile.PL", "Build.PL", "META.json", "META.yml"))
    text += "".join(index.read(rel) for rel in
                    _test_files(index, root, "t", ".t", recursive=True, limit=40))
    found = [name for token, name in _PERL_FRAMEWORK_TOKENS if token in text]
    return list(dict.fromkeys(found)) or ["Test::More"]


def _has_files_under(index: _Index, directory: str) -> bool:
    return next(index.subtree(directory), None) is not None


def _detect_test_frameworks(index: _Index, root: str, langs: dict[str, int]) -> list[str]:
    fw: list[str] = []
    text = ""
    jvm_text = ""
    for name in ("pyproject.toml", "package.json", "pom.xml", "build.gradle", "requirements.txt",
                 "cpanfile"):
        body = index.read(_join(root, name))
        text += body.lower()
        if name in ("pom.xml", "build.gradle"):
            jvm_text += body
    if "pytest" in text or _has_files_under(index, _join(root, "tests")) and langs.get("python"):
        fw.append("pytest")
    # Read the declared JVM framework rather than substring-matching "junit": `junit:junit:4.12`
    # was being reported as junit5, and 50 of the 51 Maven entries harvested from Vul4J are
    # JUnit 4 (or JUnit 3 on the JUnit 4 artifact). The jupiter probe shape does not even compile
    # against the JUnit 4 artifact, so that wrong answer cost the whole real-world Java corpus.
    jvm = jvm_test_framework(jvm_text)
    if jvm:
        fw.append(jvm)
    elif langs.get("java") and _has_files_under(index, _join(root, "src/test/java")):
        # A Java repo with a test tree and nothing declared at the root: a module pom or a
        # parent declares it. Say `junit4`, the overwhelming majority.
        fw.append("junit4")
    fw += js_test_runners(index.base, index, root)
    if langs.get("perl") or _test_files(index, root, "t", ".t", recursive=False, limit=1):
        fw += _perl_test_frameworks(index, root)
    return list(dict.fromkeys(fw))

# `maven:3.9-...` and `gradle:8-...` lead with the BUILD TOOL's version, so the declared language
# level has to be read from the build file's own tags rather than guessed from an image name.
_JAVA_RELEASE_TAGS = (
    re.compile(r"<maven\.compiler\.release>\s*(\d+)\s*</maven\.compiler\.release>"),
    re.compile(r"<maven\.compiler\.source>\s*(?:1\.)?(\d+)\s*</maven\.compiler\.source>"),
    re.compile(r"<maven\.compiler\.target>\s*(?:1\.)?(\d+)\s*</maven\.compiler\.target>"),
    re.compile(r"<java\.version>\s*(?:1\.)?(\d+)\s*</java\.version>"),
    re.compile(r"<source>\s*(?:1\.)?(\d+)\s*</source>"),
    re.compile(r"<target>\s*(?:1\.)?(\d+)\s*</target>"),
)
_GRADLE_RELEASE_TAGS = (
    re.compile(r"sourceCompatibility\s*=?\s*['\"]?(?:1\.)?(\d+)"),
    re.compile(r"targetCompatibility\s*=?\s*['\"]?(?:1\.)?(\d+)"),
    re.compile(r"languageVersion\s*=\s*JavaLanguageVersion\.of\((\d+)\)"),
)


def declared_java_release(build_file_text: str) -> int | None:
    """The oldest language level a build file asks for, or None if it says nothing.

    The *oldest* rather than the newest: a pom setting source 7 and target 8 has to be compiled
    by a JDK that still accepts 7, so the lower number is the binding constraint.
    """
    found = [int(m.group(1))
             for pattern in _JAVA_RELEASE_TAGS + _GRADLE_RELEASE_TAGS
             for m in pattern.finditer(build_file_text)]
    return min(found) if found else None


def java_release(build_texts: Iterable[str]) -> int | None:
    """The oldest Java language level any of these build files declares, or None.

    The oldest binds: a JDK must still accept every level the build compiles at. This is the
    one rule for both the stack fingerprint and the JDK check, applied to the same candidate
    build files (:func:`java_build_texts`), so the two cannot disagree on a multi-module
    repository.
    """
    declared = [level for text in build_texts
                if (level := declared_java_release(text)) is not None]
    return min(declared) if declared else None


# How many child directories (sorted, non-source directories excluded) are read for module
# build files. A bound, so a repository with thousands of top-level directories costs the same.
_JAVA_MODULE_DIRS = 40


def java_build_texts(root: str | Path) -> list[str]:
    """The build files whose language level binds the JDK: ``root`` and its first child dirs.

    Unreadable files and directories are skipped; an unreadable repository yields nothing,
    and the JDK check then stays silent rather than guessing.
    """
    base = Path(root)
    candidates = [base / name for name in _JAVA_BUILD_FILES]
    with contextlib.suppress(OSError):
        children = [child for child in sorted(base.iterdir())
                    if child.name not in NON_SOURCE_DIRS and child.is_dir()]
        candidates += [child / name for child in children[:_JAVA_MODULE_DIRS]
                       for name in _JAVA_BUILD_FILES]
    texts = []
    for path in candidates:
        with contextlib.suppress(OSError):
            if path.is_file():
                texts.append(path.read_text(errors="replace"))
    return texts


def _declared_release(index: _Index, root: str) -> int | None:
    """The oldest Java level the build files at ``root`` ask for. Binds the JDK, so it is
    fingerprinted.

    Without it two Java repositories that differ only in language level share a recipe cache key,
    and the cached spec's base image is then wrong for one of them -- a JDK too new fails with
    "Source option 7 is no longer supported", a JDK too old with "invalid target release". The
    candidates are :func:`java_build_texts`'s, read through the walk's index.
    """
    children = sorted({_relative(root, directory).split("/", 1)[0]
                       for directory in index.subtree(root) if directory != root} - {"."})
    directories = [root, *(_join(root, child) for child in children[:_JAVA_MODULE_DIRS])]
    return java_release(index.read(_join(directory, name)) for directory in directories
                        for name in _JAVA_BUILD_FILES)


def _fingerprint(index: _Index, root: str) -> StackFingerprint:
    """The fingerprint of the subtree at ``root``; paths in it are relative to ``root``."""
    langs: dict[str, int] = {}
    manifests: set[str] = set()
    test_dirs: set[str] = set()
    for directory in index.subtree(root):
        relative = _relative(root, directory)
        parts = PurePosixPath(relative).parts if relative != "." else ()
        test_dirs.update("/".join(parts[:i + 1]) for i, part in enumerate(parts)
                         if part in _TEST_DIR_NAMES)
        for name in index.names[directory]:
            language = EXT_LANG.get(os.path.splitext(name)[1].lower())
            if language:
                langs[language] = langs.get(language, 0) + 1
            if name in MANIFESTS:
                manifests.add(name)
    return StackFingerprint(
        languages=dict(sorted(langs.items(), key=lambda kv: (-kv[1], kv[0]))),
        manifests=sorted(manifests),
        build_systems=sorted({BUILD_SYSTEM[m] for m in manifests if m in BUILD_SYSTEM}),
        test_frameworks=_detect_test_frameworks(index, root, langs),
        test_dirs=sorted(test_dirs),
        java_release=_declared_release(index, root),
    )


def detect_stack(root: str) -> StackFingerprint:
    """Fingerprint a snapshot and each manifest-rooted component in it, from one walk.

    Detection, repository tools, citation validation, and snapshot hashing share one link and
    special-file policy: the walk validates the tree before any manifest is read.
    """
    base = Path(root)
    index = _Index(base, (rel for rel, _ in walk_files(base, skip_dirs=NON_SOURCE_DIRS)))
    stack = _fingerprint(index, ".")
    return stack.model_copy(update={"components": _component_profiles(index)})


def _component_profiles(index: _Index) -> list[ComponentProfile]:
    """One profile per directory holding a manifest (the root when none does), at most 256.

    A component's languages, manifests and build systems cover its whole subtree, nested
    components included; its frameworks and Java level come from its own root's files.
    """
    manifest_paths = sorted(_join(directory, name) for directory, names in index.names.items()
                            for name in names if name in MANIFESTS)
    roots = sorted({PurePosixPath(path).parent.as_posix() for path in manifest_paths}) or ["."]
    profiles: list[ComponentProfile] = []
    for root in roots[:MAX_COMPONENTS]:
        component = _fingerprint(index, root)
        prefix = "" if root == "." else root + "/"
        languages = set(component.languages)
        if not languages:
            support = SupportStatus.not_checked
        elif languages <= _SUPPORTED_LANGUAGES:
            # Compatibility is not claimed from filename detection alone. Adapters and fixtures
            # can promote a concrete slice to `tested`; discovery starts conservatively.
            support = SupportStatus.experimental
        else:
            support = SupportStatus.unsupported
        profiles.append(ComponentProfile(
            root=root,
            languages=component.languages,
            manifest_paths=[path.removeprefix(prefix) for path in manifest_paths
                            if path.startswith(prefix)],
            build_systems=component.build_systems,
            test_frameworks=component.test_frameworks,
            java_release=component.java_release,
            support=support,
        ))
    return profiles

