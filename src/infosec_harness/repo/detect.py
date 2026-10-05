"""Deterministic stack fingerprinting (P1): language counts, manifests, and declared registries.

No model involved. Declared registries are recorded as repository requests only; build egress
is confined by the operator's proxy allowlist, which no repository declaration can widen (D14).
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from infosec_harness.domain.models import ComponentProfile, StackFingerprint, SupportStatus
from infosec_harness.repo.access import walk_files

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
SKIP = {".git", "node_modules", ".venv", "venv", "__pycache__", "target", "build", "dist", ".idea", ".tox"}
_JAVA_BUILD_FILES = ("pom.xml", "build.gradle", "build.gradle.kts")


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


def js_test_runners(root: Path) -> list[str]:
    """Node test runners the repo declares, the one its own `test` script invokes first.

    `node --test` and `tsx --test` are found only here and in the test files themselves: they
    are not packages, so no manifest mentions them and a project using them otherwise reports
    no test framework at all.
    """
    manifest = _read(root / "package.json")
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
        for pattern in ("test/*.js", "test/*.mjs", "test/*.ts", "__tests__/*.js"):
            if any("node:test" in _read(p) for p in sorted(root.glob(pattern))[:20]):
                invoked = ["node:test"]
                break
    ordered = invoked + [name for name in declared if name not in invoked]
    return list(dict.fromkeys(ordered))


def _perl_test_frameworks(root: Path) -> list[str]:
    """Which Test:: dialect the repo's own `.t` files use, Test::More when nothing says.

    Test::More is the fallback rather than a detection, because it is the ecosystem default and
    a repository with an empty `t/` still needs *some* template named for the probe author.
    """
    text = "".join(_read(root / name) for name in ("cpanfile", "Makefile.PL", "Build.PL",
                                                   "META.json", "META.yml"))
    text += "".join(_read(p) for p in sorted(root.glob("t/**/*.t"))[:40])
    found = [name for token, name in _PERL_FRAMEWORK_TOKENS if token in text]
    return list(dict.fromkeys(found)) or ["Test::More"]


def _detect_test_frameworks(root: Path, langs: dict[str, int]) -> list[str]:
    fw: list[str] = []
    text = ""
    jvm_text = ""
    for name in ("pyproject.toml", "package.json", "pom.xml", "build.gradle", "requirements.txt", "cpanfile"):
        p = root / name
        if p.exists():
            body = p.read_text(errors="ignore")
            text += body.lower()
            if name in ("pom.xml", "build.gradle"):
                jvm_text += body
    if "pytest" in text or (root / "tests").is_dir() and langs.get("python"):
        fw.append("pytest")
    # Read the declared JVM framework rather than substring-matching "junit": `junit:junit:4.12`
    # was being reported as junit5, and 50 of the 51 Maven entries harvested from Vul4J are
    # JUnit 4 (or JUnit 3 on the JUnit 4 artifact). The jupiter probe shape does not even compile
    # against the JUnit 4 artifact, so that wrong answer cost the whole real-world Java corpus.
    jvm = jvm_test_framework(jvm_text)
    if jvm:
        fw.append(jvm)
    elif langs.get("java") and (root / "src/test/java").is_dir():
        # A Java repo with a test tree and nothing declared at the root: a module pom or a
        # parent declares it. Say `junit4`, the overwhelming majority.
        fw.append("junit4")
    fw += js_test_runners(root)
    if langs.get("perl") or list(root.glob("t/*.t")):
        fw += _perl_test_frameworks(root)
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


_REGISTRY_RE = re.compile(r"https?://[\w.-]+(?::\d+)?", re.I)


def _detect_registries(root: Path) -> list[str]:
    hosts: set[str] = set()
    for rel in (".npmrc", "pip.conf", "pip/pip.conf", ".pip/pip.conf", "settings.xml", ".mvn/settings.xml"):
        p = root / rel
        if p.exists():
            for m in _REGISTRY_RE.findall(p.read_text(errors="ignore")):
                hosts.add(m.split("//", 1)[1].split("/")[0])
    for name in ("pom.xml", "build.gradle", "build.gradle.kts", ".yarnrc.yml"):
        p = root / name
        if p.exists():
            for m in _REGISTRY_RE.findall(p.read_text(errors="ignore")):
                hosts.add(m.split("//", 1)[1].split("/")[0])
    return sorted(hosts)


def detect_stack(root: str, *, _include_components: bool = True) -> StackFingerprint:
    base = Path(root)
    # Detection, repository tools, citation validation, and snapshot hashing share one link and
    # special-file policy. Validate before any manifest reader can follow a hostile symlink.
    tuple(walk_files(base, skip_dirs=SKIP))
    langs: dict[str, int] = {}
    manifests: set[str] = set()
    manifest_paths: set[str] = set()
    test_dirs: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in SKIP]
        rel_dir = os.path.relpath(dirpath, base)
        if os.path.basename(dirpath) in ("test", "tests", "t", "spec", "__tests__"):
            test_dirs.add(rel_dir)
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext in EXT_LANG:
                langs[EXT_LANG[ext]] = langs.get(EXT_LANG[ext], 0) + 1
            if name in MANIFESTS:
                manifests.add(name)
                manifest_paths.add((Path(dirpath) / name).relative_to(base).as_posix())
    build_systems = sorted({BUILD_SYSTEM[m] for m in manifests if m in BUILD_SYSTEM})
    stack = StackFingerprint(
        languages=dict(sorted(langs.items(), key=lambda kv: (-kv[1], kv[0]))),
        manifests=sorted(manifests),
        build_systems=build_systems,
        test_frameworks=_detect_test_frameworks(base, langs),
        registries=_detect_registries(base),
        test_dirs=sorted(test_dirs),
        java_release=_declared_release(base),
    )
    if _include_components:
        stack = stack.model_copy(update={"components": _component_profiles(base, manifest_paths)})
    return stack


def _component_profiles(root: Path, manifest_paths: set[str]) -> list[ComponentProfile]:
    roots = sorted({Path(path).parent.as_posix() for path in manifest_paths}) or ["."]
    profiles: list[ComponentProfile] = []
    supported_languages = {"python", "java", "javascript", "typescript", "perl"}
    for relative in roots[:256]:
        component_root = root if relative == "." else root / relative
        component = detect_stack(str(component_root), _include_components=False)
        manifests = sorted(
            Path(path).relative_to(Path(relative)).as_posix()
            for path in manifest_paths
            if relative == "." or Path(path).is_relative_to(Path(relative))
        )
        languages = set(component.languages)
        if not languages:
            support = SupportStatus.not_checked
        elif languages <= supported_languages:
            # Compatibility is not claimed from filename detection alone. Adapters and fixtures
            # can promote a concrete slice to `tested`; discovery starts conservatively.
            support = SupportStatus.experimental
        else:
            support = SupportStatus.unsupported
        profiles.append(ComponentProfile(
            root=relative,
            languages=component.languages,
            manifest_paths=manifests,
            build_systems=component.build_systems,
            test_frameworks=component.test_frameworks,
            java_release=component.java_release,
            support=support,
        ))
    return profiles


def _declared_release(root: Path) -> int | None:
    """The oldest Java level the root build file asks for. Binds the JDK, so it is fingerprinted.

    Without it two Java repositories that differ only in language level share a recipe cache key,
    and the cached spec's base image is then wrong for one of them -- a JDK too new fails with
    "Source option 7 is no longer supported", a JDK too old with "invalid target release".
    """
    levels = [declared_java_release((root / name).read_text(errors="ignore"))
              for name in _JAVA_BUILD_FILES if (root / name).exists()]
    found = [level for level in levels if level is not None]
    return min(found) if found else None
