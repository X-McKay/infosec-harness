"""Deterministic stack fingerprinting (P1): language counts, manifests, and declared registries.

No model involved. The declared registries become the build-stage egress allowlist (D14).
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from infosec_harness.domain.models import StackFingerprint

EXT_LANG = {
    ".py": "python", ".java": "java", ".kt": "java", ".scala": "java",
    ".js": "javascript", ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript",
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
    "cpanfile": "cpanm", "Makefile.PL": "cpanm",
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


def _detect_test_frameworks(root: Path, langs: dict[str, int]) -> list[str]:
    fw: set[str] = set()
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
        fw.add("pytest")
    jvm = jvm_test_framework(jvm_text)
    if jvm:
        fw.add(jvm)
    elif langs.get("java") and (root / "src/test/java").is_dir():
        # A Java repo with a test tree and nothing declared at the root: a module pom or a
        # parent declares it. Say `junit4`, the overwhelming majority, rather than `junit5`,
        # whose probe shape does not even compile against the JUnit 4 artifact.
        fw.add("junit4")
    if "jest" in text:
        fw.add("jest")
    if "vitest" in text:
        fw.add("vitest")
    if langs.get("perl") or list(root.glob("t/*.t")):
        fw.add("Test::More")
    return sorted(fw)


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


def detect_stack(root: str) -> StackFingerprint:
    base = Path(root)
    langs: dict[str, int] = {}
    manifests: set[str] = set()
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
    build_systems = sorted({BUILD_SYSTEM[m] for m in manifests if m in BUILD_SYSTEM})
    return StackFingerprint(
        languages=dict(sorted(langs.items(), key=lambda kv: (-kv[1], kv[0]))),
        manifests=sorted(manifests),
        build_systems=build_systems,
        test_frameworks=_detect_test_frameworks(base, langs),
        registries=_detect_registries(base),
        test_dirs=sorted(test_dirs),
        java_release=_declared_release(base),
    )


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
