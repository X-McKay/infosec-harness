"""Deterministic stack fingerprinting (P1): language counts, manifests, and declared registries.

No model involved. The declared registries become the build-stage egress allowlist (D14).
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from infosec_harness.domain.models import StackFingerprint

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
    for name in ("pyproject.toml", "package.json", "pom.xml", "build.gradle", "requirements.txt", "cpanfile"):
        p = root / name
        if p.exists():
            text += p.read_text(errors="ignore").lower()
    if "pytest" in text or (root / "tests").is_dir() and langs.get("python"):
        fw.append("pytest")
    if "junit" in text or (langs.get("java") and (root / "src/test/java").is_dir()):
        fw.append("junit5")
    fw += js_test_runners(root)
    if langs.get("perl") or list(root.glob("t/*.t")):
        fw += _perl_test_frameworks(root)
    return list(dict.fromkeys(fw))


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
    )
